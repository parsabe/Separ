"""Review 2026-11, item 16 (design decision A82, needs owner approval): the expected-cost decision
over {ALLOW, HOLD, BLOCK}, with the contract gate and the overrides applied as before."""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from refmon.calculus import evidence as calc
from refmon.health import decision_summary
from refmon.policy import default_policy
from refmon.schemas import Decision

COSTS = {"missed_attack": 1000.0, "false_block": 20.0, "hold": 5.0}
H = 0.7


def test_default_boundaries_and_how_they_differ_from_the_thresholds():
    hold_at, block_at = calc.expected_cost_boundaries(COSTS, H)
    assert hold_at == pytest.approx(math.log(5 / (700 - 5)))  # odds, not a probability
    assert block_at == pytest.approx(math.log((15 / 320) / (1 - 15 / 320)))
    assert round(hold_at, 2) == -4.93 and round(block_at, 2) == -3.01
    # the thresholds (C11.5): -4.94 and -3.91
    assert round(calc.hold_threshold(COSTS, H), 2) == -4.94
    assert round(calc.block_threshold(COSTS), 2) == -3.91


def _brute(log_odds, costs, h):
    table = calc.expected_costs(calc.probability(log_odds), costs, h)
    low = min(table.values())
    return next(
        d
        for d in (Decision.ALLOW, Decision.HOLD, Decision.BLOCK)
        if table[d] <= low or math.isclose(table[d], low)
    )


costs_st = st.fixed_dictionaries(
    {
        "missed_attack": st.floats(10, 1e5),
        "false_block": st.floats(0.1, 1e3),
        "hold": st.floats(0.01, 1e3),
    }
)


@settings(max_examples=400, deadline=None)
@given(st.floats(-15, 15), costs_st, st.floats(0.0, 1.0))
def test_the_cheapest_action_is_chosen_and_ties_go_to_the_milder(log_odds, costs, h):
    out = calc.decide_expected_cost(log_odds, costs, h, has_contract_signal=True)
    assert out.decision is _brute(log_odds, costs, h)


@settings(max_examples=300, deadline=None)
@given(costs_st, st.floats(0.0, 1.0))
def test_the_boundaries_are_where_the_cheapest_action_changes(costs, h):
    hold_at, block_at = calc.expected_cost_boundaries(costs, h)
    eps = 1e-6
    decide = lambda lo: calc.decide_expected_cost(lo, costs, h, has_contract_signal=True).decision  # noqa: E731
    assert decide(block_at + eps) is Decision.BLOCK
    if hold_at is None:
        assert decide(block_at - eps) is Decision.ALLOW
    else:
        assert hold_at < block_at
        assert decide(hold_at - eps) is Decision.ALLOW
        assert decide(hold_at + eps) is Decision.HOLD
        assert decide(block_at - eps) is Decision.HOLD


def test_exact_ties_go_to_the_milder_action():
    hold_at, block_at = calc.expected_cost_boundaries(COSTS, H)
    at = lambda lo: calc.cheapest(calc.probability(lo), COSTS, H)  # noqa: E731
    assert at(hold_at) in (Decision.ALLOW, Decision.HOLD)
    p = COSTS["hold"] / (H * COSTS["missed_attack"])
    assert calc.cheapest(p, COSTS, H) is Decision.ALLOW  # exactly equal: the milder one
    assert at(block_at) in (Decision.HOLD, Decision.BLOCK)


def test_the_contract_gate_and_the_overrides_apply_as_before():
    gated = calc.decide_expected_cost(0.0, COSTS, H, has_contract_signal=False)
    assert (gated.decision, gated.crossed, gated.gated) == (Decision.HOLD, "block", True)
    forced = calc.decide_expected_cost(-20.0, COSTS, H, has_contract_signal=False,
                                       override=Decision.BLOCK)  # fmt: skip
    assert forced.decision is Decision.BLOCK and forced.crossed is None
    allowed = calc.decide_expected_cost(5.0, COSTS, H, has_contract_signal=True,
                                        override=Decision.ALLOW)  # fmt: skip
    assert allowed.decision is Decision.ALLOW


def test_boundaries_move_the_right_way_when_costs_change():
    base_h, base_b = calc.expected_cost_boundaries(COSTS, H)
    dearer_fb = calc.expected_cost_boundaries({**COSTS, "false_block": 40.0}, H)
    assert dearer_fb[1] > base_b  # false blocks dearer: block later
    dearer_hold = calc.expected_cost_boundaries({**COSTS, "hold": 8.0}, H)
    assert dearer_hold[0] > base_h  # holds dearer: hold later
    better_hold = calc.expected_cost_boundaries(COSTS, 0.9)
    assert better_hold[0] < base_h  # holds catch more: hold earlier
    dearer_miss = calc.expected_cost_boundaries({**COSTS, "missed_attack": 5000.0}, H)
    assert dearer_miss[0] < base_h and dearer_miss[1] < base_b  # misses dearer: act earlier


def test_the_policy_flag_picks_the_rule_and_defaults_to_the_thresholds():
    policy = default_policy()
    assert policy.math.decision_rule == "thresholds"
    lo = -3.11  # between the two block boundaries
    old = calc.decide_by_policy(lo, policy.math, has_contract_signal=True)
    assert old.decision is Decision.BLOCK
    new_math = policy.math.model_copy(update={"decision_rule": "expected_cost"})
    assert calc.decide_by_policy(lo, new_math, has_contract_signal=True).decision is Decision.HOLD
    assert calc.boundaries(new_math) == calc.expected_cost_boundaries(COSTS, H)


def test_health_reports_the_rule_and_its_boundaries():
    summary = decision_summary(default_policy())
    assert summary == {
        "rule": "thresholds", "origin_combination": "max", "prior_log_odds": -6.907,
        "hold_at": -4.942, "block_at": -3.912,
    }  # fmt: skip
    pol = default_policy()
    pol = pol.model_copy(
        update={"math": pol.math.model_copy(update={"decision_rule": "expected_cost"})}
    )
    assert (
        decision_summary(pol)["hold_at"] == -4.934 and decision_summary(pol)["block_at"] == -3.012
    )


def test_the_heartbeat_and_the_gui_state_carry_the_boundaries(tmp_path):
    from datetime import UTC, datetime

    from tests.livehelp import make_barrier

    from refmon.health import HealthMonitor

    barrier = make_barrier(tmp_path / "wd")
    doc = HealthMonitor(barrier, rootkit_interval_s=0).write_heartbeat(datetime.now(UTC))
    assert doc["decision"]["rule"] == "thresholds" and doc["decision"]["block_at"] == -3.912
    pol = barrier.state_snapshot()["policy"]
    assert (pol["decision_rule"], pol["hold_thr"], pol["block_thr"]) == ("thresholds", -4.94, -3.91)
