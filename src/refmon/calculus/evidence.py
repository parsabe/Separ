"""Evidence combination and cost-based thresholds (CLAUDE.md C11.4, C11.5).

    L = ln(pi / (1 - pi)) + sum over questions q of max over signals j in q of (w_j * s_j)

Within a question only the strongest signal counts (correlated signals); across the three
questions the evidence adds. Block when L >= ln(C_false_block / C_missed); hold when
L >= ln(C_hold / (h * C_missed)). Overrides bypass the thresholds. The contract gate caps a block at
hold when the story has no Contract signal. Everything here is a pure function of its arguments.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..schemas import Contribution, Decision, Question


def prior_log_odds(prior: float) -> float:
    if not 0.0 < prior < 1.0:
        raise ValueError("the prior attack rate is in (0, 1)")
    return math.log(prior / (1.0 - prior))


def block_threshold(costs: Mapping[str, float]) -> float:
    return math.log(costs["false_block"] / costs["missed_attack"])


def hold_threshold(costs: Mapping[str, float], catch_rate: float) -> float:
    return math.log(costs["hold"] / (catch_rate * costs["missed_attack"]))


@dataclass(frozen=True)
class Evidence:
    question: str  # origin | contract | effect
    signal: str
    strength: float


def contributions(
    evidence: Iterable[Evidence], weights: Mapping[str, float]
) -> tuple[Contribution, ...]:
    """Every signal as a contribution (weight x strength, in nats); per question only the
    largest is `counted`. Ties go to the earlier signal name, so the result is deterministic."""
    listed = [
        Contribution(
            question=Question(e.question), signal=e.signal, weight=weights.get(e.signal, 0.0),
            strength=min(1.0, max(0.0, e.strength)),
            nats=weights.get(e.signal, 0.0) * min(1.0, max(0.0, e.strength)),
            counted=False,
        )
        for e in sorted(evidence, key=lambda e: (e.question, e.signal))
    ]  # fmt: skip
    best: dict[str, int] = {}
    for index, c in enumerate(listed):
        if c.question.value not in best or c.nats > listed[best[c.question.value]].nats:
            best[c.question.value] = index
    chosen = set(best.values())
    return tuple(c.model_copy(update={"counted": i in chosen}) for i, c in enumerate(listed))


def log_odds(prior: float, contribs: Iterable[Contribution]) -> float:
    return prior_log_odds(prior) + sum(c.nats for c in contribs if c.counted)


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    crossed: str | None  # "block" | "hold" | None
    gated: bool  # the block threshold was crossed but there was no Contract signal


def decide(
    log_odds_: float,
    block_at: float,
    hold_at: float,
    *,
    has_contract_signal: bool,
    override: Decision | None = None,
) -> Outcome:
    if override is not None:
        return Outcome(override, None, False)
    if log_odds_ >= block_at:
        if has_contract_signal:
            return Outcome(Decision.BLOCK, "block", False)
        return Outcome(Decision.HOLD, "block", True)  # the contract gate (D13)
    if log_odds_ >= hold_at:
        return Outcome(Decision.HOLD, "hold", False)
    return Outcome(Decision.ALLOW, None, False)


# -- A82 (review 2026-11, item 16; needs owner approval): one expected-cost decision -----------
#
# The thresholds above compare each action with ALLOW only, and the hold threshold uses a
# probability where the block threshold uses odds. The expected-cost rule compares all three
# actions at once with the same costs and catch rate, p = P(attack) = 1 / (1 + e^-L):
#
#     cost(ALLOW) = p * C_missed
#     cost(HOLD)  = C_hold + p * (1 - h) * C_missed
#     cost(BLOCK) = (1 - p) * C_false_block
#
# and picks the cheapest (a tie goes to the milder action). The contract gate and the overrides
# apply afterwards exactly as with the thresholds.

_MILDER_FIRST = (Decision.ALLOW, Decision.HOLD, Decision.BLOCK)


def probability(log_odds_: float) -> float:
    if log_odds_ >= 0:
        return 1.0 / (1.0 + math.exp(-log_odds_))
    e = math.exp(log_odds_)
    return e / (1.0 + e)


def expected_costs(
    p: float, costs: Mapping[str, float], catch_rate: float
) -> dict[Decision, float]:
    c_miss, c_fb, c_hold = costs["missed_attack"], costs["false_block"], costs["hold"]
    return {
        Decision.ALLOW: p * c_miss,
        Decision.HOLD: c_hold + p * (1.0 - catch_rate) * c_miss,
        Decision.BLOCK: (1.0 - p) * c_fb,
    }


def cheapest(p: float, costs: Mapping[str, float], catch_rate: float) -> Decision:
    table = expected_costs(p, costs, catch_rate)
    best = Decision.ALLOW
    for d in _MILDER_FIRST[1:]:
        # strictly cheaper (beyond rounding) to move to a harsher action: ties go to the milder
        if table[d] < table[best] and not math.isclose(table[d], table[best]):
            best = d
    return best


def _logit(p: float) -> float:
    return math.log(p / (1.0 - p))


def expected_cost_boundaries(
    costs: Mapping[str, float], catch_rate: float
) -> tuple[float | None, float]:
    """(hold_at, block_at): the log-odds at which the cheapest action changes. `hold_at` is None
    when a hold is never the cheapest action (then ALLOW turns straight into BLOCK)."""
    c_miss, c_fb, c_hold = costs["missed_attack"], costs["false_block"], costs["hold"]
    p_ab = c_fb / (c_miss + c_fb)  # allow == block
    p_ah = c_hold / (catch_rate * c_miss) if catch_rate > 0 else math.inf  # allow == hold
    denom = (1.0 - catch_rate) * c_miss + c_fb
    p_hb = (c_fb - c_hold) / denom if denom > 0 else -math.inf  # hold == block
    if 0.0 < p_ah < p_hb < 1.0:
        return _logit(p_ah), _logit(p_hb)
    return None, _logit(p_ab)


def decide_expected_cost(
    log_odds_: float,
    costs: Mapping[str, float],
    catch_rate: float,
    *,
    has_contract_signal: bool,
    override: Decision | None = None,
) -> Outcome:
    if override is not None:
        return Outcome(override, None, False)
    best = cheapest(probability(log_odds_), costs, catch_rate)
    if best is Decision.BLOCK:
        if has_contract_signal:
            return Outcome(Decision.BLOCK, "block", False)
        return Outcome(Decision.HOLD, "block", True)  # the contract gate (D13), unchanged
    if best is Decision.HOLD:
        return Outcome(Decision.HOLD, "hold", False)
    return Outcome(Decision.ALLOW, None, False)


def boundaries(math_params) -> tuple[float | None, float]:
    """(hold_at, block_at) of the policy's decision rule, for health, the GUI and reports."""
    m = math_params
    if getattr(m, "decision_rule", "thresholds") == "expected_cost":
        return expected_cost_boundaries(m.costs, m.hold_catch_rate)
    return hold_threshold(m.costs, m.hold_catch_rate), block_threshold(m.costs)


def decide_by_policy(
    log_odds_: float,
    math_params,
    *,
    has_contract_signal: bool,
    override: Decision | None = None,
) -> Outcome:
    """The decision of the policy's rule: `thresholds` (C11.5 as before) or `expected_cost`
    (A82). Both apply the contract gate and the overrides the same way."""
    m = math_params
    if getattr(m, "decision_rule", "thresholds") == "expected_cost":
        return decide_expected_cost(
            log_odds_, m.costs, m.hold_catch_rate,
            has_contract_signal=has_contract_signal, override=override,
        )  # fmt: skip
    return decide(
        log_odds_, block_threshold(m.costs), hold_threshold(m.costs, m.hold_catch_rate),
        has_contract_signal=has_contract_signal, override=override,
    )  # fmt: skip


def reestimate_weights(
    attack_stories: Iterable[Iterable[str]], benign_stories: Iterable[Iterable[str]]
) -> dict[str, float]:
    """Re-estimate w_j = ln(P(j | attack) / P(j | benign)) from labeled stories, each given as the
    set of signal names it showed, with Laplace smoothing (add one to both counts of a signal)."""
    attacks = [set(s) for s in attack_stories]
    benigns = [set(s) for s in benign_stories]
    names = set().union(*attacks, *benigns) if attacks or benigns else set()
    weights = {}
    for name in sorted(names):
        a = sum(name in s for s in attacks)
        b = sum(name in s for s in benigns)
        p_attack = (a + 1) / (len(attacks) + 2)
        p_benign = (b + 1) / (len(benigns) + 2)
        weights[name] = math.log(p_attack / p_benign)
    return weights
