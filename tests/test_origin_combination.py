"""Review 2026-11, item 15 (design decision A81, needs owner approval): one Origin strength.

The Contract and Effect signals decide whether an actor or object is labeled with the noisy-OR of
its labels (`Tagger.combined`); Judge used the strongest single label for the Origin question. With
`math.origin_combination: noisy_or` both use noisy-OR, so "Origin failed" holds exactly when the
threshold the Contract signals use is crossed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from hypothesis import given, settings
from hypothesis import strategies as st

from refmon.pipeline.judge import judge
from refmon.pipeline.tag import Tagger
from refmon.policy import default_policy
from refmon.schemas import Label

T0 = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _story(strengths: list[float], combination: str):
    policy = default_policy()
    policy = policy.model_copy(
        update={"math": policy.math.model_copy(update={"origin_combination": combination})}
    )
    tagger = Tagger(policy)
    ids = []
    for i, s in enumerate(strengths):
        lid = f"L-{i}"
        # persistent: no decay, so the strength at T0 is exactly s
        tagger.labels[lid] = Label(label_id=lid, origin="external", source_class="web",
                                   created=T0, strength=s, persistent=True)  # fmt: skip
        ids.append(lid)
    rec = SimpleNamespace(
        story=SimpleNamespace(story_id="st-1"), last_ts=T0, label_ids=set(ids), signals=[],
        events=[], flags=set(), trusted=False,
    )  # fmt: skip
    return policy, tagger, rec, ids


strengths = st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=0, max_size=6)


@settings(max_examples=300, deadline=None)
@given(strengths)
def test_with_noisy_or_origin_fails_exactly_when_the_signal_threshold_is_crossed(values):
    policy, tagger, rec, ids = _story(values, "noisy_or")
    j = judge(rec, tagger, policy)
    crossed = tagger.combined(ids, T0) >= policy.thresholds.origin_strength
    assert j.failed["origin"] is crossed
    assert abs(j.origin_strength - tagger.combined(ids, T0)) < 1e-12


@settings(max_examples=200, deadline=None)
@given(strengths, st.floats(min_value=0.0, max_value=1.0))
def test_with_noisy_or_another_label_never_weakens_origin(values, extra):
    p1, t1, r1, _ = _story(values, "noisy_or")
    p2, t2, r2, _ = _story([*values, extra], "noisy_or")
    j1, j2 = judge(r1, t1, p1), judge(r2, t2, p2)
    assert j2.origin_strength >= j1.origin_strength - 1e-12
    assert j2.failed["origin"] >= j1.failed["origin"]
    if j1.log_odds is not None and j2.log_odds is not None:
        assert j2.log_odds >= j1.log_odds - 1e-9


def test_until_approved_judge_keeps_the_strongest_label_and_the_gap_is_documented():
    """Flag off (the default): two labels at 0.4 each are labeled for the signals (noisy-OR 0.64)
    but not for the Origin question (max 0.4). This is the inconsistency A81 removes."""
    policy, tagger, rec, ids = _story([0.4, 0.4], "max")
    assert policy.math.origin_combination == default_policy().math.origin_combination == "max"
    j = judge(rec, tagger, policy)
    assert j.origin_strength == 0.4 and j.failed["origin"] is False
    assert tagger.combined(ids, T0) >= policy.thresholds.origin_strength
    policy, tagger, rec, _ = _story([0.4, 0.4], "noisy_or")
    assert judge(rec, tagger, policy).failed["origin"] is True
