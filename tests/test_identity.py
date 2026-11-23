"""Identity events (v2.2, A74-A77): hacked accounts from login and mail logs, with the weights the
owner already approved, the login cap at hold, and observe mode first."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from refmon.keys import LAB_REPLAY_KEY
from refmon.pipeline import Pipeline
from refmon.pipeline.identity import IdentityTracker
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.schemas import Decision, Mode, Override, RawEvent

T0 = datetime(2026, 11, 3, 8, 0, tzinfo=UTC)
CAMPUS = "10.20.30.40"  # the default policy's internal_network class
HOME = "198.51.100.10"  # a documentation address: an outside network
ELSEWHERE = "203.0.113.200"
ROLES = tuple(default_policy().extra_roles)


def policy(**identity) -> Policy:
    data = default_policy_dict()
    data["mode"] = "block"
    data["identity"] = {"min_logins": 4, "internal_mail_domains": ["example.org"],
                        "approved_apps": ["Zoom"], **identity}  # fmt: skip
    return Policy.parse(data)


class Feed:
    def __init__(self, pol=None):
        self.pipe = Pipeline(pol or policy(), key=LAB_REPLAY_KEY)
        self.t = T0
        self.n = 0

    def ev(self, typ, user="ana", gap=60, role="identity_provider", content="x", **attrs):
        self.n += 1
        self.t += timedelta(seconds=gap)
        raw = RawEvent.model_validate(
            {"event_id": f"e-{self.n:06d}", "ts": self.t, "device": "idp-01", "type": typ,
             "actor": {"id": f"acct:{user}", "role": role, "interactive": False, "user": user},
             "object": {"class": "login", "content": content}, "attrs": attrs},
            context={"extra_roles": ROLES},
        )  # fmt: skip
        self.pipe.process(raw)
        return self.pipe.observe.buffer[-1]

    def login(self, ip, ok=True, **kw):
        return self.ev("auth", ip=ip, auth_result="success" if ok else "failure",
                       auth_method="password", **kw)  # fmt: skip

    def last(self):
        return list(self.pipe.judgements().values())[-1]


def habit(feed: Feed, user="ana"):
    """A mature baseline: logins from campus and from home, spread over days (new stories)."""
    for i in range(6):
        feed.login(CAMPUS if i % 2 else HOME, user=user, gap=86400)


# -- Observe ----------------------------------------------------------------------------------------


def test_the_network_class_is_a_named_class_or_a_keyed_prefix_bucket_never_the_address():
    f = Feed()
    campus = f.login(CAMPUS)
    home = f.login(HOME)
    home2 = f.login("198.51.100.99")  # same /16
    other = f.login(ELSEWHERE)
    assert campus.attrs["network_class"] == "internal_network"
    assert home.attrs["network_class"].startswith("net-")
    assert home.attrs["network_class"] == home2.attrs["network_class"]
    assert other.attrs["network_class"] != home.attrs["network_class"]
    for e in (campus, home, home2, other):
        assert "ip" not in e.attrs and HOME not in e.to_json_line()


def test_the_bucket_depends_on_the_device_key():
    a = Pipeline(policy(), key=b"k1" * 16)
    b = Pipeline(policy(), key=b"k2" * 16)
    assert a.observe._network_class(HOME) != b.observe._network_class(HOME)


def test_mail_forwarding_and_app_consent_are_decided_in_observe():
    f = Feed()
    ext = f.ev("mail_rule", role="mail_server", forward_to="drop@box.example.invalid")
    internal = f.ev("mail_rule", role="mail_server", forward_to="Ana <ana@lab.example.org>")
    assert ext.attrs == {"forward_external": True}
    assert internal.attrs == {"forward_external": False}
    assert f.ev("oauth_grant", app="zoom").attrs == {"app_approved": True}
    assert f.ev("oauth_grant", app="MailSyncPro").attrs == {"app_approved": False}
    assert "box.example.invalid" not in "".join(e.to_json_line() for e in f.pipe.observe.buffer)


# -- the per-account baseline -----------------------------------------------------------------------


def test_a_new_network_counts_only_once_the_account_baseline_is_mature():
    f = Feed()
    f.login(CAMPUS, user="ben")
    f.login(ELSEWHERE, user="ben", gap=86400)  # immature: no signal (missing information)
    assert f.last().signals == []
    habit(f)
    f.login("192.0.2.50", gap=86400)  # a network class ana never used, mature baseline
    assert [s.name for s in f.last().signals] == ["contract_surprisal"]


def test_one_network_used_once_keeps_the_baseline_immature():
    f = Feed()
    habit(f)
    f.login(ELSEWHERE, gap=86400)  # mature: signal; the network is parked, then learned once
    f.login("192.0.2.77", gap=86400)  # a day later: ELSEWHERE learned, seen once -> immature
    assert f.last().signals == []  # Good-Turing: one class seen once in 7 logins is not mature


def test_known_networks_raise_nothing():
    f = Feed()
    habit(f)
    f.login(HOME, gap=86400)
    assert f.last().signals == [] and f.last().decision is Decision.ALLOW


def test_the_baseline_does_not_learn_during_an_incident():
    tr = IdentityTracker(policy(min_logins=1))
    f = Feed()
    ev = f.login(CAMPUS)
    for _ in range(3):
        tr.signals(ev, 0.0)
    new = f.login("192.0.2.9")
    assert tr.signals(new, 10.0) == ["contract_surprisal"]
    assert tr.signals(new, 20.0) == ["contract_surprisal"]  # not learned during the incident
    assert tr.signals(new, 20.0 + 3601) == []  # quiet hour over: learned (a documented limit)
    assert tr.networks["ana"][new.attrs["network_class"]] >= 1


def test_a_burst_of_failures_is_credential_access():
    f = Feed(policy(failure_burst=5))
    for _ in range(4):
        f.login(ELSEWHERE, ok=False, gap=10)
    assert f.last().signals == []
    f.login(ELSEWHERE, ok=False, gap=10)
    assert [s.name for s in f.last().signals] == ["effect_credential"]


def test_failures_spread_beyond_the_window_are_no_burst():
    f = Feed(policy(failure_burst=3, burst_window=60))
    for _ in range(6):
        f.login(ELSEWHERE, ok=False, gap=40)
    assert all(not j.signals for j in f.pipe.judgements().values())


# -- decisions ----------------------------------------------------------------------------------------


def test_mfa_fatigue_then_a_login_from_a_new_network_is_held_not_blocked():
    f = Feed(policy(failure_burst=5))
    habit(f)
    f.t += timedelta(days=1)
    for _ in range(6):
        f.ev("auth", ip=ELSEWHERE, auth_result="failure", auth_method="mfa_push", gap=15)
    f.login(ELSEWHERE, gap=15)
    j = f.last()
    assert {s.name for s in j.signals} == {"effect_credential", "contract_surprisal"}
    assert j.log_odds > -3.91  # the block threshold is crossed ...
    assert j.decision is Decision.HOLD and j.detail.get("identity_cap")  # ... and capped (A75)
    assert j.rule_decision is Decision.HOLD
    assert j.mode is Mode.OBSERVE  # the identity rules start in observe mode (A77)


def test_a_forwarding_rule_to_outside_is_held():
    f = Feed()
    f.ev("mail_rule", role="mail_server", forward_to="drop@box.example.invalid")
    j = f.last()
    assert set(j.effects) == {"exfil", "persist"} and j.decision is Decision.HOLD


def test_an_attempt_on_a_decoy_account_blocks():
    data = default_policy_dict()
    data["canaries"] = [
        *data["canaries"],
        {"name": "decoy-admin", "class": "account", "value": "svc-backup-old"},
    ]
    f = Feed(Policy.parse(data))
    f.login(ELSEWHERE, ok=False, user="svc-backup-old")
    j = f.last()
    assert (
        j.override is Override.CANARY and j.decision is Decision.BLOCK
    )  # an override still blocks


def test_a_login_from_a_listed_address_is_a_threat_list_hit():
    data = default_policy_dict()
    data["threat_lists"] = [*data["threat_lists"],
                            {"name": "decoy-sources", "kind": "host", "entries": [ELSEWHERE]}]  # fmt: skip
    f = Feed(Policy.parse(data))
    e = f.login(ELSEWHERE)
    assert e.attrs["threat_list_hit"] == "decoy-sources"
    assert f.last().decision is Decision.HOLD  # no contract signal and the login cap


def test_the_rules_are_observe_for_identity_roles_only():
    pol = default_policy(mode="block")
    assert pol.rule_mode("R-EFF-CREDENTIAL", "identity_provider") is Mode.OBSERVE
    assert pol.rule_mode("R-EFF-CREDENTIAL", "mail_server") is Mode.OBSERVE
    assert pol.rule_mode("R-EFF-CREDENTIAL", "other") is Mode.BLOCK  # everything else unchanged


@pytest.mark.parametrize("cap", ["hold", "allow"])
def test_the_cap_is_policy(cap):
    f = Feed(policy(cap=cap))
    f.ev("mail_rule", role="mail_server", forward_to="drop@box.example.invalid")
    f.ev("oauth_grant", role="mail_server", app="MailSyncPro", gap=5)
    assert f.last().decision.value in (cap, "allow")


def test_once_enforced_a_held_login_story_pauses_the_account_session():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from golden_more import s57
    from refmon.schemas import Action

    def actions(mode):
        data = default_policy_dict()
        data["mode"] = "block"
        data["rules"] = [r | {"mode": mode} for r in data["rules"]]
        pipe = Pipeline(Policy.parse(data), gate=True, key=LAB_REPLAY_KEY)
        return [(a.type.value, a.target.ref) for e in s57()[0] for a in pipe.process(e)
                if isinstance(a, Action)]  # fmt: skip

    assert actions("observe") == []  # observe first (A77): recorded, nothing paused
    assert actions("block") == [("hold", "acct:ana")]  # after the pilot: the account's session
