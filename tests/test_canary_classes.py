"""Decoy canary classes (v2.1, A69-A71): file, service, beacon; ignore_roles; the decoy sink."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from refmon.pipeline import Pipeline
from refmon.policy import Policy, default_policy_dict
from refmon.schemas import Action, ActionType, Decision, Override, RawEvent

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
DECOY_FILE = "/srv/share/finance/CEO_Password_Vault.csv"
BEACON = "/assets/img/q3-f7c1e2.png"


def policy(**extra) -> Policy:
    data = default_policy_dict()
    data["mode"] = "block"
    data["canaries"] = [
        *data.get("canaries", []),
        {"name": "vault-file", "class": "file", "value": DECOY_FILE,
         "ignore_roles": ["backup_job"]},
        {"name": "legacy-ssh", "class": "service", "value": "ssh-legacy"},
        {"name": "q3-beacon", "class": "beacon", "value": BEACON},
    ]  # fmt: skip
    data.update(extra)
    return Policy.parse(data)


def raw(i, typ, role, pid, cls, content=None, **attrs) -> RawEvent:
    return RawEvent.model_validate(
        {
            "event_id": f"e-{i:06d}", "ts": T0 + timedelta(seconds=i), "device": "dev-b21c",
            "type": typ, "actor": {"id": pid, "role": role, "interactive": False, "user": "svc"},
            "object": {"class": cls, "content": content}, "attrs": attrs,
        },
        context={"extra_roles": ("backup_job", "decoy_service")},
    )  # fmt: skip


def run(events, pol=None, sink=None):
    p = Pipeline(pol or policy(), gate=True)
    if sink is not None:
        p.observe.decoy_sink = sink
    out = []
    for e in events:
        out.extend(p.process(e))
    return p, out


def top(p):
    return max(p.judgements().values(), key=lambda j: ["allow", "hold", "block"].index(j.decision))


def test_a_labeled_process_opening_a_decoy_file_is_blocked():
    p, _ = run([
        raw(1, "content_in", "browser", "p-1", "download", "https://x.example.invalid/tool",
            source_class="download"),
        raw(2, "exec", "other", "p-2", "file", "tool", program="tool"),
        raw(3, "asset_access", "other", "p-2", "decoy_file", "vault", path=DECOY_FILE),
    ])  # fmt: skip
    j = top(p)
    assert j.override is Override.CANARY and j.decision is Decision.BLOCK


def test_any_process_touching_a_decoy_file_is_a_hit_even_unlabeled():
    p, _ = run([raw(1, "asset_access", "other", "p-9", "decoy_file", "vault",
                    path="/srv/share/finance/../finance/CEO_Password_Vault.csv")])  # fmt: skip
    assert top(p).override is Override.CANARY  # the path is normalised before matching


def test_a_role_on_the_ignore_list_is_not_a_hit():
    p, _ = run(
        [raw(1, "asset_access", "backup_job", "p-5", "decoy_file", "vault", path=DECOY_FILE)]
    )
    assert top(p).override is None
    assert all(not e.attrs.get("canary_hit") for e in p.observe.buffer)


def test_a_connection_to_a_decoy_service_blocks_and_reports_the_source_to_the_sink():
    seen = []
    p, out = run(
        [raw(1, "request_in", "decoy_service", "p-decoy", "decoy_session", "SSH-2.0-probe",
             source_class="inbound_request", decoy="ssh-legacy", ip="198.51.100.23")],
        sink=lambda name, ip, ts: seen.append((name, ip)),
    )  # fmt: skip
    j = top(p)
    assert j.override is Override.CANARY and j.decision is Decision.BLOCK
    assert seen == [("legacy-ssh", "198.51.100.23")]
    # the raw attributes are gone after Observe
    (ev,) = p.observe.buffer
    assert set(ev.attrs) & {"ip", "decoy", "path"} == set()
    assert "198.51.100.23" not in ev.to_json_line()
    # the listener is a channel: the hit it reports never contains the listener itself
    kills = [a for a in out if isinstance(a, Action) and a.type is ActionType.KILL_PROCESS_TREE]
    assert all(a.target.id != "p-decoy" for a in kills)


def test_a_fetched_beacon_blocks():
    p, _ = run([raw(1, "request_in", "decoy_service", "p-decoy", "http_request", "GET",
                    source_class="inbound_request", decoy="files-http", url_path=BEACON + "?x=1",
                    ip="203.0.113.9")])  # fmt: skip
    assert top(p).override is Override.CANARY


def test_every_connection_to_the_listener_is_its_own_story():
    p, _ = run([
        raw(i, "request_in", "decoy_service", "p-decoy", "decoy_session", f"probe {i}",
            source_class="inbound_request", decoy="ssh-legacy", ip=f"198.51.100.{i}")
        for i in (1, 2, 3)
    ])  # fmt: skip
    assert len(p.judgements()) == 3


def test_an_ordinary_request_is_no_hit_and_reaches_no_sink():
    seen = []
    p, _ = run(
        [raw(1, "request_in", "web_worker", "p-w", "http_request", "GET /",
             source_class="inbound_request", url_path="/index.html", ip="198.51.100.4")],
        sink=lambda *a: seen.append(a),
    )  # fmt: skip
    assert seen == [] and top(p).override is None


def test_an_unknown_canary_class_is_rejected():
    data = default_policy_dict()
    data["canaries"] = [{"name": "x", "class": "rumour", "value": "y"}]
    with pytest.raises(ValidationError):
        Policy.parse(data)


def test_the_decoy_listener_role_is_a_channel_by_default():
    pol = policy()
    assert "decoy_service" in pol.extra_roles
    assert "decoy_service" in pol.non_carrier_roles
    assert "decoy_service" in pol.non_process_keyed_roles
