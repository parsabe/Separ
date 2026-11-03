"""Block-list proposals from decoy hits (v2.1, A71): external raw and expiring, internal sealed."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta

import pytest

from refmon import signing
from refmon.deception.proposals import THREAT_LIST, SourceProposals
from refmon.pipeline.observe import Observe
from refmon.policy import Policy, default_policy, default_policy_dict
from refmon.pseudonym import (
    Approval,
    AuditLog,
    Pseudonymizer,
    ReidentificationDenied,
    Vault,
    approval_message,
)
from refmon.schemas import RawEvent

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


@pytest.fixture
def keys():
    return {name: signing.generate_keypair() for name in ("ana", "ben", "cem")}


def store(tmp_path, keys, clock=None, vault_key=None):
    vault = Vault({n: pub for n, (_, pub) in keys.items()}, 2, AuditLog(), key=vault_key)
    return SourceProposals(
        tmp_path / "proposals" / "decoy-sources.json", default_policy(),
        Pseudonymizer(b"k" * 32), vault, clock=clock or Clock(),
    ), vault  # fmt: skip


def test_an_external_source_is_proposed_raw_in_an_owner_only_file(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    e = s.record("legacy-ssh", "198.51.100.23", T0)
    assert e.address == "198.51.100.23" and not e.internal and e.pseudonym is None
    assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(s.path.parent.stat().st_mode) == 0o700
    again = s.record("legacy-ssh", "198.51.100.23", T0 + timedelta(hours=1))
    assert again.id == e.id and again.hits == 2
    assert len(s.entries()) == 1


def test_an_internal_source_is_only_a_pseudonym_and_a_sealed_value(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    e = s.record("legacy-ssh", "10.20.30.40", T0)
    assert e.internal and e.address is None and e.pseudonym.startswith("ps-ip-")
    assert "10.20.30.40" not in s.path.read_text()


def test_internal_means_private_or_a_policy_internal_range(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    assert s.record("x", "192.168.1.5", T0).internal
    assert s.record("x", "127.0.0.1", T0).internal
    assert s.record("x", "fe80::1", T0).internal
    assert not s.record("x", "203.0.113.7", T0).internal
    assert s.record("x", "not-an-address", T0) is None


def test_a_pending_proposal_expires_and_is_deleted(tmp_path, keys):
    clock = Clock()
    s, _ = store(tmp_path, keys, clock)
    s.record("legacy-ssh", "198.51.100.23", T0)
    clock.now = T0 + timedelta(days=7, seconds=1)
    assert s.entries() == []
    assert "198.51.100.23" not in s.path.read_text()


def test_approval_adds_the_address_to_the_threat_list_and_needs_a_name(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    e = s.record("legacy-ssh", "198.51.100.23", T0)
    with pytest.raises(ValueError):
        s.approve(e.id, " ", default_policy_dict())
    doc = s.approve(e.id, "admin-ana", default_policy_dict())
    spec = next(x for x in doc["threat_lists"] if x["name"] == THREAT_LIST)
    assert spec == {"name": THREAT_LIST, "kind": "host", "entries": ["198.51.100.23"]}
    assert Policy.parse(doc)  # still a valid policy (the caller signs it)
    (kept,) = s.entries()
    assert kept.status == "approved" and kept.approved_by == "admin-ana"


def test_an_internal_address_cannot_be_approved_without_re_identification(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    e = s.record("legacy-ssh", "10.1.2.3", T0)
    with pytest.raises(PermissionError):
        s.approve(e.id, "admin-ana", default_policy_dict())


def test_four_eyes_reveal_the_sealed_internal_address_later(tmp_path, keys):
    vault_key = b"0" * 43 + b"="  # a fixed Fernet key, as the daemon keeps one in its workdir
    s, _ = store(tmp_path, keys, vault_key=vault_key)
    e = s.record("legacy-ssh", "10.1.2.3", T0)
    # a later process: a new vault with the same key adopts the sealed value from the file
    s2, vault = store(tmp_path, keys, vault_key=vault_key)
    s2.adopt_internal()
    rq = vault.open_request(e.pseudonym, "block decoy source", requester="ana")
    msg = approval_message(rq, e.pseudonym, "block decoy source")
    one = [Approval("ben", signing.sign_message(msg, keys["ben"][0]))]
    with pytest.raises(ReidentificationDenied):
        vault.complete(rq, one)
    rq = vault.open_request(e.pseudonym, "block decoy source", requester="ana")
    msg = approval_message(rq, e.pseudonym, "block decoy source")
    two = [Approval(n, signing.sign_message(msg, keys[n][0])) for n in ("ben", "cem")]
    assert vault.complete(rq, two) == "10.1.2.3"
    assert [x["event"] for x in vault.audit.entries][-1] == "reidentified"


def test_an_approved_source_is_a_threat_list_hit_on_its_next_request(tmp_path, keys):
    s, _ = store(tmp_path, keys)
    e = s.record("legacy-ssh", "198.51.100.23", T0)
    pol = Policy.parse(s.approve(e.id, "admin-ana", default_policy_dict()))
    obs = Observe(pol, b"k" * 32)
    ev = RawEvent.model_validate({
        "event_id": "e-000001", "ts": T0, "device": "dev-b21c", "type": "request_in",
        "actor": {"id": "p-w", "role": "web_worker", "interactive": False, "user": "svc"},
        "object": {"class": "http_request", "content": "GET /"},
        "attrs": {"source_class": "inbound_request", "url_path": "/", "ip": "198.51.100.23"},
    })  # fmt: skip
    out = obs(ev)
    assert out.attrs["threat_list_hit"] == THREAT_LIST
    assert "198.51.100.23" not in json.dumps(out.attrs)
