"""Attack family naming (v2.1, A68): reporting only, never evidence."""

import pytest
from tests.scenario_run import cases, run_case

from refmon.families import FAMILIES, NONE, SUSPICIOUS, classify, classify_judgement
from refmon.policy import default_policy
from refmon.replay import ReplaySource


@pytest.mark.parametrize(
    ("signals", "kw", "family"),
    [
        (["contract_external_exec", "effect_fetch"], {"sources": ["web"]}, "clickfix"),
        (["effect_fetch"], {"override": "canary", "sources": ["web"]}, "decoy"),
        ([], {"override": "self_tamper"}, "self_tamper"),
        (["effect_credential"], {"sources": ["download"]}, "credential_theft"),
        (["contract_web_worker_exec", "effect_fetch"], {"roles": ["web_worker"]}, "server_rce"),
        (["contract_write_executable", "effect_persist"], {"roles": ["web_worker"]}, "web_shell"),
        (["contract_universal_violation", "effect_mass_change"], {}, "ransomware"),
        (["effect_tamper"], {}, "defense_evasion"),
        (["effect_lateral"], {}, "lateral"),
        (["effect_escalate"], {}, "escalation"),
        (["effect_response_anomaly_repeated"], {}, "memory_leak"),
        (["contract_external_exec"], {"sources": ["agent_input"]}, "prompt_injection"),
        (["contract_exec_violation"], {"sources": ["mail"], "roles": ["office"]}, "malicious_attachment"),
        (["effect_persist"], {"sources": ["removable"]}, "removable_media"),
        (["effect_persist"], {"sources": ["package"]}, "supply_chain"),
        (["contract_unsigned_launch"], {"sources": ["download"]}, "fake_installer"),
        (["effect_threat_list_hit"], {"sources": ["web"]}, "known_bad"),
        (["effect_exfil"], {}, "data_theft"),
    ],
)  # fmt: skip
def test_each_family(signals, kw, family):
    assert classify(signals, **kw).id == family


def test_the_override_names_the_family_before_the_behaviour():
    # a decoy hit is named after the decoy even when the attacker also did other things
    sigs = ["contract_web_worker_exec", "effect_mass_change", "effect_fetch"]
    assert classify(sigs, override="canary", roles=["web_worker"]).id == "decoy"


def test_nothing_and_unknown():
    assert classify([]) is NONE
    assert classify(["contract_surprisal"]) is SUSPICIOUS


def test_every_family_has_a_name_and_advice():
    for fam in FAMILIES.values():
        assert fam.name and fam.advice.endswith(".")


def test_golden_blocks_get_a_family():
    """Every malicious catalog story that blocks gets a family other than 'none'."""
    named = 0
    for case in cases():
        if case.expected.kind != "malicious":
            continue
        events = list(ReplaySource(case.events_path, extra_roles=default_policy().extra_roles))
        roles = {e.actor.role for e in events}
        sources = {e.attrs.get("source_class") for e in events} - {None}
        p = run_case(case)
        for j in p.judgements().values():
            if j.decision.value == "block":
                assert classify_judgement(j, sources=sources, roles=roles) is not NONE, (
                    case.scenario
                )
                named += 1
    assert named >= 20
