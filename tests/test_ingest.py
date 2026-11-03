"""Sensor ingest through admin mapping files (v2.2, A73). Samples are synthetic, harmless stand-ins
shaped like the documented output of each sensor."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from refmon.cli import main as cli_main
from refmon.ingest.mapping import (
    Mapper,
    Mapping,
    MappingError,
    clean_identifier,
    load_mapping,
    lookup,
    parse_line,
    parse_ts,
    split_path,
    value_spec,
)
from refmon.ingest.runtime import IngestConfig, IngestRunner, SourceSpec, follow_file
from refmon.pipeline import Pipeline
from refmon.policy import default_policy

HERE = Path(__file__).parent / "ingest"
TEMPLATES = Path(__file__).resolve().parent.parent / "src" / "refmon" / "ingest" / "mappings"
ROLES = tuple(default_policy().extra_roles)
RAW = ("lab-marker.example.invalid", "203.0.113.66", "lab-shell.php", "/var/www", "curl -s")


def wait_for(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


def mapper(doc: dict) -> Mapper:
    base = {"name": "t", "rules": [{"name": "r", "event": {
        "type": "exec", "actor": {"id": "{pid}", "role": "other"},
        "object": {"class": "command_text", "content": {"from": "cmd"}}}}]}  # fmt: skip
    base.update(doc)
    return Mapper(Mapping.model_validate(base), extra_roles=ROLES)


# -- the mapping language ---------------------------------------------------------------------------


def test_paths_walk_objects_literal_dotted_keys_and_lists():
    rec = {"a": {"b.c": [10, {"d": 4}]}}
    assert split_path("a[b.c].1.d") == ["a", "b.c", "1", "d"]
    assert lookup(rec, "a[b.c].1.d") == 4
    assert lookup(rec, "a[b.c].0") == 10
    assert lookup(rec, "a.missing") is not None and lookup(rec, "a.missing") is lookup(rec, "x.y")
    with pytest.raises(MappingError):
        split_path("a[b")


@pytest.mark.parametrize(
    ("spec", "rec", "want"),
    [
        ("{a}@{b}", {"a": 1, "b": "x"}, "1@x"),
        ({"from": "a", "map": {"1": "one"}, "default": "other"}, {"a": 1}, "one"),
        ({"from": "a", "map": {"1": "one"}, "default": "other"}, {"a": 2}, "other"),
        ({"from": "m", "regex": r"for (\S+) from", "group": 1}, {"m": "Accepted key for ana from x"}, "ana"),
        ({"from": "n", "as": "int"}, {"n": "42"}, 42),
        ({"from": "f", "as": "bool"}, {"f": "yes"}, True),
        ({"from": "p", "basename": True, "strip_version": True}, {"p": "/usr/sbin/php-fpm8.2"}, "php-fpm"),
        ({"from": "p", "basename": True, "strip_version": True}, {"p": "/usr/bin/python3.11"}, "python"),
        ({"first": ["{x} {y}", {"from": "x"}]}, {"x": "bin"}, "bin"),
        ({"from": "p", "classify": [{"regex": "^/tmp/", "value": "temp"}], "default": "o"}, {"p": "/tmp/a"}, "temp"),
        ({"from": "missing", "default": "d"}, {}, "d"),
        ("literal", {}, "literal"),
        (7, {}, 7),
    ],
)  # fmt: skip
def test_value_specs(spec, rec, want):
    assert value_spec(spec).evaluate(rec) == want


def test_a_template_naming_a_missing_path_is_missing():
    assert value_spec({"template": "{a}:{b}", "default": None}).evaluate({"a": 1}) is None


def test_named_tables_and_unknown_tables():
    m = mapper({"tables": {"roles": {"nginx": "web_worker"}}, "rules": [{"name": "r", "event": {
        "type": "exec", "actor": {"id": "{pid}", "role": {"from": "p", "map": "roles", "default": "other"}},
        "object": {"class": "command_text"}}}]})  # fmt: skip
    ev, out = m.map(json.dumps({"pid": 1, "p": "nginx"}))
    assert out == "mapped" and ev.actor.role == "web_worker"
    with pytest.raises(MappingError):
        mapper({"rules": [{"name": "r", "event": {
            "type": "exec", "actor": {"id": "x", "role": {"from": "p", "map": "nope"}},
            "object": {"class": "c"}}}]})  # fmt: skip


def test_conditions_choose_the_first_matching_rule():
    rules = [
        {"name": "shell", "match": {"t": {"in": ["execve"]}, "c": {"regex": "^sh "}},
         "event": {"type": "exec", "actor": {"id": "a", "role": "other"}, "object": {"class": "shell"}}},
        {"name": "absent", "match": {"x": {"exists": False}},
         "event": {"type": "exec", "actor": {"id": "a", "role": "other"}, "object": {"class": "plain"}}},
    ]  # fmt: skip
    m = mapper({"rules": rules})
    assert m.map(json.dumps({"t": "execve", "c": "sh -c id"}))[0].object.class_ == "shell"
    assert m.map(json.dumps({"t": "execve", "c": "ls"}))[0].object.class_ == "plain"
    assert m.map(json.dumps({"t": "x", "x": 1})) == (None, "unmatched")


def test_outcomes_unparsable_invalid_and_blank():
    m = mapper({})
    assert m.map("{not json") == (None, "unparsable")
    assert m.map("[1, 2]") == (None, "unparsable")
    assert m.map("   ") == (None, "unmatched")
    bad_role = mapper({"rules": [{"name": "r", "event": {
        "type": "exec", "actor": {"id": "a", "role": "astronaut"}, "object": {"class": "c"}}}]})  # fmt: skip
    assert bad_role.map("{}") == (None, "invalid")


def test_identifiers_are_cleaned_and_timestamps_parsed():
    assert clean_identifier("ana müller/../x") == "ana_m_ller_.._x"
    assert clean_identifier("") == "unknown"
    assert len(clean_identifier("x" * 200)) == 64
    want = datetime(2026, 11, 3, 10, 0, 0, 123456, tzinfo=UTC)
    assert parse_ts("2026-11-03T10:00:00.123456789Z") == want
    assert parse_ts(want.timestamp()) == want
    assert parse_ts(int(want.timestamp() * 1e6)) == want  # journald microseconds
    assert abs(parse_ts(int(want.timestamp() * 1e9)) - want).total_seconds() < 1e-5  # nanoseconds
    assert parse_ts("1762164000").year == 2025


def test_key_value_lines():
    rec = parse_line('type=EXECVE msg=audit(1.2:3): argc=2 a0="ls" a1="-l \\"x\\""', "kv")
    assert rec["type"] == "EXECVE" and rec["a0"] == "ls" and rec["a1"] == '-l "x"'


# -- the shipped templates ----------------------------------------------------------------------------


def mapped(template: str, sample: str):
    m = load_mapping(TEMPLATES / template, extra_roles=ROLES)
    return [m.map(line) for line in (HERE / sample).read_text().splitlines()]


def test_tetragon_template_links_exec_and_connect_into_one_blocked_story():
    out = mapped("tetragon.yaml", "tetragon-sample.jsonl")
    assert [o for _, o in out] == ["mapped", "mapped", "unmatched", "unparsable"]
    exec_ev, conn_ev = out[0][0], out[1][0]
    assert exec_ev.actor.role == "web_worker"  # php-fpm8.2 -> php-fpm
    assert conn_ev.actor.parent == exec_ev.actor.id  # the started program is the child
    pipe = Pipeline(default_policy())
    for ev in (exec_ev, conn_ev):
        pipe.process(ev)
    (j,) = pipe.judgements().values()
    assert j.decision.value == "block" and j.failed["contract"] and j.failed["effect"]


def test_falco_template_web_shell_write_blocks_and_cache_write_is_allowed():
    out = mapped("falco.yaml", "falco-sample.jsonl")
    assert [o for _, o in out] == ["mapped", "mapped", "unmatched"]
    shell, cache = out[0][0], out[1][0]
    assert shell.attrs == {"path_group": "uploads_non_executable", "web_root": "main_site",
                           "new_file": True, "executable": True}  # fmt: skip
    assert cache.attrs["path_group"] == "cache" and "executable" not in cache.attrs
    for ev, want in ((shell, "block"), (cache, "allow")):
        pipe = Pipeline(default_policy())
        pipe.process(ev)
        assert next(iter(pipe.judgements().values())).decision.value == want


def test_nothing_raw_survives_observe_for_any_template_sample():
    pipe = Pipeline(default_policy())
    for template, sample in (
        ("tetragon.yaml", "tetragon-sample.jsonl"),
        ("falco.yaml", "falco-sample.jsonl"),
    ):
        for ev, _ in mapped(template, sample):
            if ev is not None:
                pipe.process(ev)
    dumped = "".join(e.to_json_line() for e in pipe.observe.buffer)
    for raw in RAW:
        assert raw not in dumped


def test_every_template_declares_only_known_capabilities():
    from refmon.heartbeat import CAPABILITY_PROTECTIONS

    for path in TEMPLATES.glob("*.yaml"):
        m = load_mapping(path, extra_roles=ROLES)
        assert set(m.mapping.provides) <= set(CAPABILITY_PROTECTIONS), path.name


# -- sources and the runner ----------------------------------------------------------------------------


def test_follow_file_reads_new_lines_and_survives_rotation(tmp_path):
    log = tmp_path / "sensor.log"
    log.write_text("old line\n")
    stop = threading.Event()
    lines = []

    def collect():
        for line in follow_file(log, stop, poll=0.02):
            lines.append(line)

    t = threading.Thread(target=collect, daemon=True)
    t.start()
    time.sleep(0.15)
    with log.open("a") as fh:
        fh.write("one\ntw")
        fh.flush()
        time.sleep(0.1)
        fh.write("o\n")
    assert wait_for(lambda: lines == ["one", "two"])
    log.rename(tmp_path / "sensor.log.1")  # logrotate
    log.write_text("three\n")
    assert wait_for(lambda: lines == ["one", "two", "three"])
    stop.set()
    t.join(timeout=2)


def tetragon_runner(source: SourceSpec, sink):
    return IngestRunner(load_mapping(TEMPLATES / "tetragon.yaml", extra_roles=ROLES), source, sink)


def test_the_socket_source_is_owner_only_and_counts_outcomes(tmp_path):
    got = []
    path = tmp_path / "run" / "tetragon.sock"
    r = tetragon_runner(SourceSpec(socket=path), got.append)
    r.start()
    try:
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(path))
            s.sendall((HERE / "tetragon-sample.jsonl").read_bytes())
        assert wait_for(lambda: r.snapshot().get("unparsable") == 1)
        assert r.snapshot() == {"sensor": "tetragon", "mapped": 2, "unmatched": 1, "unparsable": 1}
        assert len(got) == 2
    finally:
        r.stop()
    assert not path.exists()


def test_a_failing_sink_is_counted_and_does_not_stop_the_runner(tmp_path):
    log = tmp_path / "t.log"
    log.write_text((HERE / "tetragon-sample.jsonl").read_text())

    def boom(_):
        raise RuntimeError("judge failed")

    r = tetragon_runner(SourceSpec(file=log, from_start=True), boom)
    r.start()
    try:
        assert wait_for(lambda: r.snapshot().get("sink_failed") == 2)
        assert r.alive
    finally:
        r.stop()


def test_a_source_is_exactly_one_kind():
    with pytest.raises(ValueError):
        SourceSpec()
    with pytest.raises(ValueError):
        SourceSpec(file="a", socket="b")


# -- the daemon and the CLI --------------------------------------------------------------------------


def test_the_daemon_judges_ingested_events_and_reports_capabilities(tmp_path):
    from refmon.live import LiveBarrier

    barrier = LiveBarrier(workdir=tmp_path / "wd")
    log = tmp_path / "tetragon.log"
    log.write_text("")
    cfg = IngestConfig.model_validate(
        {"sensors": [{"mapping": str(TEMPLATES / "tetragon.yaml"), "source": {"file": str(log)}}]}
    )
    barrier.start_ingest(cfg)
    try:
        assert barrier.ingest_capabilities() == ("network_connections", "process_ancestry")
        time.sleep(0.4)  # the follower starts at the end of the file
        with log.open("a") as fh:
            fh.write((HERE / "tetragon-sample.jsonl").read_text())
        assert wait_for(lambda: barrier.ingest_runners[0].snapshot().get("mapped") == 2)
        stories = [barrier.pipeline.judge(barrier.pipeline.record(s))
                   for s, m in barrier._story_meta.items() if m["category"] == "sensor"]  # fmt: skip
        assert any(j.decision.value == "block" for j in stories)
        logs = "".join(p.read_text() for p in barrier.logs_dir.glob("*") if p.is_file())
        for raw in RAW:
            assert raw not in logs
        assert barrier.ingest_conditions() == []
    finally:
        barrier.stop_ingest()
    assert [c[0] for c in barrier.ingest_conditions()] == ["ingest:tetragon"]


def test_check_prints_shapes_never_content(capsys):
    code = cli_main(["ingest", "check", str(TEMPLATES / "tetragon.yaml"),
                     "--input", str(HERE / "tetragon-sample.jsonl"), "--judge"])  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0
    assert "exec by web_worker" in out and "summary: mapped 2, unmatched 1, unparsable 1" in out
    assert "block" in out
    for raw in RAW:
        assert raw not in out


def test_list_shows_the_templates(capsys):
    assert cli_main(["ingest", "list"]) == 0
    out = capsys.readouterr().out
    assert "falco.yaml" in out and "tetragon.yaml" in out


# -- the identity templates (v2.2, A74) ---------------------------------------------------------------

IDENTITY_SAMPLES = {
    "sshd-journald.yaml": (
        "sshd-sample.jsonl",
        ["mapped", "mapped", "mapped", "unmatched", "unmatched"],
    ),
    "keycloak.yaml": ("keycloak-sample.log", ["mapped", "mapped", "unmatched"]),
    "shibboleth-idp.yaml": ("shibboleth-sample.log", ["mapped", "unmatched"]),
    "m365-audit.yaml": ("m365-sample.jsonl", ["mapped"] * 5 + ["unmatched"]),
    "postfix-dovecot.yaml": ("mail-sample.jsonl", ["mapped", "mapped", "mapped", "unmatched"]),
}
ALL_SAMPLES = {**IDENTITY_SAMPLES, "falco.yaml": ("falco-sample.jsonl", None),
               "tetragon.yaml": ("tetragon-sample.jsonl", None),
               "k8s-audit.yaml": ("k8s-audit-sample.jsonl", None),
               "tetragon-k8s": ("tetragon-k8s-sample.jsonl", None)}  # fmt: skip


@pytest.mark.parametrize("template", sorted(IDENTITY_SAMPLES))
def test_identity_templates_map_their_samples_to_one_actor_per_account(template):
    sample, want = IDENTITY_SAMPLES[template]
    out = mapped(template, sample)
    assert [o for _, o in out] == want
    for ev, _ in out:
        if ev is None:
            continue
        assert ev.actor.id == f"acct:{ev.actor.user}"  # one account, one actor, across sources
        assert ev.actor.role in ("identity_provider", "mail_server")
        if ev.type.value == "auth":
            assert ev.attrs["auth_result"] in ("success", "failure") and "ip" in ev.attrs


def test_every_template_sample_passes_observe_and_judge_without_error():
    """Every allowlisted attribute of a mapped event is a valid identifier after Observe (a long
    SAML URN would otherwise break the Event); nothing raw survives."""
    pipe = Pipeline(default_policy())
    for template, (sample, _) in sorted(ALL_SAMPLES.items()):
        template = "tetragon.yaml" if template == "tetragon-k8s" else template
        for ev, _ in mapped(template, sample):
            if ev is not None:
                pipe.process(ev)
    dumped = "".join(e.to_json_line() for e in pipe.observe.buffer)
    for raw in (
        *RAW,
        "198.51.100.1",
        "203.0.113.2",
        "box.example.invalid",
        "MailSyncPro",
        "serviceaccount/token",
        "terraform.tfstate",
        "169.254.169.254",
        "db-creds",
    ):  # account names are actor identifiers, pseudonymised when a verdict leaves (Phase 4)
        assert raw not in dumped
    assert len(pipe.judgements()) >= 5


def test_keycloak_takes_its_time_from_the_line_prefix():
    (ev, _), *_ = mapped("keycloak.yaml", "keycloak-sample.log")
    assert ev.ts.isoformat() == "2026-11-03T10:00:00+00:00"


def test_m365_forwarding_outside_is_held_and_inside_is_not():
    from refmon.policy import Policy, default_policy_dict

    data = default_policy_dict()
    data["identity"] = {"internal_mail_domains": ["example.org"]}
    pipe = Pipeline(Policy.parse(data))
    out = mapped("m365-audit.yaml", "m365-sample.jsonl")
    rules = [ev for ev, _ in out if ev is not None and ev.type.value == "mail_rule"]
    outside, inside = rules
    pipe.process(outside)
    assert pipe.observe.buffer[-1].attrs == {"forward_external": True}
    j = list(pipe.judgements().values())[-1]
    assert j.decision.value == "hold" and set(j.effects) == {"exfil", "persist"}
    pipe.process(inside)
    assert pipe.observe.buffer[-1].attrs == {"forward_external": False}


# -- containers, Kubernetes and IaC (v2.3, A78) ------------------------------------------------------


def judged_alone(template, sample):
    pol = default_policy()
    out = []
    for ev, outcome in mapped(template, sample):
        if ev is None:
            out.append(outcome)
            continue
        pipe = Pipeline(pol)
        pipe.process(ev)
        j = list(pipe.judgements().values())[-1]
        out.append((ev.actor.role, j.decision.value))
    return out


def test_k8s_audit_template_follows_the_role_contracts():
    assert judged_alone("k8s-audit.yaml", "k8s-audit-sample.jsonl") == [
        ("k8s_api_client", "hold"),  # exec into a pod: outside an ordinary client's contract
        ("k8s_api_client", "block"),  # a privileged pod mounting the host's root
        ("k8s_api_client", "block"),  # a new cluster role binding
        ("ci_deployer", "hold"),  # a DaemonSet: effect_persist has no role allowance (F13)
        ("k8s_admin", "allow"),  # an admin reads a secret
        ("k8s_admin", "allow"),  # an admin execs into a pod
        "unmatched",  # an ordinary read
        "unmatched",  # a refused request (403) is not an action
    ]


def test_tetragon_container_and_terraform_records_follow_the_contracts():
    assert judged_alone("tetragon.yaml", "tetragon-k8s-sample.jsonl") == [
        ("web_worker", "block"),  # the role comes from the nginx image; it reads its SA token
        ("web_worker", "block"),  # and calls the cloud metadata service
        ("iac_tool", "allow"),  # terraform runs its provider (versioned name -> terraform-provider)
        ("iac_tool", "allow"),  # and reads its state
        ("iac_tool", "hold"),  # a local-exec provisioner starts a shell
        ("interactive_shell", "hold"),  # which connects to an unknown host
    ]


def test_a_terraform_local_exec_that_fetches_is_one_blocked_story():
    pipe = Pipeline(default_policy())
    for ev, _ in mapped("tetragon.yaml", "tetragon-k8s-sample.jsonl")[2:]:
        pipe.process(ev)
    best = pipe.best()
    assert best.decision.value == "block"
    assert {s.name for s in best.signals} >= {"contract_exec_violation", "effect_fetch"}
