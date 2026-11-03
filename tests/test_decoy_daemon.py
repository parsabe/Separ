"""Deception in the live daemon (v2.1), end to end: plant -> approve -> touch -> propose -> block."""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

from refmon.cli import main as cli_main
from refmon.live import LiveBarrier
from refmon.policy_io import load_policy_data
from refmon.yamlio import write_document

OUTSIDE = "203.0.113.50"  # documentation range, never a real host


def wait_for(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return False


def adopt(barrier):
    loaded = load_policy_data(barrier.policy_path, [barrier._public_key()])
    barrier.adopt_policy(loaded, why="test")


def notes(barrier) -> list[dict]:
    path = barrier.logs_dir / "notifications.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
def setup(tmp_path):
    barrier = LiveBarrier(workdir=tmp_path / "wd")
    config = tmp_path / "decoys.yaml"
    write_document(
        {
            "plant": {"dir": str(tmp_path / "share"),
                      "beacon_url": "http://files.example.internal:8088"},
            "listen": {"max_seconds": 2, "services": [
                {"name": "ssh-legacy", "port": 0, "bind": "127.0.0.1",
                 "banner": "SSH-2.0-OpenSSH_8.0", "delay_ms": [0, 1]},
                {"name": "files-http", "port": 0, "bind": "127.0.0.1", "kind": "http",
                 "delay_ms": [0, 1]},
            ]},
            "watch": True,
        },
        config,
    )  # fmt: skip
    args = ["--workdir", str(barrier.workdir), "--config", str(config)]
    assert cli_main(["decoy", "plant", *args]) == 0
    yield barrier, config, args
    barrier.stop_decoys()


def decoy_stories(barrier):
    return [
        (sid, barrier.pipeline.judge(barrier.pipeline.record(sid)))
        for sid, meta in barrier._story_meta.items()
        if meta["category"] == "decoy" and sid in barrier.pipeline.linker.records
    ]


def test_unapproved_decoys_are_reported_unarmed_and_never_change_the_policy(setup):
    barrier, config, _ = setup
    from refmon.deception.runtime import load_settings

    before = barrier.policy_path.read_bytes()
    barrier.start_decoys(load_settings(config))
    assert barrier.decoy_unarmed() == ["files-http", "ssh-legacy"]
    keys = {c[0] for c in barrier.decoy_conditions()}
    assert "degraded:decoy_unarmed" in keys
    assert barrier.policy_path.read_bytes() == before  # planting proposed, it did not apply


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify is Linux")
def test_full_flow(setup, tmp_path, capsys):
    barrier, config, args = setup
    from refmon.deception.runtime import load_settings

    assert cli_main(["decoy", "approve-canaries", *args, "--by", "admin-ana"]) == 0
    adopt(barrier)
    assert {c.class_ for c in barrier.policy.canaries} >= {"file", "service", "beacon"}
    barrier.start_decoys(load_settings(config))
    assert barrier.decoy_unarmed() == []
    assert "degraded:decoy_attribution" in {c[0] for c in barrier.decoy_conditions()}

    # 1. a scanner from this machine touches the SSH decoy: blocked story, internal proposal
    port = barrier.decoy_listener.ports["ssh-legacy"]
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        assert s.recv(32).startswith(b"SSH-2.0-OpenSSH_8.0")
    assert wait_for(lambda: decoy_stories(barrier))
    (_, j) = decoy_stories(barrier)[0]
    assert j.decision.value == "block" and j.override.value == "canary"
    (entry,) = barrier.decoy_sources.entries()
    assert entry.internal and entry.address is None  # 127.0.0.1 is kept only as a pseudonym

    # 2. an outside address fetches the beacon: external proposal, then approved and blocked
    barrier.decoy_connection("files-http", OUTSIDE, "/assets/img/x.png", "GET /assets/img/x.png")
    ext = next(e for e in barrier.decoy_sources.entries() if not e.internal)
    assert ext.address == OUTSIDE
    capsys.readouterr()
    assert cli_main(["decoy", "sources", "--workdir", str(barrier.workdir)]) == 0
    assert ext.id in capsys.readouterr().out
    marker = tmp_path / "firewall.txt"
    fw = f"{sys.executable} -c \"import sys; open(sys.argv[1], 'w').write(sys.argv[2])\" {marker} {{ip}}"
    assert cli_main(["decoy", "approve-source", ext.id, "--workdir", str(barrier.workdir),
                     "--by", "admin-ben", "--firewall-command", fw]) == 0  # fmt: skip
    assert marker.read_text() == OUTSIDE
    adopt(barrier)
    spec = next(s for s in barrier.policy.threat_lists if s.name == "decoy-sources")
    assert spec.entries == [OUTSIDE]

    # 3. someone opens a planted decoy file: an alert (inotify names no process)
    proposal = json.loads((barrier.workdir / "proposals" / "decoys.json").read_text())
    Path(proposal["files"][0]).read_text()
    assert wait_for(lambda: any(n["title"] == "Decoy file touched" for n in notes(barrier)))

    # privacy: the outside address is only in the proposal file and the policy block list; no
    # decoy secret is in any log
    logs = "".join(p.read_text() for p in barrier.logs_dir.glob("*") if p.is_file())
    assert OUTSIDE not in logs and "/assets/img/x.png" not in logs
    for c in proposal["canaries"]:
        if c["class"] in ("credential", "beacon"):
            assert c["value"] not in logs
    titles = [n["title"] for n in notes(barrier)]
    assert "Decoy source proposed for blocking" in titles


def test_an_internal_source_cannot_be_approved_by_command(setup, capsys):
    barrier, config, args = setup
    from refmon.deception.runtime import load_settings

    cli_main(["decoy", "approve-canaries", *args, "--by", "admin-ana"])
    adopt(barrier)
    barrier.start_decoys(load_settings(config))
    barrier.decoy_connection("ssh-legacy", "10.9.8.7", None, "")
    (entry,) = barrier.decoy_sources.entries()
    before = barrier.policy_path.read_bytes()
    code = cli_main(["decoy", "approve-source", entry.id, "--workdir", str(barrier.workdir),
                     "--by", "admin-ana"])  # fmt: skip
    assert code != 0 and "four-eyes" in capsys.readouterr().err
    assert barrier.policy_path.read_bytes() == before
    assert "10.9.8.7" not in (barrier.workdir / "proposals" / "decoy-sources.json").read_text()


def test_approval_refuses_a_tampered_policy(setup, capsys):
    barrier, _, args = setup
    text = barrier.policy_path.read_text().replace("mode: block", "mode: observe")
    barrier.policy_path.write_text(text)
    code = cli_main(["decoy", "approve-canaries", *args, "--by", "admin-ana"])
    assert code != 0 and "signature" in capsys.readouterr().err
    assert barrier.policy_path.read_text() == text  # the tampered file was not re-signed
