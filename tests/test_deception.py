"""Deception (v2.1, A69-A72): planted decoys, the decoy-file watcher, decoy services and tarpit."""

from __future__ import annotations

import json
import os
import random
import socket
import stat
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from refmon.deception.listener import PIXEL, DecoyListener, ListenConfig, ServiceSpec
from refmon.deception.plant import (
    KINDS,
    PlantConfig,
    apply_canaries,
    plant,
    refresh,
    write_proposal,
)
from refmon.policy import Policy, default_policy_dict

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify is Linux")


def planted(tmp_path, **kw):
    cfg = PlantConfig(dir=tmp_path / "share", beacon_url="http://files.example.internal:8088", **kw)
    return cfg, plant(cfg, now=NOW, rng=random.Random(7))


# -- planting --------------------------------------------------------------------------------------


def test_every_kind_is_planted_with_a_file_canary_and_its_secrets(tmp_path):
    _, p = planted(tmp_path)
    assert len(p.files) == len(KINDS)
    files = {c["value"] for c in p.canaries if c["class"] == "file"}
    assert files == set(p.files)
    text = "".join(Path(f).read_text() for f in p.files)
    for c in p.canaries:
        if c["class"] in ("credential", "beacon"):
            assert c["value"] in text  # the canary value is really in a decoy
    assert all(c["ignore_roles"] == ["backup_job"] for c in p.canaries if c["class"] == "file")


def test_nothing_in_the_decoy_directory_gives_the_trap_away(tmp_path):
    cfg, _ = planted(tmp_path)
    for f in cfg.dir.rglob("*"):
        assert "refmon" not in f.name.lower() and "decoy" not in f.name.lower()
        if f.is_file():
            assert "refmon" not in f.read_text().lower() and "decoy" not in f.read_text().lower()


def test_file_times_are_aged_distinct_and_read_after_written(tmp_path):
    _, p = planted(tmp_path, age_months=12)
    mtimes = [os.stat(f).st_mtime for f in p.files]
    assert len(set(mtimes)) == len(mtimes)
    oldest = (NOW - timedelta(days=360)).timestamp()
    newest = (NOW - timedelta(days=1)).timestamp()
    for f in p.files:
        st = os.stat(f)
        assert oldest <= st.st_mtime <= newest and st.st_atime >= st.st_mtime


def test_secrets_are_random_per_plant(tmp_path):
    a = plant(PlantConfig(dir=tmp_path / "a"), now=NOW, rng=random.Random(1))
    b = plant(PlantConfig(dir=tmp_path / "b"), now=NOW, rng=random.Random(1))
    va = {c["value"] for c in a.canaries if c["class"] == "credential"}
    vb = {c["value"] for c in b.canaries if c["class"] == "credential"}
    assert va and va.isdisjoint(vb)


def test_pgpass_is_private_like_the_real_one(tmp_path):
    _, p = planted(tmp_path)
    pg = next(f for f in p.files if f.endswith(".pgpass"))
    assert stat.S_IMODE(os.stat(pg).st_mode) == 0o600


def test_no_beacon_document_without_a_beacon_address(tmp_path):
    p = plant(PlantConfig(dir=tmp_path / "s"), now=NOW)
    assert not any(c["class"] == "beacon" for c in p.canaries)


def test_planting_never_overwrites_or_leaves_the_directory(tmp_path):
    cfg, _ = planted(tmp_path)
    with pytest.raises(FileExistsError):
        plant(cfg, now=NOW)
    with pytest.raises(ValueError):
        plant(PlantConfig(dir=tmp_path / "x", names={"env": "../../etc/x"}), now=NOW)
    with pytest.raises(ValueError):
        plant(PlantConfig(dir=tmp_path / "y", files=["bitcoin_wallet"]), now=NOW)


def test_the_proposal_is_owner_only_and_applies_to_a_valid_policy(tmp_path):
    _, p = planted(tmp_path)
    out = tmp_path / "proposals" / "decoys.json"
    write_proposal(p, out, now=NOW)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    proposal = json.loads(out.read_text())
    assert proposal["status"] == "proposed"
    with pytest.raises(ValueError):
        apply_canaries(default_policy_dict(), proposal, "")
    doc = apply_canaries(default_policy_dict(), proposal, "admin-ana")
    pol = Policy.parse(doc)
    assert {c.name for c in pol.canaries} >= {c["name"] for c in proposal["canaries"]}
    again = apply_canaries(doc, proposal, "admin-ana")  # idempotent: names are replaced
    assert len(again["canaries"]) == len(doc["canaries"])


# -- the watcher -------------------------------------------------------------------------------------


@linux_only
def test_the_watcher_reports_open_change_and_removal_but_not_a_refresh(tmp_path):
    from refmon.deception.watch import DecoyWatcher, decoys_from_proposal

    _, p = planted(tmp_path)
    decoys = decoys_from_proposal(p.proposal(NOW))
    w = DecoyWatcher(decoys)
    try:
        assert w.watched == len(p.files) and w.missing == []
        refresh(p.files, now=NOW, count=3)
        assert w.poll(0.2) == []  # times only: the watcher sees nothing
        target = p.files[0]
        Path(target).read_text()
        assert w.poll(1.0) == [(decoys[target], "opened")]
        os.unlink(target)
        assert (decoys[target], "removed") in w.poll(1.0)
        assert decoys[target] in w.missing
    finally:
        w.close()


def test_refresh_moves_times_to_recent_working_hours(tmp_path):
    _, p = planted(tmp_path)
    touched = refresh(p.files, now=NOW, rng=random.Random(3), count=2)
    assert len(touched) == 2
    for f in touched:
        t = datetime.fromtimestamp(os.stat(f).st_mtime, UTC)
        assert NOW - timedelta(days=6) <= t <= NOW - timedelta(minutes=5)


# -- decoy services --------------------------------------------------------------------------------


@pytest.fixture
def touches():
    return []


def listener(touches, *specs, **cfg):
    lst = DecoyListener(
        ListenConfig(services=[ServiceSpec(bind="127.0.0.1", port=0, delay_ms=(0, 1), **s)
                               for s in specs], **cfg),
        lambda *a: touches.append(a),
    )  # fmt: skip
    lst.start()
    return lst


def recv_all(sock, limit=1 << 16):
    out = b""
    while len(out) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
    return out


def test_a_banner_service_reports_the_touch_and_shows_the_configured_banner(touches):
    lst = listener(touches, {"name": "ssh-legacy", "banner": "SSH-2.0-OpenSSH_8.0"})
    try:
        with socket.create_connection(("127.0.0.1", lst.ports["ssh-legacy"]), timeout=3) as s:
            assert s.recv(64) == b"SSH-2.0-OpenSSH_8.0\r\n"
        deadline = time.monotonic() + 2
        while not touches and time.monotonic() < deadline:
            time.sleep(0.01)
        assert touches[0] == ("ssh-legacy", "127.0.0.1", None, "")
    finally:
        lst.stop()


def test_an_http_service_answers_a_beacon_image_at_once_and_reports_the_path(touches):
    lst = listener(touches, {"name": "files-http", "kind": "http", "server_header": "Apache/2.4.37",
                             "tarpit_bytes_per_s": 1.0})  # fmt: skip
    try:
        with socket.create_connection(("127.0.0.1", lst.ports["files-http"]), timeout=3) as s:
            s.sendall(b"GET /assets/img/q3.png?u=1 HTTP/1.1\r\nHost: x\r\n\r\n")
            t0 = time.monotonic()
            data = recv_all(s)
        assert time.monotonic() - t0 < 1.0  # the image is not tarpitted
        assert data.endswith(PIXEL) and b"Server: Apache/2.4.37" in data
        assert touches[0][:3] == ("files-http", "127.0.0.1", "/assets/img/q3.png?u=1")
    finally:
        lst.stop()


def test_the_tarpit_drips_its_answer(touches):
    lst = listener(touches, {"name": "slow", "banner": "SSH-2.0-x", "tarpit_bytes_per_s": 20.0})
    try:
        with socket.create_connection(("127.0.0.1", lst.ports["slow"]), timeout=5) as s:
            t0 = time.monotonic()
            got = b""
            while not got.endswith(b"\r\n"):
                got += s.recv(1)
        assert got == b"SSH-2.0-x\r\n"
        assert time.monotonic() - t0 >= 0.4  # 11 bytes at 20 B/s
    finally:
        lst.stop()


def test_tarpits_are_bounded_in_number_and_time(touches):
    lst = listener(touches, {"name": "endless", "endless": True}, max_concurrent=1,
                   max_seconds=1.0)  # fmt: skip
    try:
        port = lst.ports["endless"]
        first = socket.create_connection(("127.0.0.1", port), timeout=3)
        time.sleep(0.2)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as second:
            assert recv_all(second) == b""  # no slot: closed at once
        assert lst.stats["refused_busy"] == 1
        t0 = time.monotonic()
        recv_all(first)  # the endless tarpit ends at max_seconds
        assert time.monotonic() - t0 < 3.0
        first.close()
        assert len(touches) == 2  # both connections were reported
    finally:
        lst.stop()


def test_a_failing_judgement_does_not_kill_the_listener():
    calls = []

    def boom(*a):
        calls.append(a)
        raise RuntimeError("judge failed")

    lst = DecoyListener(
        ListenConfig(services=[ServiceSpec(name="x", bind="127.0.0.1", port=0, banner="hi",
                                           delay_ms=(0, 1))]), boom,
    )  # fmt: skip
    lst.start()
    try:
        for _ in range(2):
            with socket.create_connection(("127.0.0.1", lst.ports["x"]), timeout=3) as s:
                assert s.recv(16) == b"hi\r\n"
        assert len(calls) == 2 and lst.alive
    finally:
        lst.stop()
    assert not any(t.is_alive() for t in threading.enumerate() if t.name == "refmon-decoy-x")
