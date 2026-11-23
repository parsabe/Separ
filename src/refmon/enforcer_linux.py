"""LinuxEnforcer: containment on a real Linux host (review 2026-11, item 3).

Same interface as the SimulatedEnforcer (`act(Action) -> ActionResult`, `undo(action_id)`), but
the actions happen:

- `hold`: SIGSTOP the process; undo is SIGCONT.
- `block`: SIGKILL the one process (the operation it was about to do never happens).
- `kill_process_tree`: freeze the tree with the cgroup v2 freezer when the process has a cgroup of
  its own (every process in it belongs to the tree), else SIGSTOP the whole tree top-down; then
  SIGKILL every process of it. Not reversible.
- `cut_network`: an nftables rule in the dedicated table `inet separ` that drops the output of the
  process's cgroup (`socket cgroupv2`); undo deletes the rule by its handle. Without `nft` or
  cgroup v2 the action is `unavailable`.
- `quarantine_file`: move the file into a root-owned 0700 quarantine directory, mode 0400; undo
  moves it back if its place is still free. Symlinks are never followed.
- `revert_persistence`, `restore_file`, `isolate_host`: `unavailable` (no platform code yet).

Safety: never PID 1, never the daemon itself or one of its ancestors, never a process of another
user unless the daemon runs as root. Actions name processes by actor id; the real pid comes only
from a sensor (`note_pid`, fed by Observe from `RawEvent.pid`). Without a real pid the action is
`unavailable`, never guessed: missing information never generates evidence, nor an action.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .config import secure_dir
from .schemas import UNDO_OPS, Action, ActionResult, ActionType, UndoRecord

Runner = Callable[[list[str]], tuple[int, str, str]]
TABLE = ("inet", "separ")
CHAIN = "output"

# what each action needs, for `separ health`
ACTIONS = (
    "hold",
    "block",
    "kill_process_tree",
    "cut_network",
    "quarantine_file",
    "revert_persistence",
    "restore_file",
    "isolate_host",
)


class ProcessTable(Protocol):
    def pids(self) -> list[int]: ...
    def exists(self, pid: int) -> bool: ...
    def owner(self, pid: int) -> int | None: ...
    def ppid(self, pid: int) -> int | None: ...
    def cgroup(self, pid: int) -> str | None: ...
    def signal(self, pid: int, sig: int) -> None: ...


class ProcFS:
    """The real process table, read from /proc (read-only, except `signal`)."""

    def __init__(self, root: Path = Path("/proc")) -> None:
        self.root = root

    def pids(self) -> list[int]:
        return [int(p.name) for p in self.root.iterdir() if p.name.isdigit()]

    def exists(self, pid: int) -> bool:
        return (self.root / str(pid)).is_dir()

    def _status(self, pid: int, field: str) -> str | None:
        try:
            for line in (self.root / str(pid) / "status").read_text().splitlines():
                if line.startswith(field + ":"):
                    return line.split(":", 1)[1].split()[0]
        except (OSError, IndexError):
            return None
        return None

    def owner(self, pid: int) -> int | None:
        value = self._status(pid, "Uid")
        return int(value) if value is not None else None

    def ppid(self, pid: int) -> int | None:
        value = self._status(pid, "PPid")
        return int(value) if value is not None else None

    def cgroup(self, pid: int) -> str | None:
        try:
            for line in (self.root / str(pid) / "cgroup").read_text().splitlines():
                if line.startswith("0::"):
                    return line[3:].strip() or None
        except OSError:
            return None
        return None

    def signal(self, pid: int, sig: int) -> None:
        os.kill(pid, sig)


def run_command(argv: list[str]) -> tuple[int, str, str]:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    return done.returncode, done.stdout, done.stderr


@dataclass
class _Undo:
    kind: ActionType
    data: dict[str, Any]


class LinuxEnforcer:
    backend = "linux"

    def __init__(
        self,
        quarantine_dir: Path,
        *,
        procs: ProcessTable | None = None,
        run: Runner | None = None,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        self_pid: int | None = None,
        euid: int | None = None,
        nft: str | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.quarantine_dir = Path(quarantine_dir)
        self.procs: ProcessTable = procs if procs is not None else ProcFS()
        self.run: Runner = run if run is not None else run_command
        self.cgroup_root = Path(cgroup_root)
        self.self_pid = os.getpid() if self_pid is None else self_pid
        self.euid = (os.geteuid() if hasattr(os, "geteuid") else 1000) if euid is None else euid
        self.nft = nft if nft is not None else shutil.which("nft")
        self.log = log or (lambda line: None)
        self.pids: dict[str, int] = {}
        self.files: dict[str, Path] = {}
        self.results: list[ActionResult] = []
        self.undo_records: dict[str, UndoRecord] = {}
        self._undo: dict[str, _Undo] = {}
        self._table_ready = False

    # -- what the sensors tell it --------------------------------------------------------------

    def note_pid(self, actor_id: str, pid: int) -> None:
        if pid > 0:
            self.pids[actor_id] = pid

    def note_file(self, fingerprint: str, path: Path) -> None:
        self.files[fingerprint] = Path(path)

    # -- what it can do, for `separ health` -----------------------------------------------------

    def cgroup_v2(self) -> bool:
        return (self.cgroup_root / "cgroup.controllers").is_file()

    def capabilities(self) -> dict[str, str]:
        caps = dict.fromkeys(ACTIONS, "available")
        if not self.nft:
            caps["cut_network"] = "unavailable: nft not installed"
        elif not self.cgroup_v2():
            caps["cut_network"] = "unavailable: no cgroup v2"
        for kind in ("revert_persistence", "restore_file", "isolate_host"):
            caps[kind] = "unavailable: not implemented on Linux yet"
        if self.euid != 0:
            for kind in ("hold", "block", "kill_process_tree"):
                caps[kind] = "available for this user's own processes only"
        return caps

    # -- the interface ---------------------------------------------------------------------------

    def act(self, action: Action) -> ActionResult:
        if action.action_id in self.undo_records:
            return self._result(action.action_id, False, "duplicate_action_id")
        try:
            detail, undo = self._dispatch(action)
        except OSError as exc:
            detail, undo = f"failed_{type(exc).__name__}"[:64], None
        ok = detail == "applied"
        op = UNDO_OPS[action.type] if ok and undo is not None else None
        record = UndoRecord(
            action_id=action.action_id, target=action.target, op=op, reversible=op is not None
        )
        if op is not None and undo is not None:
            self._undo[action.action_id] = undo
        self.undo_records[action.action_id] = record
        self.log(
            f"ENFORCE {action.type.value} {action.target.ref[:24]} -> {detail} "
            f"(linux, story {action.story_id})"
        )
        return self._result(action.action_id, ok, detail, record)

    def undo(self, action_id: str) -> ActionResult:
        entry = self._undo.pop(action_id, None)
        if entry is None:
            known = action_id in self.undo_records
            return self._result(
                action_id, False, "not_reversible" if known else "unknown_action_id"
            )
        try:
            detail = self._revert(entry)
        except OSError as exc:
            detail = f"failed_{type(exc).__name__}"[:64]
        self.log(f"ENFORCE undo {entry.kind.value} -> {detail} (linux)")
        return self._result(action_id, detail == "undone", detail)

    def _result(
        self, action_id: str, ok: bool, detail: str, undo: UndoRecord | None = None
    ) -> ActionResult:
        res = ActionResult(action_id=action_id, ok=ok, detail=detail, undo=undo)
        self.results.append(res)
        return res

    # -- processes ---------------------------------------------------------------------------------

    def _ancestors_of_self(self) -> set[int]:
        out, pid = set(), self.self_pid
        while pid and pid not in out:
            out.add(pid)
            pid = self.procs.ppid(pid) or 0
        return out

    def _refusal(self, pid: int) -> str | None:
        if pid <= 1:
            return "refused_pid1"
        if pid in self._ancestors_of_self():
            return "refused_self"
        if not self.procs.exists(pid):
            return "no_such_process"
        owner = self.procs.owner(pid)
        if owner is None:
            return "unavailable_owner_unknown"
        if self.euid != 0 and owner != self.euid:
            return "refused_other_user"
        return None

    def _tree(self, root: int) -> list[int]:
        children: dict[int, list[int]] = {}
        for pid in self.procs.pids():
            parent = self.procs.ppid(pid)
            if parent is not None:
                children.setdefault(parent, []).append(pid)
        out, todo = [], [root]
        while todo:
            pid = todo.pop(0)
            if pid in out:
                continue
            out.append(pid)
            todo += sorted(children.get(pid, []))
        return out

    def _pid_for(self, action: Action) -> tuple[int | None, str | None]:
        pid = self.pids.get(action.target.ref)
        if pid is None:
            return None, "unavailable_no_pid"
        refusal = self._refusal(pid)
        return (None, refusal) if refusal else (pid, None)

    def _own_cgroup(self, pid: int, tree: list[int]) -> Path | None:
        """The process's cgroup directory when every process in it belongs to the tree."""
        path = self.procs.cgroup(pid)
        if not path or path == "/" or not self.cgroup_v2():
            return None
        parent = self.procs.ppid(pid)
        if parent is not None and self.procs.cgroup(parent) == path:
            return None
        directory = self.cgroup_root / path.lstrip("/")
        try:
            members = {int(x) for x in (directory / "cgroup.procs").read_text().split()}
        except (OSError, ValueError):
            return None
        if not members or not members <= set(tree) or not (directory / "cgroup.freeze").exists():
            return None
        return directory

    def _dispatch(self, action: Action) -> tuple[str, _Undo | None]:
        kind = action.type
        if kind in (ActionType.HOLD, ActionType.BLOCK, ActionType.KILL_PROCESS_TREE):
            pid, why = self._pid_for(action)
            if pid is None:
                return str(why), None
            if kind is ActionType.HOLD:
                self.procs.signal(pid, signal.SIGSTOP)
                return "applied", _Undo(kind, {"pid": pid})
            if kind is ActionType.BLOCK:
                self.procs.signal(pid, signal.SIGKILL)
                return "applied", None
            tree = [p for p in self._tree(pid) if self._refusal(p) is None]
            group = self._own_cgroup(pid, tree)
            if group is not None:
                (group / "cgroup.freeze").write_text("1")
                tree = sorted(
                    set(tree) | {int(x) for x in (group / "cgroup.procs").read_text().split()}
                )
            else:
                for p in tree:  # top-down, so no new child escapes
                    with contextlib.suppress(ProcessLookupError):
                        self.procs.signal(p, signal.SIGSTOP)
            for p in tree:
                with contextlib.suppress(ProcessLookupError):
                    self.procs.signal(p, signal.SIGKILL)
            self.log(f"ENFORCE killed {len(tree)} process(es), freezer={'yes' if group else 'no'}")
            return "applied", None
        if kind is ActionType.CUT_NETWORK:
            return self._cut_network(action)
        if kind is ActionType.QUARANTINE_FILE:
            return self._quarantine(action)
        return "unavailable_not_implemented", None

    # -- network -----------------------------------------------------------------------------------

    def _nft(self, *args: str) -> tuple[int, str, str]:
        return self.run([str(self.nft), *args])

    def _ensure_table(self) -> bool:
        if self._table_ready:
            return True
        family, table = TABLE
        steps = [
            ("add", "table", family, table),
            ("add", "chain", family, table, CHAIN, "{", "type", "filter", "hook", "output",
             "priority", "0", ";", "policy", "accept", ";", "}"),
        ]  # fmt: skip
        for step in steps:
            code, _, _ = self._nft(*step)
            if code != 0:
                return False
        self._table_ready = True
        return True

    def _cut_network(self, action: Action) -> tuple[str, _Undo | None]:
        if not self.nft:
            return "unavailable_no_nft", None
        if not self.cgroup_v2():
            return "unavailable_no_cgroup_v2", None
        pid, why = self._pid_for(action)
        if pid is None:
            return str(why), None
        path = (self.procs.cgroup(pid) or "").strip("/")
        if not path:
            return "unavailable_no_cgroup", None
        if not self._ensure_table():
            return "failed_nft_table", None
        level = str(len(path.split("/")))
        family, table = TABLE
        code, out, _ = self._nft(
            "--echo", "--handle", "add", "rule", family, table, CHAIN,
            "socket", "cgroupv2", "level", level, f'"{path}"', "drop",
            "comment", f'"separ {action.action_id}"',
        )  # fmt: skip
        if code != 0:
            return "failed_nft_rule", None
        handle = next(
            (w for line in out.splitlines() if "# handle" in line for w in line.split()[-1:]), None
        )
        if handle is None or not handle.isdigit():
            return "failed_nft_handle", None
        return "applied", _Undo(ActionType.CUT_NETWORK, {"handle": handle, "cgroup": path})

    # -- files -------------------------------------------------------------------------------------

    def _quarantine(self, action: Action) -> tuple[str, _Undo | None]:
        path = self.files.get(action.target.ref)
        if path is None:
            return "unavailable_no_path", None
        try:
            st = path.lstat()
        except FileNotFoundError:
            return "no_such_file", None
        if stat.S_ISLNK(st.st_mode):
            return "refused_symlink", None
        if not stat.S_ISREG(st.st_mode):
            return "refused_not_regular", None
        if self.euid != 0 and st.st_uid != self.euid:
            return "refused_other_user", None
        secure_dir(self.quarantine_dir, 0o700)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = self.quarantine_dir / f"{stamp}_{action.action_id}.quarantined"
        os.rename(path, dest)  # renames the entry itself; it never follows a link
        fd = os.open(dest, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
        return "applied", _Undo(
            ActionType.QUARANTINE_FILE,
            {"from": str(path), "to": str(dest), "mode": stat.S_IMODE(st.st_mode)},
        )

    # -- undo --------------------------------------------------------------------------------------

    def _revert(self, entry: _Undo) -> str:
        if entry.kind is ActionType.HOLD:
            with contextlib.suppress(ProcessLookupError):
                self.procs.signal(int(entry.data["pid"]), signal.SIGCONT)
            return "undone"
        if entry.kind is ActionType.CUT_NETWORK:
            family, table = TABLE
            code, _, _ = self._nft(
                "delete", "rule", family, table, CHAIN, "handle", entry.data["handle"]
            )
            return "undone" if code == 0 else "failed_nft_delete"
        if entry.kind is ActionType.QUARANTINE_FILE:
            origin, held = Path(entry.data["from"]), Path(entry.data["to"])
            if origin.exists() or origin.is_symlink():
                return "refused_origin_taken"
            os.rename(held, origin)
            fd = os.open(origin, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fchmod(fd, int(entry.data["mode"]))
            finally:
                os.close(fd)
            return "undone"
        return "not_reversible"
