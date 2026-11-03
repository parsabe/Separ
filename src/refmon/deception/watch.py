"""Decoy-file watcher (v2.1, A72): notices when a planted decoy is opened.

Linux inotify, through ctypes, needs no privileges for files the daemon's user can read. inotify
does not say *which process* opened the file, so in this mode a hit is an **alert**, never a
block: there is no process to contain, and inventing one would be evidence from missing
information. `ignore_roles` cannot apply either (no role without a process). The heartbeat reports
the gap as degraded protection. With root, an admin sensor on fanotify (which reports the PID) can
feed the same decoys into the pipeline as `asset_access` events with a raw `path`; Observe then
matches the `file` canary, and the block and `ignore_roles` work (docs/deception.md).

The watcher never opens a decoy itself, and `refresh` changes only times, so neither trips it.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import errno
import os
import select
import struct
from pathlib import Path

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_OPEN = 0x00000020
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000
IN_NONBLOCK = 0x00000800
IN_CLOEXEC = 0x00080000
WATCHED = IN_OPEN | IN_ACCESS | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF
_EVENT = struct.Struct("iIII")  # wd, mask, cookie, len


class WatchUnavailable(OSError):
    """No inotify here (not Linux, or the limit of watches is reached)."""


class DecoyWatcher:
    """Watches decoy files and reports the canary names of the ones touched."""

    def __init__(self, decoys: dict[str, str]) -> None:
        """`decoys`: file path -> canary name."""
        name = ctypes.util.find_library("c")
        if not name:
            raise WatchUnavailable("no C library")
        libc = ctypes.CDLL(name, use_errno=True)
        if not hasattr(libc, "inotify_init1"):
            raise WatchUnavailable("inotify is not available")
        self._libc = libc
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise WatchUnavailable(os.strerror(ctypes.get_errno()))
        self._names: dict[int, str] = {}
        self.missing: list[str] = []  # decoys that could not be watched (gone, unreadable)
        for path, canary in decoys.items():
            wd = libc.inotify_add_watch(self.fd, os.fsencode(path), WATCHED)
            if wd < 0:
                err = ctypes.get_errno()
                if err == errno.ENOSPC:
                    self.close()
                    raise WatchUnavailable("the inotify watch limit is reached")
                self.missing.append(canary)
                continue
            self._names[wd] = canary

    @property
    def watched(self) -> int:
        return len(self._names)

    def poll(self, timeout: float) -> list[tuple[str, str]]:
        """Wait up to `timeout` seconds; return (canary name, what happened) per touch, where
        what is `opened`, `modified` or `removed` (a removed or moved decoy is no longer
        watched)."""
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            data = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return []
        hits: list[tuple[str, str]] = []
        offset = 0
        while offset + _EVENT.size <= len(data):
            wd, mask, _cookie, length = _EVENT.unpack_from(data, offset)
            offset += _EVENT.size + length
            canary = self._names.get(wd)
            if canary is None:
                continue
            if mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED):
                self._names.pop(wd, None)
                self.missing.append(canary)
                hits.append((canary, "removed"))
            elif mask & IN_MODIFY:
                hits.append((canary, "modified"))
            elif mask & (IN_OPEN | IN_ACCESS):
                hits.append((canary, "opened"))
        # one open is usually followed by reads: report each decoy once per poll
        return list(dict.fromkeys(hits))

    def close(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)


def decoys_from_proposal(proposal: dict) -> dict[str, str]:
    """file path -> canary name, from an approved (or proposed) decoy canary proposal."""
    return {
        c["value"]: c["name"]
        for c in proposal.get("canaries", [])
        if c.get("class") == "file" and Path(c["value"]).is_file()
    }
