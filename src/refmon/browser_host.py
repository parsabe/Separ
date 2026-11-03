"""Native-messaging host between the Refmon browser extension and the user's Refmon daemon (v2.1).

The browser starts this program (`refmon browser-host`) itself and talks to it over stdin and
stdout: each message is a 4-byte length in native byte order followed by that many bytes of UTF-8
JSON. Only the extension named in the host manifest may start it, and no web page can reach it, so
the daemon's port is never exposed to page scripts. The host forwards each observation in memory to
the daemon's `/api/browser` route with the daemon's API token and writes the answer back.

Privacy (CLAUDE.md Part A): the host is a sensor relay. It never logs, stores or hashes clipboard
text or addresses; it hands them to Observe in memory through the daemon and forgets them. Its only
diagnostics go to stderr and are fixed phrases.

Missing information never generates evidence: when the daemon is not running the host answers
`unavailable` and the extension shows degraded protection; nothing is judged.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import struct
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import IO, Any

HOST_NAME = "org.refmon.browser"
FIREFOX_EXTENSION_ID = "refmon-browser@refmon.invalid"
MAX_MESSAGE = 64 * 1024  # bytes; the daemon caps the clipboard text far below this
FORWARDED_KINDS = frozenset({"clipboard_write", "navigate", "download", "hold_answer"})
_HEADER = struct.Struct("=I")  # native byte order, as the browsers write it

UNAVAILABLE = {"decision": "unavailable", "reason": "daemon_not_running", "action": "none"}


class FramingError(ValueError):
    """The stream is out of step (a bad length or truncated message); the host must stop."""


def read_message(stream: IO[bytes]) -> dict[str, Any] | None:
    """One message, or None when the browser closed the pipe."""
    header = stream.read(_HEADER.size)
    if not header:
        return None
    if len(header) != _HEADER.size:
        raise FramingError("truncated length header")
    (length,) = _HEADER.unpack(header)
    if length > MAX_MESSAGE:
        raise FramingError("message too large")
    body = stream.read(length)
    if len(body) != length:
        raise FramingError("truncated message")
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FramingError("message is not UTF-8 JSON") from exc
    if not isinstance(message, dict):
        raise FramingError("message is not a JSON object")
    return message


def write_message(stream: IO[bytes], message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(_HEADER.pack(len(body)))
    stream.write(body)
    stream.flush()


class Forwarder:
    """Sends observations to the daemon's `/api/browser`. The token is read on every call, so a
    daemon restarted with a new token is found again without restarting the browser."""

    def __init__(self, workdir: Path, host: str = "localhost", port: int = 8765) -> None:
        self.workdir, self.host, self.port = Path(workdir), host, port

    def _token(self) -> str | None:
        with contextlib.suppress(OSError):
            return (self.workdir / "api.token").read_text(encoding="utf-8").strip()
        return None

    def _request(self, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        token = self._token()
        if token is None:
            return dict(UNAVAILABLE)
        headers = {"X-Refmon-Token": token, "Content-Type": "application/json"}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"http://{self.host}:{self.port}{path}", data=data, headers=headers,
            method="POST" if body is not None else "GET",
        )  # fmt: skip
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            with contextlib.suppress(Exception):
                reason = json.loads(exc.read().decode("utf-8")).get("error", "")
                return {"error": f"refused ({exc.code})", "detail": str(reason)[:200]}
            return {"error": f"refused ({exc.code})"}
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            return dict(UNAVAILABLE)

    def forward(self, message: dict[str, Any]) -> dict[str, Any]:
        return self._request("/api/browser", message)

    def ping(self) -> dict[str, Any]:
        state = self._request("/api/state", None)
        if "error" in state or state.get("decision") == "unavailable":
            return {"pong": True, "daemon": "unavailable"}
        return {"pong": True, "daemon": "running", "mode": state.get("policy", {}).get("mode")}


def handle(message: dict[str, Any], forwarder: Forwarder) -> dict[str, Any]:
    """Answer one message. The extension's `id` is echoed so it can match answers to requests."""
    request_id = message.pop("id", None)
    kind = message.get("kind")
    if kind == "ping":
        answer = forwarder.ping()
    elif kind in FORWARDED_KINDS:
        answer = forwarder.forward(message)
    else:
        answer = {"error": "unknown kind"}
    if request_id is not None:
        answer["id"] = request_id
    return answer


def serve(stdin: IO[bytes], stdout: IO[bytes], forwarder: Forwarder) -> int:
    """Run until the browser closes the pipe. A framing error ends the host (the stream can no
    longer be trusted); the browser starts a new one on the next message."""
    while True:
        try:
            message = read_message(stdin)
        except FramingError as exc:
            print(f"refmon browser-host: {exc}", file=sys.stderr)
            return 1
        if message is None:
            return 0
        write_message(stdout, handle(message, forwarder))


# -- installing the host manifests ---------------------------------------------------------------

USER_MANIFEST_DIRS = {
    "firefox": ".mozilla/native-messaging-hosts",
    "chromium": ".config/chromium/NativeMessagingHosts",
    "chrome": ".config/google-chrome/NativeMessagingHosts",
}
SYSTEM_MANIFEST_DIRS = {
    "firefox": (
        "/usr/lib/mozilla/native-messaging-hosts",  # Debian, Ubuntu
        "/usr/lib64/mozilla/native-messaging-hosts",  # RHEL, Rocky, Fedora
    ),
    "chromium": ("/etc/chromium/native-messaging-hosts",),
    "chrome": ("/etc/opt/chrome/native-messaging-hosts",),
}


def manifest(browser: str, launcher: Path, *, firefox_id: str, chromium_ids: Iterable[str]) -> dict:
    base = {
        "name": HOST_NAME,
        "description": "Refmon browser protection: judges clipboard writes and downloads",
        "path": str(launcher),
        "type": "stdio",
    }
    if browser == "firefox":
        return {**base, "allowed_extensions": [firefox_id]}
    return {**base, "allowed_origins": [f"chrome-extension://{i}/" for i in chromium_ids]}


def launcher_script(python: str, workdir: Path | None, port: int) -> str:
    args = [python, "-m", "refmon.cli", "browser-host", "--port", str(port)]
    if workdir is not None:
        args += ["--workdir", str(workdir)]
    quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in args)
    # the browser appends its own arguments (manifest path and extension id, or the origin)
    return f'#!/bin/sh\nexec {quoted} "$@"\n'


def install(
    *,
    home: Path,
    launcher_dir: Path,
    system: bool = False,
    workdir: Path | None = None,
    port: int = 8765,
    firefox_id: str = FIREFOX_EXTENSION_ID,
    chromium_ids: Iterable[str] = (),
    python: str | None = None,
    system_root: Path = Path("/"),
) -> list[Path]:
    """Write the launcher and one manifest per browser. Chromium-family manifests are written only
    when an extension id is given (the id of a packed extension is known only after packing)."""
    chromium_ids = list(chromium_ids)
    launcher_dir.mkdir(parents=True, exist_ok=True)
    launcher = launcher_dir / "refmon-browser-host"
    launcher.write_text(launcher_script(python or sys.executable, workdir, port), encoding="utf-8")
    launcher.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    written = [launcher]
    browsers = ["firefox"] + (["chromium", "chrome"] if chromium_ids else [])
    for browser in browsers:
        doc = manifest(browser, launcher, firefox_id=firefox_id, chromium_ids=chromium_ids)
        if system:
            targets = [system_root / d.lstrip("/") for d in SYSTEM_MANIFEST_DIRS[browser]]
        else:
            targets = [home / USER_MANIFEST_DIRS[browser]]
        for directory in targets:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"{HOST_NAME}.json"
            path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            os.chmod(path, 0o644)
            written.append(path)
    return written
