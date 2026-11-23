"""Review 2026-11, items 1 and 2: one source of truth for the policy, and no signing in the daemon.

`separ setup` writes the policy where the daemon reads it; the daemon refuses to start without
one; only the admin tools (with the private key from --key) can sign; /api/mode is gone; a policy
or public key that someone else can change is refused.
"""

from __future__ import annotations

import ast
import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from tests.livehelp import make_barrier, provision

from refmon import admin, signing
from refmon.cli import main as cli_main
from refmon.config import PolicyMissing, UntrustedFile, check_trusted, resolve_policy_paths
from refmon.live import LiveBarrier, make_http_server

SRC = Path(__file__).resolve().parents[1] / "src" / "refmon"
# every module that runs inside the daemon (serve, gui, browser host relay, sensors, decoys)
DAEMON_MODULES = [
    "live.py",
    "health.py",
    "heartbeat.py",
    "notify.py",
    "browser_host.py",
    "live_ui.py",
    "ingest/runtime.py",
    "ingest/mapping.py",
    "deception/runtime.py",
    "deception/listener.py",
    "deception/watch.py",
    "deception/proposals.py",
]
SIGNING_NAMES = {"sign", "signed", "sign_message", "generate_keypair", "write_signed"}


def _setup(tmp_path: Path, *extra: str) -> tuple[Path, Path]:
    config, key = tmp_path / "etc-separ", tmp_path / "admin-home" / "admin.key"
    assert cli_main(["setup", "--config-dir", str(config), "--key", str(key), *extra]) == 0
    return config, key


def test_setup_then_start_uses_exactly_that_policy(tmp_path: Path, capsys) -> None:
    config, key = _setup(tmp_path, "--laptop", "--mode", "observe")
    barrier = LiveBarrier(workdir=tmp_path / "state", policy_path=config / "policy.yaml")
    assert barrier.policy.mode.value == "observe"
    assert barrier.pub_path == config / "admin.pub"
    # the setup's destinations and identity settings are in force
    assert "local" in {d.name for d in barrier.policy.destinations}
    assert barrier.policy.identity.approved_apps == ["Browser", "Terminal", "VSCode", "Git"]
    # files the daemon reads are 0644; the key is 0600 in a 0700 folder outside both
    assert (config / "policy.yaml").stat().st_mode & 0o777 == 0o644
    assert (config / "admin.pub").stat().st_mode & 0o777 == 0o644
    assert key.stat().st_mode & 0o777 == 0o600
    assert key.parent.stat().st_mode & 0o777 == 0o700
    assert not list(config.rglob("admin.key")) and not list(barrier.workdir.rglob("admin.key"))


def test_a_missing_policy_stops_the_start(tmp_path: Path, capsys) -> None:
    with pytest.raises(PolicyMissing):
        LiveBarrier(workdir=tmp_path / "wd", policy_path=tmp_path / "cfg" / "policy.yaml")
    code = cli_main(
        ["serve", "--workdir", str(tmp_path / "wd"), "--policy", str(tmp_path / "x.yaml")]
    )
    assert code == 1
    assert "separ setup" in capsys.readouterr().err
    assert not (tmp_path / "x.yaml").exists()


def test_policy_paths_default_to_the_config_folder(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    pol, pub = resolve_policy_paths()
    assert pol == tmp_path / "xdg" / "separ" / "policy.yaml"
    assert pub == tmp_path / "xdg" / "separ" / "admin.pub"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert resolve_policy_paths() == (Path("/etc/separ/policy.yaml"), Path("/etc/separ/admin.pub"))
    assert resolve_policy_paths("/x/p.yaml", None)[1] == Path("/x/admin.pub")


# -- item 2: the daemon only verifies --------------------------------------------------------


def _calls_to_signing(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and (node.module.endswith("admin") or node.module.endswith("signing"))
        ):
            found += [a.name for a in node.names if a.name in SIGNING_NAMES or a.name == "admin"]
        if isinstance(node, ast.Attribute) and node.attr in SIGNING_NAMES:
            found.append(node.attr)
        if isinstance(node, ast.Name) and node.id in SIGNING_NAMES:
            found.append(node.id)
        if isinstance(node, ast.Constant) and node.value in ("admin.key", "_private_key"):
            found.append(str(node.value))
    return found


@pytest.mark.parametrize("module", DAEMON_MODULES)
def test_no_daemon_module_can_produce_a_signature(module: str) -> None:
    assert _calls_to_signing(SRC / module) == []


def test_the_running_daemon_never_signs(tmp_path: Path, monkeypatch) -> None:
    barrier = make_barrier(tmp_path / "wd")

    def refuse(*a, **k):
        raise AssertionError("the daemon tried to sign")

    for name in ("sign", "signed", "sign_message", "generate_keypair"):
        monkeypatch.setattr(signing, name, refuse)
    barrier.run_all_presets()
    barrier.reload_policy()
    server = make_http_server(barrier, host="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        for path, body in (("/api/reload", {}), ("/api/mode", {"mode": "observe"})):
            req = urllib.request.Request(
                f"http://localhost:{port}{path}", data=json.dumps(body).encode(), method="POST",
                headers={"Content-Type": "application/json", "X-Separ-Token": barrier.api_token},
            )  # fmt: skip
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            assert status == (200 if path == "/api/reload" else 404)
    finally:
        server.shutdown()
        server.server_close()
        t.join(2)
    assert barrier.policy.mode.value == "block"  # /api/mode is gone: nothing switched it off
    assert not hasattr(barrier, "set_mode") and not hasattr(barrier, "_private_key")


def test_mode_change_is_a_new_signed_file_plus_reload(tmp_path: Path, capsys) -> None:
    barrier = make_barrier(tmp_path / "wd")
    pol = ["--policy", str(barrier.policy_path), "--public-key", str(barrier.pub_path)]
    assert (
        cli_main(["policy", "set-mode", "observe", *pol, "--key", str(barrier.test_admin_key)]) == 0
    )
    assert barrier.policy.mode.value == "block"  # not before the reload
    assert barrier.reload_policy()["mode"] == "observe"
    capsys.readouterr()
    assert cli_main(["policy", "show", *pol, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "observe"


def test_a_tampered_file_is_never_re_signed_and_a_reload_keeps_the_last_valid(tmp_path: Path):
    barrier = make_barrier(tmp_path / "wd")
    text = barrier.policy_path.read_text().replace("mode: block", "mode: observe")
    barrier.policy_path.write_text(text)
    with pytest.raises(ValueError):
        admin.set_mode("warn", barrier.policy_path, barrier.pub_path, barrier.test_admin_key)
    res = barrier.reload_policy()
    assert res["reloaded"] is False and barrier.policy.mode.value == "block"


def test_a_key_in_a_daemon_work_directory_is_refused(tmp_path: Path, monkeypatch) -> None:
    workdir = tmp_path / "state" / "separ"
    workdir.mkdir(parents=True)
    monkeypatch.setattr("refmon.admin.default_workdir", lambda: workdir)
    key = workdir / "admin.key"
    key.write_text(signing.generate_keypair()[0])
    key.chmod(0o600)
    with pytest.raises(admin.KeyRefused, match="work directory"):
        admin.read_private_key(key)
    other = tmp_path / "k"
    other.write_text(signing.generate_keypair()[0])
    other.chmod(0o644)
    with pytest.raises(admin.KeyRefused, match="group or others"):
        admin.read_private_key(other)


def test_a_policy_writable_by_others_is_refused(tmp_path: Path) -> None:
    policy, public, _ = provision(tmp_path / "cfg")
    policy.chmod(0o664)
    with pytest.raises(UntrustedFile, match="group or others"):
        LiveBarrier(workdir=tmp_path / "wd", policy_path=policy, public_key_path=public)
    policy.chmod(0o644)
    public.chmod(0o646)
    with pytest.raises(UntrustedFile):
        LiveBarrier(workdir=tmp_path / "wd", policy_path=policy, public_key_path=public)
    public.chmod(0o644)
    policy.parent.chmod(0o775)
    with pytest.raises(UntrustedFile, match="directory"):
        LiveBarrier(workdir=tmp_path / "wd", policy_path=policy, public_key_path=public)


def test_trust_rules_for_the_system_daemon(tmp_path: Path) -> None:
    policy, _, _ = provision(tmp_path / "cfg")
    me = os.geteuid()
    # in /etc/separ a file the (non-root) daemon user owns is refused: it could roll it back
    with pytest.raises(UntrustedFile, match="daemon's own user"):
        check_trusted(policy, system=True, euid=me if me else 1000)
    # a root daemon refuses anything not owned by root
    if me != 0:
        with pytest.raises(UntrustedFile, match="not root"):
            check_trusted(policy, system=True, euid=0)
    # the per-user configuration: owned by the user, reported (degraded), not refused
    assert check_trusted(policy, system=False, euid=me if me else 1000) in ([], ["owner_writable"])
    link = tmp_path / "cfg" / "link.yaml"
    link.symlink_to(policy)
    with pytest.raises(UntrustedFile, match="symlink"):
        check_trusted(link, system=False)


def test_the_per_user_daemon_reports_an_owner_writable_policy(tmp_path: Path) -> None:
    barrier = make_barrier(tmp_path / "wd")
    if os.geteuid() == 0:
        pytest.skip("as root the test files are root-owned")
    keys = {c[0] for c in barrier.policy_conditions()}
    assert keys == {"degraded:policy_owner_writable"}
