"""Round 2, A3 (owner decision on review-list R2): a per-user daemon uses /etc/separ when IT put a
policy there, and then requires it root-owned and not writable by group or others. Only without one
does it fall back to the user's own folder, reported as degraded protection."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tests.livehelp import provision

from refmon import config
from refmon.cli import main as cli_main
from refmon.config import UntrustedFile, default_config_dir, resolve_policy_paths
from refmon.live import LiveBarrier

if os.geteuid() == 0:
    pytest.skip("these tests play a non-root daemon", allow_module_level=True)


def _root_owned(monkeypatch, under: Path, *, uid: int = 0, mode_or: int = 0):
    """Make files under `under` look owned by `uid` (a test cannot chown to root)."""
    real = config._lstat

    def fake(path: Path):
        st = real(path)
        if Path(path).resolve().is_relative_to(under.resolve()):
            fields = list(st)
            fields[4] = uid
            fields[0] = st.st_mode | mode_or
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(config, "_lstat", fake)


def _install_system_policy(mode: str = "observe") -> Path:
    system = config.SYSTEM_CONFIG_DIR
    provision(system, mode=mode)
    system.chmod(0o755)
    return system


def test_with_a_root_owned_system_policy_a_user_daemon_uses_it(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    provision(tmp_path / "xdg" / "separ", mode="block")  # the user's own: not used
    system = _install_system_policy("observe")
    _root_owned(monkeypatch, system)
    assert default_config_dir() == system
    assert resolve_policy_paths() == (system / "policy.yaml", system / "admin.pub")
    barrier = LiveBarrier(workdir=tmp_path / "wd")
    assert barrier.policy_path == system / "policy.yaml"
    assert barrier.policy.mode.value == "observe"
    assert barrier.policy_conditions() == []  # root-owned: no degraded protection


def test_a_system_policy_the_user_owns_is_refused_not_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    provision(tmp_path / "xdg" / "separ")
    _install_system_policy()  # owned by this (non-root) user
    with pytest.raises(UntrustedFile, match="root-owned"):
        LiveBarrier(workdir=tmp_path / "wd")


def test_a_system_policy_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    system = _install_system_policy()
    _root_owned(monkeypatch, system, uid=os.geteuid() + 1)
    with pytest.raises(UntrustedFile, match="not root"):
        LiveBarrier(workdir=tmp_path / "wd")


def test_a_group_writable_system_policy_is_refused(tmp_path, monkeypatch):
    system = _install_system_policy()
    _root_owned(monkeypatch, system, mode_or=0o020)
    with pytest.raises(UntrustedFile, match="group or others"):
        LiveBarrier(workdir=tmp_path / "wd")


def test_half_a_system_install_is_not_silently_skipped(tmp_path, monkeypatch):
    from refmon.config import PolicyMissing

    system = _install_system_policy()
    (system / "policy.yaml").unlink()  # only the public key is left
    _root_owned(monkeypatch, system)
    assert default_config_dir() == system
    with pytest.raises(PolicyMissing):
        LiveBarrier(workdir=tmp_path / "wd")


def test_without_a_system_policy_the_user_folder_is_used_and_degraded(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    provision(tmp_path / "xdg" / "separ", mode="warn")
    assert not config.SYSTEM_CONFIG_DIR.exists()
    barrier = LiveBarrier(workdir=tmp_path / "wd")
    assert barrier.policy_path == tmp_path / "xdg" / "separ" / "policy.yaml"
    assert barrier.policy.mode.value == "warn"
    assert {c[0] for c in barrier.policy_conditions()} == {"degraded:policy_owner_writable"}


def test_setup_as_a_user_never_writes_the_system_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    system = _install_system_policy()
    before = (system / "policy.yaml").read_bytes()
    assert cli_main(["setup", "--laptop", "--key", str(tmp_path / "k" / "a.key")]) == 0
    assert (tmp_path / "xdg" / "separ" / "policy.yaml").is_file()
    assert (system / "policy.yaml").read_bytes() == before
