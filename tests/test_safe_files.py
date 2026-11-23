"""Review 2026-11, item 4: keys and work directories are created safely.

Secret files are 0600 from their first byte (O_EXCL, never write-then-chmod); a directory that
another user owns, or a symlink, is refused; the per-user work directory is $XDG_STATE_HOME/separ,
not a predictable path under /tmp; the old /tmp keys are copied over once.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from tests.livehelp import provision

from refmon import config
from refmon.cli import main as cli_main
from refmon.config import secret_file, secure_dir, write_secret
from refmon.live import LiveBarrier, default_live_workdir


@pytest.fixture
def opened(monkeypatch):
    """Record every os.open (path, flags, mode) and refuse any chmod of a secret afterwards."""
    calls: list[tuple[str, int, int]] = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *a, **k):
        calls.append((str(path), flags, mode))
        return real_open(path, flags, mode, *a, **k)

    monkeypatch.setattr(os, "open", spy)
    return calls


def _secret_opens(calls, name):
    return [(f, m) for p, f, m in calls if p.endswith(name)]


def test_setup_creates_the_admin_key_0600_from_the_start(tmp_path, opened, monkeypatch):
    old = os.umask(0)  # a permissive umask must not matter
    try:
        key = tmp_path / "adm" / "admin.key"
        assert cli_main(["setup", "--config-dir", str(tmp_path / "cfg"), "--key", str(key)]) == 0
    finally:
        os.umask(old)
    ((flags, mode),) = _secret_opens(opened, "admin.key")
    assert mode == 0o600 and flags & os.O_EXCL and flags & os.O_CREAT
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "cfg").stat().st_mode) == 0o755


def test_every_daemon_secret_is_0600_at_creation(tmp_path, opened):
    policy, public, _ = provision(tmp_path / "cfg")
    old = os.umask(0)
    try:
        LiveBarrier(workdir=tmp_path / "wd", policy_path=policy, public_key_path=public)
    finally:
        os.umask(old)
    for name in ("device.key", "api.token", "pseudonym.key"):
        ((flags, mode),) = _secret_opens(opened, name)
        assert mode == 0o600 and flags & os.O_EXCL, name
        assert stat.S_IMODE((tmp_path / "wd" / name).stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "wd").stat().st_mode) == 0o700


def test_keygen_never_overwrites_and_is_0600(tmp_path):
    key = tmp_path / "k"
    old = os.umask(0)
    try:
        assert cli_main(["keygen", str(key)]) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert cli_main(["keygen", str(key)]) == 1  # exists: refused, not replaced


def test_a_directory_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    victim = tmp_path / "planted"
    victim.mkdir(mode=0o700)
    me = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: me + 1)  # as if another user had created it
    with pytest.raises(PermissionError, match="another user"):
        secure_dir(victim)
    monkeypatch.undo()
    policy, public, _ = provision(tmp_path / "cfg")
    monkeypatch.setattr(os, "getuid", lambda: me + 1)
    with pytest.raises(PermissionError):
        LiveBarrier(workdir=victim, policy_path=policy, public_key_path=public)


def test_a_symlinked_directory_or_secret_is_refused(tmp_path):
    target = tmp_path / "attacker"
    target.mkdir()
    link = tmp_path / "separ"
    link.symlink_to(target)
    with pytest.raises(PermissionError, match="plain directory"):
        secure_dir(link)
    (target / "file").write_text("x")
    secret_link = tmp_path / "device.key"
    secret_link.symlink_to(target / "file")
    with pytest.raises(PermissionError):
        secret_file(secret_link, lambda: "new")
    with pytest.raises(FileExistsError):
        write_secret(secret_link, "new")  # O_EXCL | O_NOFOLLOW: never written through
    assert (target / "file").read_text() == "x"


def test_the_per_user_work_directory_is_xdg_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert default_live_workdir() == tmp_path / "state" / "separ"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert default_live_workdir() == Path.home() / ".local" / "state" / "separ"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert default_live_workdir() == Path("/var/lib/separ")


def test_the_old_tmp_keys_are_copied_once_and_said_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path / "tmp"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdgcfg"))
    old = config.legacy_tmp_workdir()
    old.mkdir(parents=True, mode=0o700)
    write_secret(old / "device.key", "ab" * 32)
    write_secret(old / "pseudonym.key", "cd" * 32)
    provision(tmp_path / "xdgcfg" / "separ")
    barrier = LiveBarrier()
    assert barrier.workdir == tmp_path / "state" / "separ"
    assert barrier._device_key == bytes.fromhex("ab" * 32)
    assert (barrier.workdir / "pseudonym.key").read_text().strip() == "cd" * 32
    assert "migrated device.key, pseudonym.key" in capsys.readouterr().out
    # once: a changed old key is not copied again
    (old / "device.key").unlink()
    write_secret(old / "device.key", "ef" * 32)
    assert LiveBarrier()._device_key == bytes.fromhex("ab" * 32)
    assert "migrated" not in capsys.readouterr().out


def test_old_tmp_keys_of_another_user_are_not_copied(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path / "tmp"))
    old = config.legacy_tmp_workdir()
    old.mkdir(parents=True)
    write_secret(old / "device.key", "ab" * 32)
    me = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: me + 1)
    assert config.migrate_legacy_workdir(tmp_path / "new") == []


@pytest.mark.parametrize(
    "command",
    [
        "rm ~/.local/state/separ/device.key",
        "echo 'mode: observe' > ~/.config/separ/policy.yaml",
        "cp evil.pub ~/.config/separ/admin.pub",
        "shred ~/.separ-admin/admin.key",
    ],
)
def test_the_new_locations_are_still_separ_itself(command):
    """Moving the files must not drop the self-tamper protection that named the old paths."""
    from refmon.intent import analyze

    assert analyze(command).tamper == "self"


def test_no_production_class_has_a_default_key():
    """Review 2026-11, item 8: a forgotten key is an error, never the constant everyone knows."""
    import inspect

    from refmon.pipeline import Pipeline
    from refmon.policy import default_policy
    from refmon.rootkit import RootkitScanner, evaluate_rootkit_scan

    for fn in (Pipeline.__init__, RootkitScanner.__init__, evaluate_rootkit_scan):
        param = inspect.signature(fn).parameters["key"]
        assert param.default is inspect.Parameter.empty, fn
    with pytest.raises(TypeError):
        Pipeline(default_policy())
    src = Path(__file__).resolve().parents[1] / "src" / "refmon"
    holders = sorted(
        str(p.relative_to(src)) for p in src.rglob("*.py") if b"refmon-device-key" in p.read_bytes()
    )
    assert holders == [
        "audit.py",
        "keys.py",
    ]  # the named lab replay key, and the audit's guess list


def test_ingest_check_judge_uses_a_fresh_random_key(tmp_path, monkeypatch):
    import refmon.keys as keys

    made = []
    real = keys.new_device_key
    monkeypatch.setattr(keys, "new_device_key", lambda: made.append(1) or real())
    maps = Path(__file__).resolve().parents[1] / "src" / "refmon" / "ingest" / "mappings"
    sample = tmp_path / "ssh.jsonl"
    sample.write_text(
        '{"_COMM": "sshd", "MESSAGE": "Accepted password for alice from 203.0.113.7 port 22 ssh2",'
        ' "__REALTIME_TIMESTAMP": "1795000000000000", "_HOSTNAME": "h"}\n'
    )
    cli_main(
        ["ingest", "check", str(maps / "sshd-journald.yaml"), "--input", str(sample), "--judge"]
    )
    assert made
