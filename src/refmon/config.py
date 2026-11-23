"""Where Separ keeps its configuration, its state and the admin's signing key (review 2026-11).

One source of truth for every path, so that `separ setup` writes the policy the daemon reads:

- signed policy and public key: /etc/separ/ for the system daemon, and for a per-user daemon too
  whenever /etc/separ holds one (it must then be root-owned); else $XDG_CONFIG_HOME/separ/
- work directory (state, logs): /var/lib/separ (root), else $XDG_STATE_HOME/separ/
- admin signing key: never on an endpoint; the admin's own ~/.separ-admin/admin.key

The daemon only ever reads the **public** key. Everything that signs (`separ setup`,
`separ policy`, `separ sign`, `separ decoy approve-*`) runs as an admin command that reads the
private key from `--key PATH`, never from the daemon's work directory.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

SYSTEM_CONFIG_DIR = Path("/etc/separ")
SYSTEM_WORKDIR = Path("/var/lib/separ")
POLICY_NAME = "policy.yaml"
PUBLIC_KEY_NAME = "admin.pub"
SETUP_HINT = "run `separ setup` first (as root for the system daemon)"


class PolicyMissing(FileNotFoundError):
    """No signed policy where the daemon looks: it refuses to start (it never makes one)."""


class UntrustedFile(PermissionError):
    """A policy or public key that someone other than the admin could change."""


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var, "")
    base = Path(value) if value and Path(value).is_absolute() else Path.home() / fallback
    return base / "separ"


def user_config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config")


def user_state_dir() -> Path:
    return _xdg("XDG_STATE_HOME", ".local/state")


def system_config_present() -> bool:
    """IT installed a system policy (/etc/separ/policy.yaml or admin.pub exists)."""
    return any((SYSTEM_CONFIG_DIR / n).exists() for n in (POLICY_NAME, PUBLIC_KEY_NAME))


def default_config_dir() -> Path:
    """Where the daemon reads its policy (owner decision R2, round 2): /etc/separ for the system
    daemon, and for a per-user daemon too whenever /etc/separ holds a policy or public key (then
    they must be root-owned: check_trusted). Only without one does a per-user daemon fall back to
    its own $XDG_CONFIG_HOME/separ, reported as degraded protection."""
    if is_root() or system_config_present():
        return SYSTEM_CONFIG_DIR
    return user_config_dir()


def default_workdir() -> Path:
    """/var/lib/separ for the system daemon (root), $XDG_STATE_HOME/separ otherwise."""
    return SYSTEM_WORKDIR if is_root() else user_state_dir()


def legacy_tmp_workdir() -> Path:
    """The work directory before review 2026-11 (predictable, shared, wiped at reboot)."""
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    return Path(tempfile.gettempdir()) / f"separ-live-{uid}"


def default_admin_key() -> Path:
    """The admin's private signing key: a separate 0700 directory in the admin's home, on the
    admin's machine. It is never copied to an endpoint and never read by the daemon."""
    return Path.home() / ".separ-admin" / "admin.key"


def resolve_policy_paths(
    policy: str | Path | None = None, public_key: str | Path | None = None
) -> tuple[Path, Path]:
    """(policy, public key). Explicit paths win; the public key defaults to the policy's folder."""
    pol = Path(policy) if policy else default_config_dir() / POLICY_NAME
    pub = Path(public_key) if public_key else pol.parent / PUBLIC_KEY_NAME
    return pol, pub


# -- safe directories and secret files --------------------------------------------------------


def secure_dir(path: Path, mode: int = 0o700) -> None:
    """A directory that holds keys or state: a real directory owned by this user, never a symlink,
    closed to everyone else (`mode`). On a shared node another user could create a predictable
    path first with their own keys, or plant a symlink to a directory they control."""
    path = Path(path)
    if not path.is_symlink() and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir(mode=mode)
    if path.is_symlink() or not path.is_dir():
        raise PermissionError(f"refusing directory {path}: not a plain directory")
    if hasattr(os, "getuid") and path.lstat().st_uid != os.getuid():
        raise PermissionError(f"refusing directory {path}: it belongs to another user")
    path.chmod(mode)


def secret_file(path: Path, make: Callable[[], str]) -> str:
    """Read a secret, creating it first (O_EXCL, mode 0600 from the start, never briefly
    readable, never through a symlink)."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        write_secret(path, make())
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PermissionError(f"refusing secret {path}: not a plain file")
    return path.read_text(encoding="utf-8").strip()


def write_secret(path: Path, text: str) -> None:
    """Create a new secret file, 0600 from its first byte. Refuses to overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text.rstrip("\n") + "\n")


def write_public(path: Path, text: str, mode: int = 0o644) -> None:
    """Write a file meant to be read by the daemon (policy, public key): replaced atomically,
    `mode` set before it becomes visible, never written through a symlink."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            os.fchmod(fh.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# -- trust checks on what the daemon reads ------------------------------------------------------


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def check_trusted(path: Path, *, system: bool | None = None, euid: int | None = None) -> list[str]:
    """Refuse a policy or public key (or its folder) that someone other than the admin can change.

    Always refused: a symlink, a non-regular file, anything writable by group or others, and for a
    root daemon anything not owned by root. In the system configuration (/etc/separ) every daemon,
    root or per-user, requires root-owned files and folder: a file its own user (or any other
    non-root user) owns could be rolled back by that user. In the per-user fallback configuration
    the user is by definition the owner; that is returned as a warning (`owner_writable`),
    reported as degraded protection, not refused (docs/review-list.md R2, owner decision).
    """
    path = Path(path)
    euid = (os.geteuid() if hasattr(os, "geteuid") else 1000) if euid is None else euid
    if system is None:
        system = _under(path, SYSTEM_CONFIG_DIR)
    warnings: list[str] = []
    for item, kind in ((path, "file"), (path.parent, "directory")):
        st = _lstat(item)
        if stat.S_ISLNK(st.st_mode):
            raise UntrustedFile(f"refusing {item}: a symlink")
        if kind == "file" and not stat.S_ISREG(st.st_mode):
            raise UntrustedFile(f"refusing {item}: not a regular file")
        if st.st_mode & 0o022:
            raise UntrustedFile(f"refusing {kind} {item}: writable by group or others")
        if (euid == 0 or system) and st.st_uid != 0:
            if st.st_uid == euid:
                raise UntrustedFile(
                    f"refusing {item}: writable by the daemon's own user (it must be root-owned)"
                )
            raise UntrustedFile(f"refusing {kind} {item}: owned by uid {st.st_uid}, not root")
        if euid != 0 and st.st_uid == euid and "owner_writable" not in warnings:
            warnings.append("owner_writable")
    return warnings


def migrate_legacy_workdir(workdir: Path, log: Callable[[str], Any] = print) -> list[str]:
    """Copy device.key and pseudonym.key once from the old /tmp work directory, if it exists and
    belongs to this user, so that fingerprints and pseudonyms stay comparable. Returns the names
    copied (and says so)."""
    old = legacy_tmp_workdir()
    marker = workdir / ".migrated-from-tmp"
    if marker.exists() or old.resolve() == Path(workdir).resolve():
        return []
    try:
        st = old.lstat()
    except OSError:
        return []
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return []
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return []
    copied = []
    for name in ("device.key", "pseudonym.key"):
        src, dst = old / name, Path(workdir) / name
        try:
            sst = src.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(sst.st_mode) or (hasattr(os, "getuid") and sst.st_uid != os.getuid()):
            continue
        if dst.exists():
            continue
        write_secret(dst, src.read_text(encoding="utf-8").strip())
        copied.append(name)
    write_public(marker, "copied: " + ",".join(copied) + "\n", mode=0o600)
    if copied:
        log(f"migrated {', '.join(copied)} from the old work directory {old} to {workdir}")
    return copied
