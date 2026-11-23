"""The admin's side of the signed policy: everything that signs lives here (review 2026-11, item 2).

The daemon never imports this module and never holds a private key. `separ setup`,
`separ policy sign|set-mode|show` and the deception approvals call it with the private key read
from `--key PATH` (default ~/.separ-admin/admin.key, a 0700 directory on the admin's machine).
A key file inside a daemon work directory is refused.

    separ policy show     [--policy P] [--public-key K]            verify and summarize
    separ policy sign     [--policy P] [--key KEY]                 sign the file in place
    separ policy set-mode MODE [--policy P] [--public-key K] [--key KEY]
                                                                    verify, change the mode, re-sign
    separ reload [--workdir W]                                      the daemon re-reads and verifies
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import yaml

from . import signing
from .config import (
    SYSTEM_WORKDIR,
    default_admin_key,
    default_workdir,
    legacy_tmp_workdir,
    secure_dir,
    write_public,
    write_secret,
)
from .policy_io import LoadedPolicy, load_policy_data, read_document
from .schemas import Mode


class KeyRefused(PermissionError):
    """A private key file the admin tools will not use."""


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def read_private_key(path: str | Path | None = None) -> str:
    """The admin's private key from `path` (default ~/.separ-admin/admin.key). Refused when it is a
    symlink, readable by group or others, or lies in a daemon work directory."""
    key = Path(path) if path else default_admin_key()
    for workdir in {SYSTEM_WORKDIR, default_workdir(), legacy_tmp_workdir()}:
        if _inside(key, workdir):
            raise KeyRefused(
                f"refusing the private key {key}: it lies in the daemon work directory {workdir}; "
                "keep it on the admin's machine (--key PATH)"
            )
    try:
        st = key.lstat()
    except FileNotFoundError as exc:
        raise KeyRefused(
            f"no private key at {key}: pass --key PATH (the admin's key, not on the endpoint)"
        ) from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise KeyRefused(f"refusing the private key {key}: not a plain file")
    if st.st_mode & 0o077:
        raise KeyRefused(f"refusing the private key {key}: readable by group or others (chmod 600)")
    return key.read_text(encoding="utf-8").strip()


def ensure_admin_key(path: str | Path | None = None) -> tuple[str, str, bool]:
    """(private, public, created). Creates the key in a 0700 directory, 0600 from the start."""
    key = Path(path) if path else default_admin_key()
    if key.exists() or key.is_symlink():
        private = read_private_key(key)
        return private, signing.public_key_of(private), False
    secure_dir(key.parent, 0o700)
    private, public = signing.generate_keypair()
    write_secret(key, private)
    return private, public, True


def dump(document: dict[str, Any]) -> str:
    return yaml.safe_dump(document, sort_keys=False, width=100)


def write_signed_policy(document: dict[str, Any], private_key: str, path: str | Path) -> None:
    """Sign and write a policy readable by the daemon (0644, atomic, never through a symlink)."""
    body = {k: v for k, v in document.items() if k != signing.SIGNATURE_FIELD}
    write_public(Path(path), dump(signing.signed(body, private_key)), mode=0o644)


def write_public_key(public: str, path: str | Path) -> None:
    write_public(Path(path), public.strip() + "\n", mode=0o644)


def verified(policy: str | Path, public_key: str | Path) -> LoadedPolicy:
    pub = Path(public_key).read_text(encoding="utf-8").strip()
    return load_policy_data(policy, [pub])


def sign_file(policy: str | Path, key: str | Path | None = None) -> None:
    """Sign a policy document in place (after a human edited it)."""
    write_signed_policy(read_document(policy), read_private_key(key), policy)


def set_mode(
    mode: str, policy: str | Path, public_key: str | Path, key: str | Path | None = None
) -> LoadedPolicy:
    """Verify the current policy (a tampered file is never re-signed), change its mode, re-sign."""
    wanted = Mode(mode.lower())
    private = read_private_key(key)
    if signing.public_key_of(private) != Path(public_key).read_text(encoding="utf-8").strip():
        raise KeyRefused("the private key does not belong to the policy's public key")
    verified(policy, public_key)
    doc = read_document(policy)
    doc["mode"] = wanted.value
    write_signed_policy(doc, private, policy)
    return verified(policy, public_key)


def show(policy: str | Path, public_key: str | Path) -> dict[str, Any]:
    loaded = verified(policy, public_key)
    p = loaded.policy
    return {
        "policy": str(policy),
        "public_key": str(public_key),
        "signature": "ok",
        "digest": loaded.digest,
        "mode": p.mode.value,
        "destinations": [d.name for d in p.destinations],
        "trusted_sources": [t.name for t in p.trusted_sources],
        "packs": [f"{n} {v}" for n, v in loaded.packs],
        "owner_uid": os.stat(policy).st_uid,
        "file_mode": oct(os.stat(policy).st_mode & 0o777),
    }
