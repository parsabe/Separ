"""Start a live barrier the way an installation does: `separ setup` first (review 2026-11).

The daemon never makes a policy or holds a private key, so every test provisions a signed policy
and public key in a config folder next to the work directory, with the admin key apart from both.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from refmon.admin import ensure_admin_key, set_mode, write_public_key, write_signed_policy
from refmon.config import secure_dir
from refmon.live import LiveBarrier
from refmon.policy import default_policy_dict


def provision(
    config_dir: Path, *, mode: str = "block", mutate: Any = None
) -> tuple[Path, Path, Path]:
    """(policy, public key, admin key): a signed policy as `separ setup` writes it."""
    config_dir = Path(config_dir)
    secure_dir(config_dir, 0o700)
    key = config_dir.parent / f"{config_dir.name}-admin" / "admin.key"
    priv, pub, _ = ensure_admin_key(key)
    doc = default_policy_dict()
    doc["mode"] = mode
    if mutate is not None:
        mutate(doc)
    policy, public = config_dir / "policy.yaml", config_dir / "admin.pub"
    write_public_key(pub, public)
    write_signed_policy(doc, priv, policy)
    return policy, public, key


def make_barrier(
    workdir: Path, *, mode: str = "block", mutate: Any = None, **kw: Any
) -> LiveBarrier:
    workdir = Path(workdir)
    config = workdir.parent / f"{workdir.name}-config"
    if not (config / "policy.yaml").exists():
        provision(config, mode=mode, mutate=mutate)
    barrier = LiveBarrier(
        workdir=workdir,
        policy_path=config / "policy.yaml",
        public_key_path=config / "admin.pub",
        **kw,
    )
    barrier.test_admin_key = config.parent / f"{config.name}-admin" / "admin.key"
    return barrier


def change_mode(barrier: LiveBarrier, mode: str) -> dict[str, Any]:
    """What an admin does: re-sign with the admin key, then `separ reload`."""
    set_mode(mode, barrier.policy_path, barrier.pub_path, barrier.test_admin_key)
    return barrier.reload_policy(why="test mode change")
