"""Guided policy setup for Separ (servers and laptops).

`separ setup` writes the signed policy and the public key exactly where the daemon reads them
(review 2026-11, item 1): /etc/separ/ for the system daemon (run as root), $XDG_CONFIG_HOME/separ/
for a per-user daemon, or `--config-dir`. The private key stays with the admin (`--key`, default
~/.separ-admin/admin.key): the daemon only ever gets the public key.
"""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

from .admin import ensure_admin_key, write_public_key, write_signed_policy
from .config import (
    POLICY_NAME,
    PUBLIC_KEY_NAME,
    default_admin_key,
    default_config_dir,
    is_root,
    secure_dir,
)
from .policy import default_policy_dict


def run_setup(args: argparse.Namespace) -> int:
    """Write and sign the policy for a server or a laptop."""
    is_server = getattr(args, "server", False)
    is_laptop = getattr(args, "laptop", False)
    config_arg = getattr(args, "config_dir", None)
    mode_arg = getattr(args, "mode", None) or "observe"
    key_path = Path(getattr(args, "key", None) or default_admin_key())

    target_dir = Path(config_arg) if config_arg else default_config_dir()
    # the daemon must be able to read the folder; nobody else may write it
    secure_dir(target_dir, 0o755)

    print("=" * 64)
    print(" Separ Security Configuration & Policy Setup")
    print("=" * 64)

    priv, pub, created = ensure_admin_key(key_path)
    pub_path = target_dir / PUBLIC_KEY_NAME
    if pub_path.exists():
        existing = pub_path.read_text(encoding="utf-8").strip()
        if existing != pub:
            raise PermissionError(
                f"{pub_path} holds another admin's public key; pass that admin's --key, or "
                "remove the file on purpose to change the trust anchor"
            )
    if created:
        print(f"✓ Generated the admin signing key: {key_path} (0600, in a 0700 folder)")
    else:
        print(f"✓ Using the admin signing key: {key_path}")

    policy_doc = default_policy_dict()
    policy_doc["mode"] = mode_arg

    is_server_target = is_server or (is_root() and not is_laptop)
    if is_server_target:
        print("✓ Configuring for: Server Infrastructure (TUBAF Campus / Enterprise)")
        policy_doc["identity"] = {
            "internal_mail_domains": ["tu-freiberg.de"],
            "approved_apps": ["Zoom", "Moodle", "Nextcloud", "OPAL"],
            "min_logins": 20,
            "failure_burst": 10,
            "burst_window": "5m",
        }
        policy_doc["destinations"] = [
            {"name": "campus", "match": {"cidr": ["139.18.0.0/16"]}},
            {"name": "vpn", "match": {"cidr": ["10.0.0.0/8"]}},
            {"name": "eduroam", "match": {"cidr": ["172.16.0.0/12"]}},
        ]
        ingest_path = target_dir / "ingest.yaml"
        if not ingest_path.exists():
            pkg_ingest = Path(__file__).resolve().parents[2] / "packaging/etc/separ/ingest.yaml"
            if pkg_ingest.is_file():
                shutil.copy2(pkg_ingest, ingest_path)
                os.chmod(ingest_path, 0o644)
                print(f"✓ Created server sensor ingest config: {ingest_path}")
    else:
        print("✓ Configuring for: Workstation / Laptop Endpoint")
        policy_doc["identity"] = {
            "internal_mail_domains": ["tu-freiberg.de"],
            "approved_apps": ["Browser", "Terminal", "VSCode", "Git"],
        }
        policy_doc["destinations"] = [
            {
                "name": "local",
                "match": {"cidr": ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]},
            },
            {"name": "campus", "match": {"cidr": ["139.18.0.0/16"]}},
        ]

    pol_path = target_dir / POLICY_NAME
    write_public_key(pub, pub_path)
    write_signed_policy(policy_doc, priv, pol_path)
    print(f"✓ Signed policy written to: {pol_path} (0644)")
    print(f"✓ Public key written to   : {pub_path} (0644; the daemon verifies with it)")
    print(f"  Mode                  : {mode_arg.upper()}")
    print("  Campus CIDRs protected: 139.18.0.0/16, 10.0.0.0/8, 172.16.0.0/12")
    print("  Internal domains      : tu-freiberg.de")
    print("=" * 64)
    print(f"Keep {key_path} on the admin's machine, not on the endpoints: the daemon needs")
    print("only the public key. Later changes: separ policy set-mode MODE --key KEY; separ reload")
    print("Setup complete! You can now start Separ:")
    if is_root():
        print("  sudo systemctl enable --now separ.service")
    else:
        print("  separ gui")
    print("=" * 64)
    return 0
