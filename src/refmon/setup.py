"""Guided policy and environment configuration setup for Separ (servers and laptops)."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

from . import signing
from .live import default_live_workdir
from .policy import default_policy_dict
from .policy_io import write_signed


def run_setup(args: argparse.Namespace) -> int:
    """Setup and configure Separ policy and environment for servers or laptops."""
    is_server = getattr(args, "server", False)
    is_laptop = getattr(args, "laptop", False)
    workdir_arg = getattr(args, "workdir", None)
    mode_arg = getattr(args, "mode", None) or "observe"

    # Default to system if root, else user workdir
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not workdir_arg:
        target_dir = Path("/etc/separ")
        keys_dir = Path("/var/lib/separ")
    elif workdir_arg:
        target_dir = Path(workdir_arg)
        keys_dir = Path(workdir_arg)
    else:
        target_dir = Path.home() / ".config/separ"
        keys_dir = default_live_workdir()

    target_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    keyfile = keys_dir / "admin.key"

    print("=" * 64)
    print(" Separ Security Configuration & Policy Setup")
    print("=" * 64)

    # 1. Key generation
    if not keyfile.exists():
        priv, pub = signing.generate_keypair()
        keyfile.write_text(priv + "\n", encoding="utf-8")
        keyfile.chmod(0o600)
        (keys_dir / "admin.pub").write_text(pub + "\n", encoding="utf-8")
        print(f"✓ Generated administrative signing key: {keyfile}")
    else:
        priv = keyfile.read_text(encoding="utf-8").strip()
        pub = (
            (keys_dir / "admin.pub").read_text(encoding="utf-8").strip()
            if (keys_dir / "admin.pub").exists()
            else ""
        )
        print(f"✓ Existing signing key found: {keyfile}")

    # 2. Build Policy
    pol_path = target_dir / "policy.yaml"
    policy_doc = default_policy_dict()
    policy_doc["mode"] = mode_arg

    is_server_target = is_server or (hasattr(os, "geteuid") and os.geteuid() == 0 and not is_laptop)
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
        # Ingest config for servers
        ingest_path = target_dir / "ingest.yaml"
        if not ingest_path.exists():
            pkg_ingest = Path(__file__).resolve().parents[2] / "packaging/etc/separ/ingest.yaml"
            if pkg_ingest.is_file():
                shutil.copy2(pkg_ingest, ingest_path)
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

    # Sign the policy document
    write_signed(policy_doc, priv, pol_path)
    print(f"✓ Signed and verified policy written to: {pol_path}")
    print(f"  Mode                  : {mode_arg.upper()}")
    print("  Campus CIDRs protected: 139.18.0.0/16, 10.0.0.0/8, 172.16.0.0/12")
    print("  Internal domains      : tu-freiberg.de")
    print("=" * 64)
    print("Setup complete! You can now start Separ:")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("  sudo systemctl enable --now separ.service")
    else:
        print("  separ gui")
    print("=" * 64)
    return 0
