"""Guided policy setup for Separ (servers and laptops).

`separ setup` writes the signed policy and the public key exactly where the daemon reads them
(review 2026-11, item 1): /etc/separ/ for the system daemon (run as root), $XDG_CONFIG_HOME/separ/
for a per-user daemon, or `--config-dir`. The private key stays with the admin (`--key`, default
~/.separ-admin/admin.key): the daemon only ever gets the public key.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
from pathlib import Path

from .admin import ensure_admin_key, write_public_key, write_signed_policy
from .config import (
    POLICY_NAME,
    PUBLIC_KEY_NAME,
    SYSTEM_CONFIG_DIR,
    default_admin_key,
    is_root,
    secure_dir,
    user_config_dir,
)
from .policy import default_policy_dict


def _cidrs(values: list[str] | None, flag: str) -> list[str]:
    out = []
    for value in values or []:
        try:
            out.append(str(ipaddress.ip_network(value.strip(), strict=True)))
        except ValueError as exc:
            raise ValueError(f"{flag} {value!r} is not a network in CIDR form: {exc}") from None
    return out


def run_setup(args: argparse.Namespace) -> int:
    """Write and sign the policy for a server or a laptop."""
    is_server = getattr(args, "server", False)
    is_laptop = getattr(args, "laptop", False)
    config_arg = getattr(args, "config_dir", None)
    mode_arg = getattr(args, "mode", None) or "observe"
    key_path = Path(getattr(args, "key", None) or default_admin_key())

    # root writes the system policy; a user writes their own (never /etc/separ, even when it exists)
    target_dir = (
        Path(config_arg) if config_arg else (SYSTEM_CONFIG_DIR if is_root() else user_config_dir())
    )
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
    mail_domain = (getattr(args, "mail_domain", None) or "tu-freiberg.de").strip().lower()
    nets = {
        "campus": _cidrs(getattr(args, "campus_cidr", None), "--campus-cidr"),
        "vpn": _cidrs(getattr(args, "vpn_cidr", None), "--vpn-cidr"),
        "wlan": _cidrs(getattr(args, "wlan_cidr", None), "--wlan-cidr"),
    }

    is_server_target = is_server or (is_root() and not is_laptop)
    if is_server_target and not nets["campus"]:
        raise ValueError(
            "server mode needs the campus network: --campus-cidr CIDR (repeatable); "
            "Separ ships no campus network of its own"
        )
    # only what the admin named: no campus network is built in (review 2026-11, item 9)
    # internal: lateral movement is counted towards these networks. They come before the
    # reference classes, because the first class that matches an address names it.
    configured = [
        {"name": name, "internal": True, "match": {"cidr": cidrs}}
        for name, cidrs in nets.items()
        if cidrs
    ]
    if is_server_target:
        print("✓ Configuring for: Server Infrastructure (Campus / Enterprise)")
        policy_doc["identity"] = {
            "internal_mail_domains": [mail_domain],
            "approved_apps": ["Zoom", "Moodle", "Nextcloud", "OPAL"],
            "min_logins": 20,
            "failure_burst": 10,
            "burst_window": "5m",
        }
        policy_doc["destinations"] = [*configured, *policy_doc.get("destinations", [])]
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
            "internal_mail_domains": [mail_domain],
            "approved_apps": ["Browser", "Terminal", "VSCode", "Git"],
        }
        local = {
            "name": "local",
            "internal": True,
            "match": {"cidr": ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]},
        }
        policy_doc["destinations"] = [*configured, local, *policy_doc.get("destinations", [])]

    pol_path = target_dir / POLICY_NAME
    write_public_key(pub, pub_path)
    write_signed_policy(policy_doc, priv, pol_path)
    print(f"✓ Signed policy written to: {pol_path} (0644)")
    print(f"✓ Public key written to   : {pub_path} (0644; the daemon verifies with it)")
    print(f"  Mode                  : {mode_arg.upper()}")
    if not is_server_target:
        print("  Local networks        : 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8 (class local)")
    for name, cidrs in nets.items():
        if cidrs:
            print(f"  {name.capitalize() + ' networks':22}: {', '.join(cidrs)}")
    print(f"  Internal mail domain  : {mail_domain}")
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
