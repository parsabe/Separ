"""`refmon decoy ...`: the human steps of the deception layer (v2.1).

    refmon decoy plant --config decoys.yaml            plant decoys, write the canary proposal
    refmon decoy approve-canaries --config decoys.yaml --by NAME
                                                       sign the proposal's canaries into the policy
    refmon decoy refresh --config decoys.yaml          make a few decoys look recently used
    refmon decoy sources [--json]                      list proposed decoy-hit sources
    refmon decoy approve-source ID --by NAME [--firewall-command 'nft add element ... {ip}']
                                                       add an outside source to the block list

Every policy change here is signed with the admin's private key (`--key`, default
~/.separ-admin/admin.key; never the daemon's work directory) only after the current policy verified
with its public key, so a tampered policy file is never re-signed. A running daemon adopts the
signed change itself (or at once with `separ reload`).
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .. import signing
from ..policy_io import load_policy_data, read_document
from ..pseudonym import AuditLog, Pseudonymizer, Vault
from .plant import apply_canaries, plant, refresh, write_proposal
from .proposals import SourceProposals
from .runtime import add_service_canaries, load_settings


def add_parser(sub) -> None:
    dec = sub.add_parser("decoy", help="deception: decoy files, decoy services, block proposals")
    dsub = dec.add_subparsers(dest="decoy_command", required=True)

    def common(p, config=True, signs=False):
        p.add_argument("--workdir", default=None, help="the daemon's work directory")
        p.add_argument("--policy", default=None, help="the signed policy (default: config dir)")
        p.add_argument("--public-key", default=None, help="default: next to the policy")
        if signs:
            p.add_argument("--key", default=None, help="admin key (~/.separ-admin/admin.key)")
        if config:
            p.add_argument("--config", required=True, help="decoys.yaml")

    common(dsub.add_parser("plant"))
    common(dsub.add_parser("refresh"))
    p = dsub.add_parser("approve-canaries")
    common(p, signs=True)
    p.add_argument("--by", required=True)
    p = dsub.add_parser("sources")
    common(p, config=False)
    p.add_argument("--json", action="store_true", dest="as_json")
    p = dsub.add_parser("approve-source")
    common(p, config=False, signs=True)
    p.add_argument("proposal_id")
    p.add_argument("--by", required=True)
    p.add_argument(
        "--firewall-command",
        default=None,
        help="run after approval; {ip} is replaced by the address (no shell)",
    )


def _workdir(args) -> Path:
    from ..live import default_live_workdir

    return Path(args.workdir) if args.workdir else default_live_workdir()


def _paths(args) -> tuple[Path, Path]:
    from ..config import resolve_policy_paths

    return resolve_policy_paths(getattr(args, "policy", None), getattr(args, "public_key", None))


def _verified_document(args) -> dict:
    """The policy document, after its signature verified with the admin's public key."""
    policy, public = _paths(args)
    load_policy_data(policy, [public.read_text(encoding="utf-8").strip()])  # PolicyRejected
    doc = read_document(policy)
    return {k: v for k, v in doc.items() if k != signing.SIGNATURE_FIELD}


def _sign(args, doc: dict) -> None:
    from ..admin import read_private_key, write_signed_policy

    policy, public = _paths(args)
    private = read_private_key(getattr(args, "key", None))
    if signing.public_key_of(private) != public.read_text(encoding="utf-8").strip():
        raise PermissionError("the private key does not belong to the policy's public key")
    write_signed_policy(doc, private, policy)


def _sources(workdir: Path, args) -> SourceProposals:
    policy, public = _paths(args)
    loaded = load_policy_data(policy, [public.read_text(encoding="utf-8").strip()])
    pseud = Pseudonymizer(bytes.fromhex((workdir / "pseudonym.key").read_text().strip()))
    key_file = workdir / "decoy-vault.key"
    key = key_file.read_text().strip().encode() if key_file.exists() else None
    vault = Vault({}, max(2, loaded.policy.reporting.reidentify_requires), AuditLog(), key=key)
    return SourceProposals(
        workdir / "proposals" / "decoy-sources.json", loaded.policy, pseud, vault
    )


def run(args: argparse.Namespace) -> int:
    workdir = _workdir(args)
    cmd = args.decoy_command
    if cmd == "plant":
        settings = load_settings(args.config)
        if settings.plant is None:
            raise ValueError("decoys.yaml has no `plant` section")
        planted = add_service_canaries(plant(settings.plant), settings.listen)
        out = settings.proposal_path(workdir)
        write_proposal(planted, out)
        for f in planted.files:
            print(f"planted {f}")
        print(f"proposal with {len(planted.canaries)} canaries: {out} (owner-only; it holds the "
              "decoy secrets)")  # fmt: skip
        print("next: refmon decoy approve-canaries --config ... --by YOUR-NAME")
    elif cmd == "refresh":
        settings = load_settings(args.config)
        proposal = json.loads(settings.proposal_path(workdir).read_text(encoding="utf-8"))
        for f in refresh(proposal.get("files", [])):
            print(f"refreshed {f}")
    elif cmd == "approve-canaries":
        settings = load_settings(args.config)
        path = settings.proposal_path(workdir)
        proposal = json.loads(path.read_text(encoding="utf-8"))
        doc = apply_canaries(_verified_document(args), proposal, args.by)
        _sign(args, doc)
        proposal.update(status="approved", approved_by=args.by,
                        approved=datetime.now(UTC).isoformat(timespec="seconds"))  # fmt: skip
        path.write_text(json.dumps(proposal, indent=2), encoding="utf-8")
        print(
            f"{len(proposal['canaries'])} canaries signed into {_paths(args)[0]} "
            f"(approved by {args.by}); a running daemon adopts it within a heartbeat "
            "(or at once: separ reload)"
        )
    elif cmd == "sources":
        entries = _sources(workdir, args).entries()
        if args.as_json:
            rows = [{k: v for k, v in e.__dict__.items() if k != "sealed"} for e in entries]
            print(json.dumps(rows, indent=2))
        for e in [] if args.as_json else entries:
            who = e.pseudonym + " (internal: four-eyes needed)" if e.internal else e.address
            print(f"{e.id}  {e.status:8}  hits={e.hits:<4} last={e.last_seen}  {e.canary}  {who}")
        if not entries and not args.as_json:
            print("no proposals")
    elif cmd == "approve-source":
        store = _sources(workdir, args)
        entry = next((e for e in store.entries() if e.id == args.proposal_id), None)
        doc = store.approve(args.proposal_id, args.by, _verified_document(args))
        _sign(args, doc)
        print(f"{args.proposal_id}: {entry.address} added to the decoy-sources block list "
              f"(approved by {args.by})")  # fmt: skip
        if args.firewall_command:
            argv = [w.replace("{ip}", entry.address) for w in shlex.split(args.firewall_command)]
            done = subprocess.run(argv, check=False, timeout=30)
            print(f"firewall command exited {done.returncode}")
            return 0 if done.returncode == 0 else 1
    return 0
