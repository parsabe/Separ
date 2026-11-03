"""Plant realistic decoy files (honeytokens) and propose them as canaries (v2.1, A69).

    refmon decoy plant --config decoys.yaml --out proposal.json

Each decoy looks like what an attacker hunts for on a real server: an application `.env` with a
database password, cloud access keys, a kubeconfig for a production cluster, a `.pgpass`, a
"password vault" spreadsheet, and a board summary whose image is loaded from a beacon address (a
decoy listener of your own, never an outside service). Every secret is random and valid nowhere.

Realism, because an experienced attacker distrusts a system that looks too clean:
- file times are scattered over months (`age_months`) and never share a timestamp;
- `refmon decoy refresh` touches a few now and then so they look like living documents;
- nothing in the decoy directory says "Refmon" or "decoy": the list of what was planted lives in
  the proposal file the admin keeps, not next to the decoys.

Planting changes no policy. It writes a proposal: the canaries a human approves and signs into the
policy (`refmon decoy approve-canaries`), like every other policy change.
"""

from __future__ import annotations

import json
import os
import random
import secrets
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

KINDS = ("env", "cloud_keys", "kubeconfig", "pgpass", "password_vault", "beacon_doc")
_ALNUM = string.ascii_letters + string.digits


class PlantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dir: Path
    files: list[str] = Field(default_factory=lambda: list(KINDS))
    age_months: int = Field(default=18, ge=1, le=120)
    # base address of a decoy HTTP listener of your own (for beacon_doc), e.g.
    # http://files.example.internal:8088 ; without it no beacon document is planted
    beacon_url: str | None = None
    ignore_roles: list[str] = Field(default_factory=lambda: ["backup_job"])
    org_domain: str = "example.internal"  # makes host names in the decoys look local
    names: dict[str, str] = Field(default_factory=dict)  # kind -> file name override


DEFAULT_NAMES = {
    "env": "app/.env",
    "cloud_keys": ".aws/credentials",
    "kubeconfig": "deploy/kubeconfig-prod.yaml",
    "pgpass": ".pgpass",
    "password_vault": "Finance/CEO_Password_Vault.csv",
    "beacon_doc": "Board/Q3-Board-Summary.html",
}


@dataclass
class Planted:
    files: list[str] = field(default_factory=list)
    canaries: list[dict[str, Any]] = field(default_factory=list)

    def proposal(self, created: datetime) -> dict[str, Any]:
        return {
            "kind": "decoy-canaries",
            "created": created.isoformat(timespec="seconds"),
            "status": "proposed",
            "files": self.files,
            "canaries": self.canaries,
        }


def _secret(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _password() -> str:
    # looks like what people choose for service accounts: a word, digits, a sign
    words = ("Winter", "Sommer", "Freiberg", "Backup", "Admin", "Server", "Projekt", "Bergbau")
    return f"{secrets.choice(words)}{secrets.randbelow(9000) + 1000}{secrets.choice('!#$%&*')}"


def _content(kind: str, cfg: PlantConfig, token: str) -> tuple[str, list[tuple[str, str]]]:
    """The file text and the canary values in it: (class, value) pairs."""
    d = cfg.org_domain
    if kind == "env":
        pw = _password()
        text = (
            "APP_ENV=production\nAPP_DEBUG=false\n"
            f"DB_HOST=db-prod.{d}\nDB_PORT=5432\nDB_DATABASE=erp\nDB_USERNAME=erp_app\n"
            f"DB_PASSWORD={pw}\nMAIL_HOST=smtp.{d}\nSESSION_LIFETIME=120\n"
        )
        return text, [("credential", pw)]
    if kind == "cloud_keys":
        key_id = "AKIA" + _secret(16, string.ascii_uppercase + string.digits)
        secret_key = _secret(40, _ALNUM + "/+")
        text = (
            f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret_key}\n"
            "region = eu-central-1\n"
        )
        return text, [("credential", secret_key)]
    if kind == "kubeconfig":
        tok = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ij" + _secret(120)
        text = (
            "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n"
            f"    server: {'https'}://k8s-prod.{d}:6443\n  name: prod\ncontexts:\n"
            "- context:\n    cluster: prod\n    user: ci-deployer\n  name: prod\n"
            "current-context: prod\nusers:\n- name: ci-deployer\n  user:\n"
            f"    token: {tok}\n"
        )
        return text, [("credential", tok)]
    if kind == "pgpass":
        pw = _password()
        return f"db-prod.{d}:5432:*:postgres_admin:{pw}\n", [("credential", pw)]
    if kind == "password_vault":
        rows = ["Service,User,Password,Notes"]
        values = []
        for service, user in (("VPN", "ceo"), ("Banking", "ceo.office"), ("ERP", "admin"),
                              ("Mail", "ceo"), ("Payroll", "hr-lead")):  # fmt: skip
            pw = _password()
            values.append(("credential", pw))
            rows.append(f"{service},{user},{pw},")
        return "\n".join(rows) + "\n", values[:1]
    if kind == "beacon_doc":
        path = f"/assets/img/{token}.png"
        base = (cfg.beacon_url or "").rstrip("/")
        text = (
            '<!doctype html>\n<html lang="de"><head><meta charset="utf-8">'
            "<title>Q3 Board Summary (confidential)</title></head><body>\n"
            "<h1>Q3 Board Summary</h1>\n<p>Confidential. Do not forward.</p>\n"
            f'<img src="{base}{path}" width="1" height="1" alt="">\n'
            "<p>Revenue, risks and the restructuring plan are in the attached sheets.</p>\n"
            "</body></html>\n"
        )
        return text, [("beacon", path)]
    raise ValueError(f"unknown decoy kind {kind!r}")


def _aged_times(rng: random.Random, n: int, now: datetime, months: int) -> list[float]:
    """n distinct times scattered over the last `months` months, none in the last day."""
    span = int(timedelta(days=30 * months).total_seconds())
    seen: set[int] = set()
    out = []
    while len(out) < n:
        back = rng.randrange(86400, span)
        if back in seen:
            continue
        seen.add(back)
        out.append((now - timedelta(seconds=back)).timestamp())
    return out


def plant(
    cfg: PlantConfig, *, now: datetime | None = None, rng: random.Random | None = None
) -> Planted:
    now = now or datetime.now(UTC)
    rng = rng or random.Random(secrets.randbits(64))
    unknown = [k for k in cfg.files if k not in KINDS]
    if unknown:
        raise ValueError(f"unknown decoy kinds: {unknown}")
    kinds = [k for k in cfg.files if k != "beacon_doc" or cfg.beacon_url]
    root = cfg.dir.resolve()
    result = Planted()
    times = _aged_times(rng, len(kinds) * 2, now, cfg.age_months)
    for i, kind in enumerate(kinds):
        rel = cfg.names.get(kind, DEFAULT_NAMES[kind])
        path = (root / rel).resolve()
        if root not in path.parents:
            raise ValueError(f"decoy path {rel!r} leaves the decoy directory")
        if path.exists():
            raise FileExistsError(f"{path} exists: refusing to overwrite a real file")
        path.parent.mkdir(parents=True, exist_ok=True)
        text, values = _content(kind, cfg, _secret(12, string.ascii_lowercase + string.digits))
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if kind == "pgpass" else 0o644
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        modified, accessed = sorted(times[2 * i : 2 * i + 2])  # last read after last change
        os.utime(path, (accessed, modified))
        result.files.append(str(path))
        name = f"decoy-{kind.replace('_', '-')}"
        result.canaries.append(
            {"name": f"{name}-file", "class": "file", "value": str(path),
             "ignore_roles": list(cfg.ignore_roles)}
        )  # fmt: skip
        for j, (cls, value) in enumerate(values):
            result.canaries.append({"name": f"{name}-{cls}-{j + 1}", "class": cls, "value": value})
    return result


def refresh(files: list[str], *, now: datetime | None = None, rng: random.Random | None = None,
            count: int = 2) -> list[str]:  # fmt: skip
    """Touch up to `count` decoys to a recent working-hours time, without opening them (so the
    decoy watcher sees no access)."""
    now = now or datetime.now(UTC)
    rng = rng or random.Random(secrets.randbits(64))
    alive = [f for f in files if Path(f).is_file()]
    chosen = rng.sample(alive, min(count, len(alive)))
    for f in chosen:
        day = now - timedelta(days=rng.randrange(0, 6))
        stamp = day.replace(
            hour=rng.randrange(8, 18), minute=rng.randrange(60), second=rng.randrange(60)
        )
        stamp = min(stamp, now - timedelta(minutes=5))
        os.utime(f, (stamp.timestamp(), stamp.timestamp()))
    return chosen


def write_proposal(planted: Planted, out: Path, *, now: datetime | None = None) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # it holds the decoy secrets
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(planted.proposal(now or datetime.now(UTC)), fh, indent=2)


def apply_canaries(policy_document: dict, proposal: dict, by: str) -> dict:
    """The policy document with the proposal's canaries added (an existing name is replaced) and
    the decoy listener role known. The caller signs it; `by` names the approver."""
    if not by.strip():
        raise ValueError("an approval names the approver")
    if proposal.get("kind") != "decoy-canaries":
        raise ValueError("not a decoy canary proposal")
    doc = json.loads(json.dumps(policy_document))
    new = {c["name"]: c for c in proposal["canaries"]}
    doc["canaries"] = [c for c in doc.get("canaries", []) if c.get("name") not in new]
    doc["canaries"] += list(new.values())
    roles = doc.setdefault("extra_roles", [])
    if "decoy_service" not in roles:
        roles.append("decoy_service")
    return doc
