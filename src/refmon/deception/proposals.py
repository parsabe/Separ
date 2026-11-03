"""Block-list proposals for the sources of decoy hits (v2.1, design decision A71).

Whoever connects to a decoy listener or fetches a decoy beacon has no legitimate reason to: the
source address is worth blocking. Blocking is a policy change, and nothing changes the policy
without a person approving it, so this module only *proposes*. It is the sink Observe hands the raw
source address to (`Observe.decoy_sink`), and it is the one named exception to "no raw value after
Observe" (CLAUDE.md Part A):

- an **external** address (outside the internal ranges) is kept raw, because an admin needs it to
  block it, in a file only the daemon's user can read (0600), and only until it expires (7 days
  after the last hit, by default) or is approved;
- an **internal** address may be a colleague's computer (curious, or itself compromised). It is
  personal data, so it is kept only as a pseudonym plus the value sealed under the vault key; seeing
  it needs the four-eyes re-identification of `pseudonym.Vault` (two approvers, logged).

Approving an external entry adds it to the `decoy-sources` threat list of the policy document,
which the admin then signs; nothing here signs or applies anything on its own.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..policy import Policy
from ..pseudonym import Pseudonymizer, Vault

THREAT_LIST = "decoy-sources"
DEFAULT_TTL = timedelta(days=7)


@dataclass
class SourceProposal:
    id: str
    canary: str
    first_seen: str
    last_seen: str
    expires: str
    hits: int
    internal: bool
    address: str | None = None  # external only
    pseudonym: str | None = None  # internal only
    sealed: str | None = None  # internal only: the address encrypted under the vault key
    status: str = "pending"  # pending | approved
    approved_by: str | None = None


def internal_networks(policy: Policy) -> list[ipaddress._BaseNetwork]:
    nets = []
    for dest in policy.destinations:
        if dest.internal:
            for cidr in dest.match.get("cidr", []):
                with contextlib.suppress(ValueError):
                    nets.append(ipaddress.ip_network(cidr, strict=False))
    return nets


# Ranges that are someone's own network wherever Refmon runs: RFC 1918, carrier-grade NAT,
# loopback, link-local and IPv6 unique-local. (`ipaddress.is_private` is not used: it also covers
# the documentation ranges, which are neither.)
LOCAL_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
              "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")
)  # fmt: skip


def is_internal(address: ipaddress._BaseAddress, nets: list) -> bool:
    return any(address.version == n.version and address in n for n in (*LOCAL_RANGES, *nets))


class SourceProposals:
    """The pending-proposal file `<workdir>/proposals/decoy-sources.json`."""

    def __init__(
        self,
        path: Path,
        policy: Policy,
        pseudonymizer: Pseudonymizer,
        vault: Vault,
        *,
        ttl: timedelta = DEFAULT_TTL,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.nets = internal_networks(policy)
        self.pseudonymizer, self.vault, self.ttl = pseudonymizer, vault, ttl
        self.clock = clock or (lambda: datetime.now(UTC))

    # -- storage -------------------------------------------------------------------------------

    def _load(self) -> list[SourceProposal]:
        try:
            rows = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [SourceProposal(**r) for r in rows]

    def _save(self, entries: list[SourceProposal]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".decoy-sources-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump([asdict(e) for e in entries], fh, indent=2)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def entries(self) -> list[SourceProposal]:
        """Every proposal that has not expired; expired ones are deleted from the file."""
        now = self.clock()
        kept = [
            e for e in self._load()
            if e.status == "approved" or datetime.fromisoformat(e.expires) > now
        ]  # fmt: skip
        if len(kept) != len(self._load()):
            self._save(kept)
        return kept

    # -- the sink ------------------------------------------------------------------------------

    def record(self, canary: str, raw_address: str, ts: datetime) -> SourceProposal | None:
        """Observe calls this with the raw source address of a decoy hit."""
        try:
            address = ipaddress.ip_address(raw_address.strip().strip("[]"))
        except ValueError:
            return None  # not an address: nothing to propose
        internal = is_internal(address, self.nets)
        value = str(address)
        key = self.pseudonymizer.pseudonym("ip", value) if internal else value
        entries = self.entries()
        when = ts.astimezone(UTC).isoformat(timespec="seconds")
        expires = (ts + self.ttl).astimezone(UTC).isoformat(timespec="seconds")
        for e in entries:
            if (e.pseudonym if e.internal else e.address) == key:
                e.hits += 1
                e.last_seen = when
                if e.status == "pending":
                    e.expires = expires
                self._save(entries)
                return e
        entry = SourceProposal(
            id=f"DS-{len(entries) + 1:04d}-{os.urandom(3).hex()}",
            canary=canary, first_seen=when, last_seen=when, expires=expires, hits=1,
            internal=internal,
            address=None if internal else value,
            pseudonym=key if internal else None,
            sealed=self.vault.seal(value).decode() if internal else None,
        )  # fmt: skip
        entries.append(entry)
        self._save(entries)
        return entry

    __call__ = record

    # -- the human steps -----------------------------------------------------------------------

    def approve(self, entry_id: str, by: str, policy_document: dict) -> dict:
        """Approve an external proposal: return the policy document with the address added to the
        `decoy-sources` host list. The caller signs and writes it (refmon decoy approve)."""
        if not by.strip():
            raise ValueError("an approval names the approver")
        entries = self.entries()
        entry = next((e for e in entries if e.id == entry_id), None)
        if entry is None:
            raise KeyError(f"no pending proposal {entry_id}")
        if entry.internal:
            raise PermissionError(
                "an internal address is personal data: re-identify it with four-eyes approval "
                "(pseudonym.Vault) before it can be blocked"
            )
        doc = json.loads(json.dumps(policy_document))  # a deep copy
        lists = doc.setdefault("threat_lists", [])
        spec = next((s for s in lists if s.get("name") == THREAT_LIST), None)
        if spec is None:
            spec = {"name": THREAT_LIST, "kind": "host", "entries": []}
            lists.append(spec)
        if entry.address not in spec["entries"]:
            spec["entries"].append(entry.address)
        entry.status, entry.approved_by = "approved", by
        self._save(entries)
        return doc

    def adopt_internal(self) -> None:
        """Hand the sealed internal addresses to the vault, so a four-eyes request can open one."""
        for e in self.entries():
            if e.internal and e.pseudonym and e.sealed:
                self.vault.adopt(e.pseudonym, e.sealed.encode())
