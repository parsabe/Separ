"""Attack family names for notifications and pop-ups (v2.1, design decision A68).

A user who sees "Refmon blocked this" wants to know *what kind* of attack it was. This module names
the family of a judged story from the same facts the verdict already carries: the names of its
signals, its override, the source classes of its labels and the roles of its processes. The names
are those of the coverage map (CLAUDE.md C13).

The family is a label for people, never evidence: it is computed after the decision, from fixed
tables, and nothing in Judge, Gate or Contain reads it. The rules are ordered; the first that
matches names the family, so a story with a decoy hit is named after the decoy, not after what the
attacker did next.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .schemas import Verdict

SERVER_ROLES = frozenset({"web_worker", "app_server", "node_app_server", "db_server"})
SERVER_EXEC = frozenset(
    {"contract_web_worker_exec", "contract_exec_violation", "contract_external_exec"}
)


@dataclass(frozen=True)
class Family:
    id: str
    name: str
    advice: str  # one sentence for the person who saw the pop-up

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "advice": self.advice}


NONE = Family("none", "No attack recognised", "Nothing to do.")
SUSPICIOUS = Family(
    "suspicious",
    "Suspicious behaviour",
    "If you did not expect this, tell the IT service desk.",
)

FAMILIES: dict[str, Family] = {
    f.id: f
    for f in (
        Family("self_tamper", "Attack on Refmon itself",
               "Someone tried to switch off the protection. Tell the IT service desk now."),
        Family("decoy", "Decoy touched (honeytoken)",
               "A trap that no real work ever touches was used. Tell the IT service desk now."),
        Family("credential_theft", "Credential theft (infostealer)",
               "Change the passwords that are stored on this computer and tell the service desk."),
        Family("known_bad", "Contact with a known bad host",
               "Do not retry. Tell the IT service desk which page you were on."),
        Family("web_shell", "Web shell planted on a server",
               "The server administrator should check the web root."),
        Family("server_rce", "Remote code execution on a server",
               "The server administrator should check the exposed service and patch it."),
        Family("ransomware", "Ransomware-like mass file change",
               "Do not reconnect drives. Tell the IT service desk now."),
        Family("defense_evasion", "Defense evasion (security tools or logs)",
               "Tell the IT service desk now."),
        Family("lateral", "Lateral movement inside the network",
               "Tell the IT service desk now."),
        Family("escalation", "Privilege escalation",
               "Tell the IT service desk now."),
        Family("server_callback", "Compromised server calling out",
               "The server administrator should check what the service connected to."),
        Family("memory_leak", "Memory-leak stage (oversized replies)",
               "The server administrator should check the service for a known leak."),
        Family("prompt_injection", "Prompt injection into an AI assistant",
               "Do not let the assistant run commands taken from that page."),
        Family("malicious_attachment", "Malicious attachment or macro document",
               "Delete the email and tell the IT service desk."),
        Family("removable_media", "Attack from a USB stick or removable medium",
               "Remove the medium and give it to the IT service desk."),
        Family("supply_chain", "Poisoned software package (supply chain)",
               "Do not install the package again. Tell the IT service desk its name."),
        Family("fake_installer", "Fake installer or drive-by download",
               "Delete the downloaded file. Get software only from the university portal."),
        Family("clickfix", "ClickFix-style command from a web page",
               "No real website asks you to paste commands. Close the page."),
        Family("data_theft", "Data theft (unusual outbound volume)",
               "Tell the IT service desk now."),
    )
}  # fmt: skip


def _effect(names: set[str], *effects: str) -> bool:
    return any(f"effect_{e}" in names for e in effects)


def classify(
    signals: Iterable[str],
    *,
    override: str | None = None,
    sources: Iterable[str] = (),
    roles: Iterable[str] = (),
) -> Family:
    """The family of one judged story. `signals` are signal names (`contract_*`, `effect_*`)."""
    names, src, rls = set(signals), set(sources), set(roles)
    ovr = str(override) if override is not None else None
    if ovr == "self_tamper":
        return FAMILIES["self_tamper"]
    if ovr == "canary":
        return FAMILIES["decoy"]
    if ovr == "protected_asset" or _effect(names, "credential"):
        return FAMILIES["credential_theft"]
    if _effect(names, "threat_list_hit"):
        return FAMILIES["known_bad"]
    server = bool(rls & SERVER_ROLES)
    if server and "contract_write_executable" in names:
        return FAMILIES["web_shell"]
    if server and names & SERVER_EXEC:
        return FAMILIES["server_rce"]
    if server and "contract_connect_violation" in names:
        return FAMILIES["server_callback"]
    if _effect(names, "mass_change"):
        return FAMILIES["ransomware"]
    if _effect(names, "tamper"):
        return FAMILIES["defense_evasion"]
    if _effect(names, "lateral"):
        return FAMILIES["lateral"]
    if _effect(names, "escalate"):
        return FAMILIES["escalation"]
    if _effect(names, "response_anomaly", "response_anomaly_repeated"):
        return FAMILIES["memory_leak"]
    if "agent_input" in src:
        return FAMILIES["prompt_injection"]
    if "mail" in src and ("office" in rls or "script_host" in rls):
        return FAMILIES["malicious_attachment"]
    if "removable" in src:
        return FAMILIES["removable_media"]
    if "package" in src:
        return FAMILIES["supply_chain"]
    pasted = "contract_external_exec" in names and "contract_unsigned_launch" not in names
    if pasted and src & {"web", "mail", "download"}:
        return FAMILIES["clickfix"]  # command text copied from a page, a mail or a document
    if "contract_unsigned_launch" in names or "download" in src:
        return FAMILIES["fake_installer"]
    if _effect(names, "exfil"):
        return FAMILIES["data_theft"]
    return SUSPICIOUS if names or ovr else NONE


def classify_verdict(
    verdict: Verdict, *, sources: Iterable[str] = (), roles: Iterable[str] = ()
) -> Family:
    names = list(verdict.contract.reasons) + list(verdict.effect.reasons)
    names += [f"effect_{e}" for e in verdict.effects]
    override = verdict.override.value if verdict.override is not None else None
    return classify(names, override=override, sources=sources, roles=roles)


def classify_judgement(
    judgement, *, sources: Iterable[str] = (), roles: Iterable[str] = ()
) -> Family:
    """The family of a Judge result (pipeline.judge.Judgement), before any verdict is built."""
    override = judgement.override.value if judgement.override is not None else None
    names = [s.name for s in judgement.signals]
    return classify(names, override=override, sources=sources, roles=roles)
