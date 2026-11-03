"""Per-account counted baselines for login and mail stories (v2.2, design decisions A74, A75).

Login logs describe accounts, not processes, so an account is the actor of its identity events
(role `identity_provider` or `mail_server`) and its own counted baseline. Every signal raised here
is one whose weight the owner already approved (no new weight, owner decision 2026-11-03):

- a successful login from a **network class the account never used**, once its baseline is mature,
  is `contract_surprisal`: an unseen kind under a mature baseline (C11.3), counted per account;
- a **burst of failed attempts** for one account (password guessing, MFA push fatigue) is
  `effect_credential`;
- a **mailbox rule that forwards outside** the organisation is `effect_exfil` and `effect_persist`;
- a **consent to an application not on the approved list** is `effect_persist`.

Maturity: at least `identity.min_logins` successful logins, and the Good-Turing estimate of an
unseen network (classes seen once / logins) under `math.baseline_maturity_unseen`. Before that the
signal is absent, not raised (missing information never generates evidence).

The baseline learns every successful login of an account. A network used while the account has an
open identity incident (a signal in the last `rates.long_window`) is parked and learned only after
the incident has been quiet that long, so an attacker's own logins do not teach it during the
incident, and a user who really moved is held once, not forever. An attacker who waits out the quiet
window is then learned too: a documented limit (A75).
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque

from ..policy import Policy
from ..schemas import Event, EventType


class IdentityTracker:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.networks: dict[str, Counter[str]] = defaultdict(Counter)
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.incident_until: dict[str, float] = {}
        # networks used while an incident was open: learned once it has been quiet (A75)
        self.pending: dict[str, set[str]] = defaultdict(set)

    def mature(self, account: str) -> bool:
        seen = self.networks.get(account)
        if not seen:
            return False
        total = sum(seen.values())
        if total < self.policy.identity.min_logins:
            return False
        once = sum(1 for n in seen.values() if n == 1)
        return once / total < self.policy.math.baseline_maturity_unseen

    def _flag(self, account: str, t: float) -> None:
        self.incident_until[account] = t + self.policy.rates.long_window

    def in_incident(self, account: str, t: float) -> bool:
        return self.incident_until.get(account, float("-inf")) > t

    def signals(self, ev: Event, t: float) -> list[str]:
        """The signal names one identity event raises, and the baseline update it makes."""
        account = ev.actor.user
        attrs = ev.attrs
        out: list[str] = []
        if ev.type is EventType.AUTH:
            if attrs.get("auth_result") == "failure":
                window = self.failures[account]
                window.append(t)
                horizon = t - self.policy.identity.burst_window
                while window and window[0] < horizon:
                    window.popleft()
                if len(window) >= self.policy.identity.failure_burst:
                    out.append("effect_credential")
            elif attrs.get("auth_result") == "success":
                net = str(attrs.get("network_class", "unknown"))
                quiet = not self.in_incident(account, t)
                if quiet and self.pending.get(account):
                    for old in self.pending.pop(account):
                        self.networks[account][old] += 1
                if net != "unknown" and self.mature(account) and net not in self.networks[account]:
                    out.append("contract_surprisal")
                if net != "unknown":
                    if out or not quiet:
                        self.pending[account].add(net)
                    else:
                        self.networks[account][net] += 1
        elif ev.type is EventType.MAIL_RULE:
            if attrs.get("forward_external") is True:
                out += ["effect_exfil", "effect_persist"]
        elif ev.type is EventType.OAUTH_GRANT and attrs.get("app_approved") is False:
            out.append("effect_persist")
        if out:
            self._flag(account, t)
        return out
