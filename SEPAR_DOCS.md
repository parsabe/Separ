# Separ — rewrite the paper and the TUBAF IT security guide (LaTeX)

Work on a new branch `docs/paper-and-it-guide`, created from `fix/review-2026-11` (v2.4). Follow CLAUDE.md.
Small commits. Nothing pushed. Do not change any code under `src/` except a new script for the paper's
numbers (below). If a fact you need is not in the repository, write `\todo{...}` in the LaTeX and list it in
your final report — never invent a number, a citation, a command or a flag.

## 0. Facts first (both documents use them)

1. Run and save to `docs/it-facts.md`: the exact output of `separ --version`, `separ setup --help`,
   `separ policy --help`, `separ policy set-mode --help`, `separ reload --help`, `separ serve --help`,
   `separ health --help`, `separ scan-rootkit --help`, `separ browser-install --help`, `separ ingest --help`.
2. In the same file: every field in `logs/events.jsonl`, `verdicts.jsonl`, `notifications.jsonl`,
   `barrier.log`, heartbeat and notification payloads that can identify a person or a machine (user names,
   host names, IP addresses, pseudonyms, device ids), each with one example line from a lab run and whether
   it is raw, keyed-hashed or pseudonymized; and whether the rootkit scan or the dashboard shows other users'
   processes or names. Where a raw identifier is stored that the privacy claims do not cover, say so plainly.
3. Add `scripts/paper_numbers.py`: reads `docs/evaluation/*.jsonl`, the golden results, the Attack Lab
   reference run (including the honest benign controls) and the audit output, and writes
   `documentation/numbers.tex` with one `\newcommand` per number (counts, percentages, Wilson 95 % intervals,
   seed, version). Every number in the paper comes from this file. Add a test that the script runs and that
   its numbers match `docs/v2.4-evaluation.md`.

## 1. The paper (`documentation/main.tex`, `references.bib`, figures)

Rewrite it as an honest research paper about **v2.4**, about 8 pages plus appendix, built so that a later
v2.5 / pilot update only means re-running `paper_numbers.py` and the figure scripts.

**Framing**
- Title and abstract describe what it is: a host-based, pre-execution command mediation layer and behavioural
  monitor for Linux (not "against network attacks"). Drop GUI, audio chimes and package sizes from the
  abstract; one short implementation paragraph is enough.
- Add an explicit threat model: attacker capabilities; what Separ mediates (commands sent through `guard`,
  browser clipboard/download/navigation observations, the watched sandbox, ingested sensor streams); what it
  does not (anything not routed to it, e.g. a terminal paste without the extension, scripts run by name;
  a root attacker; a same-user attacker can stop a per-user daemon). Do not call it a complete reference
  monitor; complete mediation (eBPF LSM / fanotify) is future work.
- Restore a **Discussion and Limitations** section (the pre-Nov-17 version had one; reuse what is still true).

**Method (match the code exactly)**
- Provenance decay: on a Contract violation a label is frozen at its *current* strength, not reset to s₀.
- Noisy-OR is used for provenance fusion; the Judge takes the max within a question and sums across questions.
  Say what that assumes (conditional independence across questions; correlated signals within one) and that it
  is a scoring heuristic, not exact Bayesian inference. Note that a fresh label of strength 1 saturates Noisy-OR.
- Weights: expert-elicited, as `docs/weights-proposal.md` says (state which rates were "spec"); structural rules
  added after catalog checks (D19, D20) — so the golden catalog is not an independent test set.
- Thresholds: describe the current per-action thresholds as derived against ALLOW only; give the hold threshold
  correctly in log-odds (logit, not ln of a probability); do not call them Bayes-optimal. Mention the
  three-action expected-cost rule (A82) as implemented but switched off pending evaluation.
- Overrides bypass the thresholds (write the gate equation to match `evidence.py: decide`).
- Observe features: state the limits of character entropy (bounded by log₂ N and by the alphabet) and that
  the encoding ratio is high for ordinary text.
- Rootkit scanner: describe it as implemented in v2.4 (readdir vs. direct lookup, full PID sweep, module
  check in both directions plus `/proc/kallsyms`, calibrated transient rate, two passes), and its limits.
- Privacy: keyed HMAC with a per-device key; the audit's dictionary attack under guessable keys plus a control
  run with the real key; the real threat (an attacker with the device key can dictionary-attack low-entropy
  commands); what identifiers are stored (from step 0).
- Containment: real only with `serve --enforce` as root; otherwise simulated, and say so.

**Evaluation (all from numbers.tex)**
- Seed discipline: seeds drawn and recorded before code, retired after use — describe it, it is a strength.
- The current version (v2.4) on its seed: malicious contained, blocked, held, missed; benign **neutral** and
  benign **with an added violation**, each as allow/hold/block, with Wilson intervals. The totals must add up.
- Golden catalog result, with the caveat above.
- Attack Lab: attacks detected out of **all** attack templates *including* the known-limit hidden script
  (28/29, not 28/28); the honest benign controls as a table (10 pasted from the web, 8 typed, with decisions
  and log-odds); state plainly that pasted commands that visibly fetch, escalate or pipe into a shell are
  blocked, including legitimate install instructions, and why trusted destinations do not change that.
- Ablation and latency as now, worded as findings (the single-signal ablation shows fragility, not proof).
- **Delete Figure 3(a) and `documentation/make_comparative_fig.py`.** No baseline numbers that were not
  measured. Comparison with related work becomes one *qualitative* capability table, clearly labelled as such.
  If you can run Falco's default rules on the Attack Lab commands here, add that as a measured baseline;
  otherwise leave a `\todo` and say it in the report.
- Every figure regenerated from data by a script; no hard-coded values in plotting code.

**Related work**
Add: information-flow control and taint tracking; Mark-of-the-Web; CamFlow; ProvDetector; Kairos; Flash;
NODLINK; CaMeL; FIDES; Tracee; BPF-LSM/KRSI. Only add a `references.bib` entry when you are sure of authors,
title, venue and year; otherwise add it with `note = {TODO verify}` and list it in the report.
Remove citations the text no longer uses (e.g. Wald if no sequential test is described).

**Future work**: complete mediation (eBPF LSM / fanotify), A82/A83, F15–F17, a real pilot measuring how often
real pastes would be held or blocked, TPM-backed keys.

Build with `latexmk -pdf`, zero undefined references or citations, regenerate the Overleaf zip. Then re-include
`documentation/` in ruff and in `check_publishable.py` (remove the temporary skip) and make both pass.

## 2. The TUBAF IT security guide (`it-service-desk/guide.tex`, plus `guide-de.tex`)

Audience: the IT security officer, URZ administrators and the data protection officer at TU Bergakademie
Freiberg. Rewrite `guide.tex` (English) and add `guide-de.tex` (the same content in German, formal "Sie").
Every command and flag must appear in `docs/it-facts.md`. Contact: `parsa@parsabe.com`. No real TUBAF network
ranges, names or e-mail addresses: use placeholders such as `<your campus range>`.

Structure:
1. **One-page summary for decision-makers**: what Separ is (student research project, v2.4), what is asked
   (an observe-only pilot on 3–5 Linux machines for about two weeks), what it records, what it cannot do.
2. **What Separ does and does not do**: the three questions in plain language; the mediation points; the honest
   limits (pasted install commands are blocked in block mode; typed ones are held; scripts run by name are not
   seen; same-user attacker can stop a per-user daemon; containment is simulated unless `--enforce` as root).
3. **Approvals before installing**: IT security officer; data protection officer (DPIA decision under GDPR
   Art. 35, record of processing activities); staff council for staff machines and staff-used servers; written
   notice to users; private devices only opt-in. Include the identifier list from step 0 as the data
   protection fact sheet.
4. **Minimum requirements**: Linux x86_64 with systemd; Ubuntu 24.04 / Debian 13 / RHEL-family 9 with Python
   3.12; root once to install; no internet, no open ports (listens on localhost only); no kernel modules,
   cloud account or licence. Hardware: say it was not measured and must be measured in the pilot.
5. **Roles and key custody**: policy owner (keeps `admin.key` on an admin workstation, never on protected
   machines, offline backup); responder; what to do if the key is lost or stolen.
6. **Installation**: download from the GitHub Release, verify `SHA256SUMS`, install `.deb`/`.rpm`; where the
   files go; `separ health`.
7. **Policy workflow**: `separ setup` on the admin workstation with their own ranges; copying `policy.yaml`
   and `admin.pub` to `/etc/separ` (root-owned, 0644); changing mode with `separ policy set-mode … --key` and
   `separ reload`; per-user daemons on IT-managed machines use `/etc/separ`.
8. **Pilot plan**: observe mode; what to collect each week (counts of would-hold and would-block stories, which
   commands, false alarms), how to read the dashboard and logs, criteria for moving to warn and then block.
9. **Optional extras**, each with its own requirement: browser extension via enterprise policy; real
   enforcement (`--enforce`, root, cgroup v2, nftables); kernel sensors (Tetragon/Falco via ingest.yaml);
   login and mail sensors; notification channels.
10. **Operations**: health checks and cron watchdog, rootkit scans and their duration, updating, uninstalling and
    rolling back, troubleshooting (daemon refuses to start, policy rejected, degraded protection).
11. **FAQ** for users and service-desk staff (why was my command held? how do I report a false alarm?).

Build both PDFs with `latexmk -pdf`, no warnings about undefined references.

## 3. Report

Finish with a short report: what changed in each document, every `\todo` left (with what is needed to close
it), any statement in the old documents you removed because the code does not support it, and the facts from
`docs/it-facts.md` that I should check myself. Do not push.
