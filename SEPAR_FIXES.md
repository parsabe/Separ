# Separ — fix the code review findings (Nov 2026)

You are working in the Separ repository (package `refmon`, CLI `separ`). Follow CLAUDE.md, especially:
small commits, each with tests; nothing changes weights or structural rules without the owner's approval;
**record a new variant seed in docs/variant-seeds.md BEFORE any change that can change a decision**,
then evaluate the old and new version on that seed exactly as docs/v2.3-evaluation.md does.

Do NOT touch `documentation/` (the paper) in this task. Do keep `README.md`, `packaging/etc/separ/README.md`
and `it-service-desk/guide.tex` factually true for every behaviour you change.

Work on a new branch `fix/review-2026-11`. Work through the items in order. After each item:
`ruff check . && ruff format --check . && pytest && python -m refmon.audit tests/golden && python scripts/check_publishable.py`.
If an item turns out to be wrong or impossible as described, stop on that item, explain why in
docs/review-list.md, and move on. Do not weaken a test to make it pass.

---

## Part 1 — Security and correctness (no decision changes expected)

### 1. `separ setup` must configure the policy the daemon actually loads
Today `setup.py` writes `policy.yaml` to `~/.config/separ/` or `/etc/separ/`, but `LiveBarrier` only reads
`<workdir>/policy.yaml` (live.py ~330) and, when it is missing, writes its own default with
`mode = "block"` hard-coded (live.py ~419-421). `separ.service` runs with `--workdir /var/lib/separ`.
- One source of truth: the system daemon reads `/etc/separ/policy.yaml` and `/etc/separ/admin.pub`;
  a per-user daemon reads `$XDG_CONFIG_HOME/separ/` (default `~/.config/separ/`). Add `--policy` and
  `--public-key` to `serve` for explicit paths.
- If no signed policy exists, the daemon **refuses to start** with a clear message ("run `separ setup`").
  It never generates a policy on its own and never defaults to `block`.
- Tests: setup with `--mode observe` then start the barrier → mode is observe and the setup's
  destinations/identity settings are in force; a missing policy → start fails.

### 2. The signing key must not live with the daemon
`admin.key` sits next to `policy.yaml` and `/api/mode` re-signs the policy on request (live.py ~433-442),
so any process of the daemon's user can switch to observe or sign anything.
- The daemon only ever gets the **public** key. Remove every `_private_key()` use from `live.py` and
  `deception/cli.py` paths that run inside the daemon.
- `separ setup` and a new `separ policy sign|set-mode|show` command do all signing. They read the
  private key from `--key PATH` (default `~/.separ-admin/admin.key`, a separate 0700 directory), never
  from the daemon work directory. Document that IT keeps it on the admin's machine, not on the endpoints.
- `/api/mode` is removed; a mode change is a new signed policy file plus `separ reload` (SIGHUP or an
  authenticated `/api/reload` that only re-reads and verifies the file).
- Policy files and `admin.pub` under `/etc/separ` are root-owned 0644; the daemon refuses a policy or
  public key that is writable by its own (non-root) user or by group/others.
- Tests: no code path in the daemon can produce a signature; `/api/mode` is gone; a writable policy is refused.

### 3. Containment must be real (or reported as unavailable)
Today only `SimulatedEnforcer` exists; nothing kills a process or cuts the network.
- Add `LinuxEnforcer` (`src/refmon/enforcer_linux.py`) implementing the same `act`/`undo` interface:
  - `pause_process` / `resume`: SIGSTOP / SIGCONT on real PIDs; `kill_process_tree`: freeze with the
    cgroup v2 freezer when the process has its own cgroup, else SIGSTOP the tree, then SIGKILL; never PID 1,
    never the daemon itself, never a process of another user unless running as root.
  - `cut_network`: an nftables rule matching the process's cgroup (`socket cgroupv2`), in a dedicated
    table `inet separ`, with an undo record; if `nft` or cgroup v2 is missing, return `unavailable`.
  - `quarantine_file`: move into a root-owned quarantine directory, 0400, keep an undo record.
- Real PIDs come from sensor events (Tetragon/Falco mappings already carry them); add a `pid` field to
  the actor mapping where the sensor gives one. Without a real PID, the action is `unavailable`,
  never guessed (missing information never generates evidence).
- `serve` uses `LinuxEnforcer` only with `--enforce` (default off) and when running as root; otherwise
  `SimulatedEnforcer` and the health report says "containment: simulated".
- Every action and its result go to the log and the GUI; `separ health` reports which actions are available.
- Tests: unit tests with a fake process table and fake `nft` runner; one opt-in integration test
  (`pytest -m root`) that runs only as root in a VM.

### 4. Safe key and work-directory creation
- `setup.py` writes `admin.key` with `write_text` then `chmod` (briefly readable). Use the existing
  `_secret_file` (O_EXCL, 0600 from the start) for every secret file, everywhere.
- Default per-user work directory: `$XDG_STATE_HOME/separ` (default `~/.local/state/separ`), not
  `/tmp/separ-live-<uid>` (predictable, shared, wiped at reboot). `setup.py` must call `_secure_dir`
  (ownership, not a symlink, 0700) on every directory it creates.
- Migration: if the old `/tmp` directory exists and belongs to the user, copy `device.key` and
  `pseudonym.key` once and say so.
- Tests: a pre-existing directory owned by another uid or a symlink is refused; key files are 0600 at creation.

### 5. Quarantine must not follow symlinks
`path.is_file()`/`stat()` follow links and `dest.chmod(0o400)` (live.py ~1245) changes the link target.
- In the sandbox/web-root watcher, use `lstat`; skip symlinks (report them as their own finding:
  "symlink in web root", no chmod); use `os.open(..., O_NOFOLLOW)` + `fchmod` where a mode is set.
- Tests: a symlink in the web root pointing to a file outside → target mode unchanged, finding reported.

### 6. Packaging: Python and pydantic versions
- `pyproject.toml` says `>=3.12`, `build_packages.py` and `install.sh` accept 3.10, and the code needs
  ≥3.11 (`StrEnum`, `datetime.UTC`, `typing.Self`). Make everything require **3.12**.
- The `.deb` depends on distro `python3-pydantic`, which is pydantic **1.x** on Ubuntu 24.04 and Debian 12;
  the code needs pydantic ≥2.7. Build the packages so they install into a private venv
  (`/opt/separ/venv`) with **vendored, pinned wheels** (pydantic, pydantic-core, annotated-types,
  typing-extensions, pyyaml, cryptography) so installation needs **no internet**; make the packages
  per-architecture (amd64/x86_64, optionally arm64). `install.sh` does the same from a wheel directory.
- Add a CI job that installs the built `.deb` in `ubuntu:24.04` and `debian:13` containers and the `.rpm`
  in `rockylinux:9` (with python3.12), then runs `separ --version && separ health --json`.

### 7. HTTP API hardening (live.py `make_http_server`)
- Cap `Content-Length` (e.g. 64 KiB), reject missing/negative values with 400; a JSON body that is not
  an object → 400 (today it raises an uncaught AttributeError).
- `/api/guard` may not set `origin` or `role` unless the request comes from the CLI client with the
  token **and** the daemon runs in lab mode; in normal operation the daemon decides them.
- Tests for each case.

### 8. No constant default keys
Remove `key=b"refmon-device-key"` defaults from `Pipeline`, `RootkitScanner`, `evaluate_rootkit_scan`;
make `key` required. Tests and lab code pass an explicit test key. `ingest check --judge` uses
`new_device_key()`.

### 9. Hard-coded values
- Remove the hard-coded device ids `dev-7f3a` / `dev-b21c` in live.py; use the pseudonymized host name.
- `setup.py`: `139.18.0.0/16` is Universität Leipzig's network, not TU Freiberg's. Remove every hard-coded
  campus network. `separ setup --server` takes `--campus-cidr` (repeatable, required for server mode),
  `--vpn-cidr`, `--wlan-cidr` (all optional), and `--mail-domain` (default `tu-freiberg.de`).
  Do not label `172.16.0.0/12` "eduroam". Print exactly what was configured (laptop mode must not
  print server networks). Update `packaging/etc/separ/policy.yaml.example` with placeholders.

---

## Part 2 — False positives and detection gaps (decision changes: record a NEW seed first)

Before item 10, draw and record a new variant seed in docs/variant-seeds.md exactly as before
(`secrets.randbelow(900_000_000) + 100_000_000`), commit it, tag the current code `v2.3.1-base`.
Weights stay unchanged in this whole part. If a structural change below is needed, write it as a
design decision (A80, A81, …) in docs/design-decisions.md with a reason that does not mention a scenario,
and mark it "needs owner approval" — implement it behind a policy flag that defaults to the new behaviour
only after I approve.

### 10. `separ guard` default origin
`cli.py` defaults `--origin web`, so every guarded command is scored as a web paste
(`sudo apt update` → −2.61 → BLOCK). Default to `none`; `web` only when given explicitly or when the
browser extension supplied the provenance.

### 11. Browser clipboard: judge commands, not every copy
Every copy, including the user's own selection of a plain URL or prose, is judged as a shell command
(a lone `https://…` should land at −2.61 → BLOCK → clipboard replaced).
- Add a pure function `looks_like_command(text) -> bool` (src/refmon/intent.py): true when the text starts
  with or contains a shell program token/known interpreter, a pipe into a shell, `$(`, backticks,
  redirections, `;`/`&&` chains, PowerShell/`mshta`/`cmd /c` forms, or Run-dialog style payloads;
  false for a lone URL, an e-mail address, and ordinary prose. Text that is not a command is judged as a
  `navigate`-style address check only (threat lists), never as an exec.
- Text copied by the user's own selection (`user_selection=True`) of a single URL is never blocked.
- Tests with a table of ≥40 examples (commands, URLs, prose, mixed).

### 12. Attack Lab: honest benign controls
All attacks are `origin="web"` and all benign controls `origin="none"` with no network use.
Add benign controls **with `origin="web"`**, recorded with their real outcome (do not tune to pass):
`git clone https://github.com/torvalds/linux`, `pip install requests`, `curl -fsSL https://sh.rustup.rs | sh`,
`sudo apt update`, `python3 -m venv .venv`, `docker run hello-world`, `wget https://example.org/file.tar.gz`,
`ssh user@login.example.org`, a pasted URL, a pasted paragraph of prose. Report the counts in
docs/attack-lab.md as "benign web-origin controls: allowed / held / blocked". Same for typed (`origin=none`)
network commands.
Also add `policy.yaml.example` entries showing how an admin lists trusted destinations and trusted
install sources (git hosts, package indexes, the university software portal) — as an example only,
not as a default.

### 13. Obfuscation and command-text gaps (intent.py)
- `exec(`, `compile(`, `__import__(`, `marshal.loads`, `codecs.decode`, `''.join(map(chr` / `chr(` chains,
  `bytes([` … `).decode` are `encoded` (hide).
- A host given through a variable to `socket.connect((h, port))` / `fsockopen($h` counts as network
  with destination `unknown`.
- `bash -c "$(curl …)"` / `sh -c "$(wget -O- …)"` is fetched-code execution like `| sh`.
- Tests for each, plus the existing ones unchanged.

### 14. Workspace "ransomware" watcher
All changed files are reported `new_file=True`, so unzip/`git checkout` in the watched workspace looks
like a ransomware burst. Report `new_file` truthfully (first time seen vs. existing file rewritten), and
feed only **rewrites/renames of existing files** to the mass-change detector. Tests: extracting 200 new
files → no mass_change; rewriting 60 existing files → mass_change.

### 15. One Origin strength everywhere
`signals.py` uses noisy-OR (`tagger.combined`) for the origin threshold; `judge.py` uses `max`. Use
noisy-OR in both (it is what the docs state). Property test: Origin "failed" ⇔ the threshold used by
Contract signals is crossed.

### 16. Hold/block thresholds as a three-action decision
`evidence.py` derives each threshold against ALLOW only and mixes probability and odds in the hold
threshold. Implement the expected-cost decision over {ALLOW, HOLD, BLOCK} with the same costs and catch
rate: cost(ALLOW)=p·C_miss, cost(HOLD)=C_hold+p(1−h)C_miss, cost(BLOCK)=(1−p)·C_fb; pick the minimum
(ties → the milder action), then apply the contract gate and overrides exactly as now. Expose the derived
log-odds boundaries in `separ health` and the GUI. This is a structural change: A-number, owner approval,
evaluate on the new seed only.

### 17. Rootkit scanner coverage (rootkit.py)
- Kernel modules: compare both directions (`/sys/module/*/initstate` vs `/proc/modules`) and also against
  `/proc/kallsyms` module names when readable; report each discrepancy type separately.
- Hidden PIDs: add a read-only sweep of `1..pid_max` with `os.stat("/proc/<pid>")` (no signals), compare
  with `readdir("/proc")`, two passes as now; keep the own-UID ancestry check.
- Measure `race_prob` instead of assuming 1e-3: add `separ scan-rootkit --calibrate N` that runs N clean
  passes and stores the observed transient-discrepancy rate; the weight uses it.
- Tests with fake /proc trees for each case.

---

## Part 3 — Finish
1. Run the full evaluation on the new seed for the old tag and the new code (scripts/dump_matrix.py,
   compare_versions.py), write docs/v2.4-evaluation.md in the existing style, including **all** benign
   variants (neutral and "adds a violation") and the new lab controls.
2. Bump the version to 2.4.0 everywhere (pyproject, packages, `separ --version`, README badge).
3. Make sure `scripts/reproduce.py` works from a fresh clone once tags are pushed; if a needed tag is
   missing it must print which one and exit non-zero (CI should show that clearly).
4. Summarize every change, every decision change, and every item you could not do in docs/progress.md.
Do not push; I will review and push myself.
