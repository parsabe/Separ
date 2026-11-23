# Separ v2.4: facts for the paper and the IT guide

Everything the paper (`documentation/main.tex`) and the IT security guides
(`it-service-desk/guide.tex`, `guide-de.tex`) state about commands, files, identifiers and
durations is taken from this file. The guides may name only commands and flags that appear in
section 1. Collected on 2026-11-23 on the development machine (a Kali Linux laptop with Python 3.14,
**not** one of the target distributions), from branch `docs/paper-and-it-guide`, version 2.4.0.

Regenerate section 1 with `python scripts/it_facts.py` (`--check docs/it-facts.md` verifies it).

## 1. Command line (exact `--help` output, COLUMNS=100)

### `separ --version`

```text
separ 2.4.0
```

### `separ setup --help`

```text
usage: separ setup [-h] [--server] [--laptop] [--mode {observe,block,warn}]
                   [--config-dir CONFIG_DIR] [--campus-cidr CIDR] [--vpn-cidr CIDR]
                   [--wlan-cidr CIDR] [--mail-domain MAIL_DOMAIN] [--key KEY]

Initialize keys, sign policy (the campus networks you name, mail domain, apps), and configure
environment.

options:
  -h, --help            show this help message and exit
  --server              configure for campus server infrastructure
  --laptop              configure for workstation / personal laptop endpoint
  --mode {observe,block,warn}
                        initial policy enforcement mode (default: observe)
  --config-dir, --workdir CONFIG_DIR
                        where the daemon reads policy.yaml and admin.pub (default: /etc/separ as
                        root, else $XDG_CONFIG_HOME/separ)
  --campus-cidr CIDR    the campus network (repeatable; required with --server). Nothing is built
                        in
  --vpn-cidr CIDR
  --wlan-cidr CIDR
  --mail-domain MAIL_DOMAIN
                        the internal mail domain (default tu-freiberg.de)
  --key KEY             the admin's private signing key (default ~/.separ-admin/admin.key; created
                        if missing). Keep it on the admin's machine, never on the endpoints
```

### `separ policy --help`

```text
usage: separ policy [-h] {show,sign,set-mode} ...

The daemon only verifies; every signature is made here with --key. After a change run `separ
reload` (or systemctl reload separ).

positional arguments:
  {show,sign,set-mode}

options:
  -h, --help            show this help message and exit
```

### `separ policy show --help`

```text
usage: separ policy show [-h] [--policy POLICY] [--public-key PUBLIC_KEY] [--json]

options:
  -h, --help            show this help message and exit
  --policy POLICY       default: <config dir>/policy.yaml
  --public-key PUBLIC_KEY
                        default: next to the policy
  --json
```

### `separ policy sign --help`

```text
usage: separ policy sign [-h] [--policy POLICY] [--public-key PUBLIC_KEY] [--key KEY]

options:
  -h, --help            show this help message and exit
  --policy POLICY       default: <config dir>/policy.yaml
  --public-key PUBLIC_KEY
                        default: next to the policy
  --key KEY             default ~/.separ-admin/admin.key
```

### `separ policy set-mode --help`

```text
usage: separ policy set-mode [-h] [--policy POLICY] [--public-key PUBLIC_KEY] [--key KEY]
                             {observe,warn,block}

positional arguments:
  {observe,warn,block}

options:
  -h, --help            show this help message and exit
  --policy POLICY       default: <config dir>/policy.yaml
  --public-key PUBLIC_KEY
                        default: next to the policy
  --key KEY             default ~/.separ-admin/admin.key
```

### `separ reload --help`

```text
usage: separ reload [-h] [--workdir WORKDIR] [--host HOST]

Sends an authenticated /api/reload to the daemon of --workdir (SIGHUP to its pid when the API
cannot be reached). The daemon never writes or signs a policy.

options:
  -h, --help         show this help message and exit
  --workdir WORKDIR  the daemon's work directory
  --host HOST
```

### `separ serve --help`

```text
usage: separ serve [-h] [--host HOST] [--port PORT] [--workdir WORKDIR] [--decoys DECOYS]
                   [--ingest INGEST] [--policy POLICY] [--public-key PUBLIC_KEY] [--lab]
                   [--enforce] [--notify-webhook URL] [--notify-command CMD] [--notify-on LIST]
                   [--rootkit-interval ROOTKIT_INTERVAL]

options:
  -h, --help            show this help message and exit
  --host HOST
  --port PORT
  --workdir WORKDIR
  --decoys DECOYS       decoys.yaml: run decoy services and watcher
  --ingest INGEST       ingest.yaml: external sensors (mapping files)
  --policy POLICY       the signed policy (default: /etc/separ/policy.yaml as root, else
                        $XDG_CONFIG_HOME/separ/policy.yaml); the daemon refuses to start without
                        one
  --public-key PUBLIC_KEY
                        the admin's public key (default: next to the policy)
  --lab                 lab mode: `separ guard --origin/--role` may choose the origin and role of
                        a command (otherwise the daemon decides them)
  --enforce             contain for real (SIGSTOP/SIGKILL, nftables, root quarantine); needs root.
                        Default off: decisions are logged, containment is simulated
  --notify-webhook URL  POST notifications as JSON to this URL (Slack/Mattermost incoming webhooks
                        work); repeatable
  --notify-command CMD  run CMD (no shell) per notification, JSON on stdin, e.g. 'mail -s Refmon
                        you@example.org'; repeatable
  --notify-on LIST      categories for the webhook/command: comma list of block, hold, alert,
                        degraded, rootkit, lifecycle or all (default:
                        block,hold,alert,rootkit,lifecycle; the log file and terminal get
                        everything)
  --rootkit-interval ROOTKIT_INTERVAL
                        seconds between rootkit scans while serving (0: only at start; default
                        3600)
```

### `separ gui --help`

```text
usage: separ gui [-h] [--host HOST] [--port PORT] [--workdir WORKDIR] [--policy POLICY]
                 [--public-key PUBLIC_KEY] [--no-browser] [--notify-webhook URL]
                 [--notify-command CMD] [--notify-on LIST] [--rootkit-interval ROOTKIT_INTERVAL]
                 [--decoys DECOYS] [--ingest INGEST]

Launch Separ's reference monitor interface. Similar to Wireshark for network packets, Separ GUI
traces behavior, role contracts and security verdicts in real time, with visual and audio alerts
for blocked attack attempts.

options:
  -h, --help            show this help message and exit
  --host HOST
  --port PORT
  --workdir WORKDIR
  --policy POLICY       the signed policy (default: /etc/separ/policy.yaml as root, else
                        $XDG_CONFIG_HOME/separ/policy.yaml); the daemon refuses to start without
                        one
  --public-key PUBLIC_KEY
                        the admin's public key (default: next to the policy)
  --no-browser          start daemon without auto-opening desktop browser
  --notify-webhook URL  POST notifications as JSON to this URL (Slack/Mattermost incoming webhooks
                        work); repeatable
  --notify-command CMD  run CMD (no shell) per notification, JSON on stdin, e.g. 'mail -s Refmon
                        you@example.org'; repeatable
  --notify-on LIST      categories for the webhook/command: comma list of block, hold, alert,
                        degraded, rootkit, lifecycle or all (default:
                        block,hold,alert,rootkit,lifecycle; the log file and terminal get
                        everything)
  --rootkit-interval ROOTKIT_INTERVAL
                        seconds between rootkit scans while serving (0: only at start; default
                        3600)
  --decoys DECOYS       path to decoys.yaml or 'default' to install standard bait (design decision
                        A75)
  --ingest INGEST       path to ingest.yaml (or directory of .yaml configs) for external sensors
                        (A76)
```

### `separ health --help`

```text
usage: separ health [-h] [--workdir WORKDIR] [--json] [--notify-webhook URL]
                    [--notify-command CMD] [--notify-on LIST]

Check a running `refmon serve` from outside, through its heartbeat file. Meant for cron or a
systemd timer: it notifies once when the daemon dies or gets a problem, and once when it recovers.

options:
  -h, --help            show this help message and exit
  --workdir WORKDIR     the daemon's work directory
  --json
  --notify-webhook URL  POST notifications as JSON to this URL (Slack/Mattermost incoming webhooks
                        work); repeatable
  --notify-command CMD  run CMD (no shell) per notification, JSON on stdin, e.g. 'mail -s Refmon
                        you@example.org'; repeatable
  --notify-on LIST      categories for the webhook/command: comma list of block, hold, alert,
                        degraded, rootkit, lifecycle or all (default:
                        block,hold,alert,rootkit,lifecycle; the log file and terminal get
                        everything)

exit codes: 0 healthy, 1 not running or heartbeat stale, 2 running with a problem
```

### `separ scan-rootkit --help`

```text
usage: separ scan-rootkit [-h] [--json] [--passes PASSES] [--interval-ms INTERVAL_MS]
                          [--with-external] [--pid-sweep {full,bounded,off}] [--calibrate N]
                          [--workdir WORKDIR] [--strict-jit]

Read-only rootkit and stealth scan of this host.

options:
  -h, --help            show this help message and exit
  --json
  --passes PASSES
  --interval-ms INTERVAL_MS
  --with-external
  --pid-sweep {full,bounded,off}
                        read-only os.stat sweep for PIDs hidden from /proc: full = 1..pid_max
                        (default; seconds), bounded = up to the highest PID allocated so far
  --calibrate N         run N clean single passes, store the observed transient discrepancy rate
                        in <workdir>/rootkit-calibration.json and exit; later scans weigh cross-
                        views with it
  --workdir WORKDIR     where the calibration is stored and read
  --strict-jit          also score anonymous rwx memory of JIT runtimes (node, java, Claude Code,
                        ...)

exit codes: 0 allow (nothing to review), 1 hold (findings to review), 2 block
```

### `separ browser-install --help`

```text
usage: separ browser-install [-h] [--system] [--port PORT] [--workdir WORKDIR]
                             [--launcher-dir LAUNCHER_DIR] [--chromium-extension-id CHROMIUM_IDS]

Write the launcher and the native-messaging manifests so the Refmon extension can reach this
user's daemon (--system: for every user, as root).

options:
  -h, --help            show this help message and exit
  --system
  --port PORT           default: the daemon's port file
  --workdir WORKDIR     daemon work directory (default: per user)
  --launcher-dir LAUNCHER_DIR
  --chromium-extension-id CHROMIUM_IDS
```

### `separ ingest --help`

```text
usage: separ ingest [-h] {list,check} ...

positional arguments:
  {list,check}

options:
  -h, --help    show this help message and exit
```

### `separ ingest list --help`

```text
usage: separ ingest list [-h]

options:
  -h, --help  show this help message and exit
```

### `separ ingest check --help`

```text
usage: separ ingest check [-h] --input INPUT [--judge] [--policy POLICY] [--public-key PUBLIC_KEY]
                          mapping

positional arguments:
  mapping

options:
  -h, --help            show this help message and exit
  --input INPUT         a file of sensor output, one record per line
  --judge
  --policy POLICY       a signed policy (default: the reference one)
  --public-key PUBLIC_KEY
```

### `separ guard --help`

```text
usage: separ guard [-h] [--host HOST] [--port PORT] [--workdir WORKDIR]
                   [--origin {web,mail,agent_input,inbound_request,download,none}] [--role ROLE]
                   [--no-exec] [--json]
                   ...

positional arguments:
  cmd_parts

options:
  -h, --help            show this help message and exit
  --host HOST
  --port PORT
  --workdir WORKDIR
  --origin {web,mail,agent_input,inbound_request,download,none}
                        where the command came from (default none: typed by you). Only `web` etc.
                        when you know it was pasted from there; a daemon accepts it in lab mode
                        only (serve --lab)
  --role ROLE
  --no-exec
  --json
```

### `separ decoy --help`

```text
usage: separ decoy [-h] {plant,refresh,approve-canaries,sources,approve-source} ...

positional arguments:
  {plant,refresh,approve-canaries,sources,approve-source}

options:
  -h, --help            show this help message and exit
```

### `separ audit --help`

```text
usage: separ audit [-h] [golden]

positional arguments:
  golden

options:
  -h, --help  show this help message and exit
```

### `separ keygen --help`

```text
usage: separ keygen [-h] keyfile

positional arguments:
  keyfile

options:
  -h, --help  show this help message and exit
```

### `separ verify --help`

```text
usage: separ verify [-h] policy public_key

positional arguments:
  policy
  public_key

options:
  -h, --help  show this help message and exit
```

## 2. What the packages install (from `dist/separ_2.4.0_amd64.deb`)

- `Architecture: amd64`, `Depends: python3 (>= 3.12) | python3.12` (the `.rpm` is `x86_64` and
  requires `python3.12 or python3.13 or python3.14`).
- `/usr/bin/separ` and `/usr/bin/refmon`: launchers that run `/opt/separ/venv/bin/separ`.
- `/opt/separ/wheels/`: the pinned wheels (CPython 3.12, 3.13, 3.14), pip and the Separ wheel, with
  `requirements-cp3XX.txt` (hash-pinned) and `SHA256SUMS`.
- `/opt/separ/install-venv`: run by the package's post-install step; builds `/opt/separ/venv` with
  `pip install --no-index --require-hashes` (no internet). Removing the package removes the venv.
- `/etc/separ/`: `README.md`, `ingest.yaml` (sensors, empty by default), `ingest.yaml.example`,
  `policy.yaml.example`, `mappings/` (Falco, Kubernetes audit, Keycloak, M365 audit,
  Postfix/Dovecot, Shibboleth IdP, sshd journald, Tetragon). **No policy and no key are installed**:
  `separ setup` (or the admin) writes `policy.yaml` and `admin.pub`.
- `/usr/lib/systemd/system/separ.service` (system daemon) and
  `/usr/lib/systemd/user/separ-user.service` (one daemon per user); neither is enabled by installing.
- `/usr/share/separ/`: the browser extension, its enterprise policy templates, the golden replay
  files; desktop entry and icon under `/usr/share/applications` and `/usr/share/icons`.

The system unit, verbatim:

```ini
[Unit]
Description=Separ Reference Monitor & Behavioral Barrier Service
Documentation=file:///usr/share/doc/separ/README.md file:///etc/separ/README.md
After=network.target

[Service]
Type=simple
User=root
RuntimeDirectory=separ
RuntimeDirectoryMode=0755
StateDirectory=separ
WorkingDirectory=/var/lib/separ
# Containment is simulated (decisions logged, nothing paused, killed or cut off) until you add
# --enforce to ExecStart: then SIGSTOP/SIGKILL on real pids from the sensors, nftables rules in
# table `inet separ`, and a root-owned quarantine. `separ health` lists what is available.
# The daemon refuses to start without a signed /etc/separ/policy.yaml + admin.pub (separ setup).
ExecStart=/usr/bin/separ serve --port 8765 --workdir /var/lib/separ --ingest /etc/separ/ingest.yaml --policy /etc/separ/policy.yaml --public-key /etc/separ/admin.pub
# re-read and verify the signed policy (it never signs or changes it)
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 3. Network, privileges, state

- `serve` and `gui` listen on `--host 127.0.0.1` and `--port 8765` by default (section 1); every
  `/api/` call needs the token in `<workdir>/api.token` (0600) and a local `Host` header. The
  per-user unit uses `--port 0` (a free port, written to `<workdir>/daemon.port`).
- No outbound connection is made by the daemon, except a notification webhook or command the admin
  configures (`--notify-webhook`, `--notify-command`).
- Work directory (state, logs, quarantine): `/var/lib/separ` for the system daemon, else
  `$XDG_STATE_HOME/separ` (`~/.local/state/separ`).
- Policy and public key: `/etc/separ/` (root-owned, not writable by group or others, else refused);
  a per-user daemon uses `/etc/separ` whenever it holds one, else `~/.config/separ/` (reported as
  degraded protection). The private key is never read by the daemon (`separ setup --key`, default
  `~/.separ-admin/admin.key`).
- Real containment only with `separ serve --enforce` as root (SIGSTOP/SIGKILL of pids reported by a
  sensor, an nftables rule in table `inet separ` when `nft` and cgroup v2 exist, a root-owned
  quarantine). Otherwise containment is simulated and `separ health` says so.
- Kernel modules, a cloud account or a licence: none.

## 4. Identifiers that Separ stores or sends

From a lab run (synthetic user `labuser`, machine name `lab-host`, an sshd journald line for the
synthetic account `alice` from 203.0.113.7 on host `node17`, documentation ranges only). "Raw" means
the value as the platform gave it; "keyed hash" means HMAC-SHA256 under the device key (`device.key`,
0600); "pseudonym" means HMAC under the separate pseudonym key (`pseudonym.key`, 0600).

| Where | Field | Form | Example (lab run) |
|---|---|---|---|
| `logs/events.jsonl` | `device` (commands through `guard`, browser, sandbox) | pseudonym of the machine name | `ps-dev-14905f5314f27ae8` |
| `logs/events.jsonl` | `device` (events from an ingested sensor) | **raw**: the sensor's host name (`_HOSTNAME`, `node_name`, `hostname`) | `node17` |
| `logs/events.jsonl` | `actor.user` | **raw** login name (the daemon's `$USER`, or the account a sensor reports) | `labuser`, `alice` |
| `logs/events.jsonl` | `actor.id` | internal id; for identity sensors **raw** account (`acct:<name>`); for Falco `<pid>@<container id>`, for Tetragon the exec id | `proc:guard-00001`, `acct:alice` |
| `logs/events.jsonl` | `object.fingerprint` | keyed hash of the command, URL, path or login line | `hmac:4f10…` |
| `logs/events.jsonl` | `attrs.network_class` (logins) | policy class, else keyed hash of the /16 (IPv4) prefix; the address is dropped | `net-cfa282b532a7` |
| `logs/verdicts.jsonl` | `device`, `users` | as in the events: device pseudonym (raw host name for sensor stories); `users` **raw** | `"users": ["labuser"]` |
| `logs/notifications.jsonl`, webhook and command payloads | `device`; `message`; `details` | device pseudonym of the daemon; fixed sentences; story id, decision, tactics; **no user name** | `"device": "ps-dev-14905f5314f27ae8"` |
| `logs/barrier.log` | file names of quarantined files | **raw** file name | `QUARANTINED upload-shell.php -> …` |
| `heartbeat.json` | `device`, `pid` | pseudonym; the daemon's process id | `"device": "ps-dev-…", "pid": 4711` |
| dashboard (`/api/state`) | work directory path, quarantined file names, last 25 event lines | **raw** (the path contains the home directory, hence the login name; event lines as above) | `"workdir": "/home/<login>/.local/state/separ"` |
| `proposals/decoy-sources.json` (only with decoys) | source address of a decoy hit | external address **raw** (by design, A71, for a block list); internal address as pseudonym plus value sealed under the vault key (four-eyes to reveal) | |

Example lines (lab run):

```text
events.jsonl (guard):  {"event_id":"ev-00002","ts":"2026-11-23T19:13:08.099302Z","device":"ps-dev-14905f5314f27ae8","type":"content_in","actor":{"id":"proc:guard-00001","role":"interactive_shell","interactive":true,"user":"labuser"},"object":{"class":"command_text","fingerprint":"hmac:4f104de515120d3005c33e9e57ce8e403c15ddf0cab175caefdcd07e03116486"},"attrs":{"source_class":"web","entropy_bits":4.4724,"encoded_char_ratio":0.0,"longest_ws_run":1}}
events.jsonl (sensor): {"event_id":"in-sshd-journald-00000001","ts":"2026-11-18T11:06:40Z","device":"node17","type":"auth","actor":{"id":"acct:alice","role":"identity_provider","interactive":false,"user":"alice"},"object":{"class":"login","fingerprint":"hmac:55858b917256ef3d68885cfde3f9f0a7e7600598f52dd220c3a3848e72d2a069"},"attrs":{"auth_result":"success","auth_method":"password","network_class":"net-cfa282b532a7"}}
verdicts.jsonl:        {"verdict_id": "v-1", "story_id": "st-1", "device": "ps-dev-14905f5314f27ae8", "decision": "block", "users": ["labuser"], "summary": "What happened: A program started from something that came in from a web page. It ran a command that was copied in from outside. It also tried to hide what it was doing. Action taken: Refmon stopped the program and everything it started. Next step: Tell the user thei…
notifications.jsonl:   {"category": "block", "details": {"decision": "block", "holds": [], "log_odds": -0.11, "mode": "block", "override": null, "platform": "server", "story_id": "st-2", "tactics": ["Initial Access", "Persistence"]}, "device": "ps-dev-14905f5314f27ae8", "message": "A program started from something that came in from a request from the internet. It wrote a program file it is not allowed to write. It also tried to start again…
barrier.log:           [19:13:08] QUARANTINED upload-shell.php -> 20261123T191308Z_upload-shell.php.quarantined (mode 0400, preserved safely)
heartbeat.json:        {"device": "ps-dev-14905f5314f27ae8", "pid": 4711, "mode": "block"}
```

**Where a raw identifier is stored that the privacy claims do not cover.** CLAUDE.md's privacy rule
covers *content* (commands, request bodies, URLs, file contents: keyed hashes after Observe) and
says "only verdicts leave the device, under pseudonyms". The following are stored **raw** on the
device and are not covered by that rule:
1. login and account names in `events.jsonl` and `verdicts.jsonl` (`actor.user`, `users`, and
   `acct:<name>` actor ids of identity sensors);
2. host names of ingested sensor events (`device`);
3. names of quarantined files in `barrier.log` and on the dashboard;
4. the work directory path on the dashboard (it contains the home directory).
Pseudonymisation of devices and users happens only in `Reporter.export`, which the live daemon does
not call: nothing it writes is exported. What leaves the machine are notifications (webhook or
command, only if configured) and the heartbeat file read by `separ health`; both name the device by
pseudonym and contain no user name.

**Who can read the logs (checked in the lab run).** The work directory is 0700 for a per-user daemon
but 0755 for the system daemon (`/var/lib/separ`), and `logs/`, the log files and `heartbeat.json`
are created with the process umask (0664 with umask 002 in the lab run; 0644 under systemd's default
umask 022). So on a machine running the **system daemon, every local user can read
`/var/lib/separ/logs/`**, including the raw login names, host names and quarantined file names above.
Not fixed in v2.4 (no code change in this task); until it is, set `UMask=0077` in the unit or
restrict `/var/lib/separ/logs` by hand.

**Other users' processes and names.** The rootkit scanner reads the environment, executable link and
memory maps only of processes of its own user (`target_uid`); its PID sweep only tests whether
`/proc/<pid>` exists and, for a PID hidden from readdir, reads its `Tgid` from `/proc/<pid>/status`
(no name, no command line is kept; a finding names a PID by keyed hash). The dashboard shows what the
daemon judged: on a desktop that is the user's own guarded commands; on a server with sensors
attached, it is every ingested event, so it shows other accounts' names and the hosts' names raw.

## 5. Measured durations (development laptop, not a target machine)

- `separ scan-rootkit` with the default full PID sweep (pid_max 4194304, two passes): 25.6 s wall
  time, of which the sweep is about 12 s per pass. `--pid-sweep bounded` (up to the highest PID
  allocated so far + 1024, here about 116000): about 0.3 s per pass.
- The daemon starts its own scan without the sweep and sweeps (bounded) on its periodic scan, every
  `--rootkit-interval` seconds (default 3600).
- Decision time of a guarded command: see the Attack Lab reference run
  (`docs/evaluation/lab-reference-run-v2.4.json`).
- CPU, memory and disk use of the daemon: **not measured**; to be measured in the pilot.

## 6. Hold and timeout defaults (default policy)

- Endpoint hold timeout (`decisions.endpoint_hold_timeout`): 60 s; without an answer the paused
  program is stopped.
- Server hold (`decisions.server_hold_wait`, `server_hold_timeout: keep_quarantined`): waits up to
  3600 s for an admin; without an answer the file stays quarantined.

## 7. Behaviour the guides rely on (checked in the code)

- **Log growth.** The daemon appends to `logs/*.jsonl` and `logs/barrier.log` and does not rotate
  them in v2.4.
- **Notification titles** (`logs/notifications.jsonl`, webhook, command): in observe or warn mode a
  story that would be blocked or held is titled `Would block (not enforced)` or
  `Would hold (not enforced)`; in block mode `Blocked` or `Held: an answer is needed`.
- **`separ guard` in block mode**: a command decided BLOCK or HOLD does not run and the command exits
  with status 1; in observe or warn mode it runs and the decision is only logged. Answering a hold of
  a guarded command in the dashboard does not run the command afterwards.
- **Browser extension holds**: the clipboard is held and the user is asked *Keep it* / *Remove it*;
  no answer within the endpoint hold timeout (60 s) removes it.
- **Packages and `/etc/separ`**: no file is marked as a configuration file (conffile). Removing the
  package removes the files it installed there (`ingest.yaml`, the examples, `mappings/`) and the
  venv; the `policy.yaml` and `admin.pub` that `separ setup` wrote, and `/var/lib/separ`, stay.
- **Key rotation**: there is no revocation list. Changing the admin key means replacing
  `/etc/separ/admin.pub` and `policy.yaml` on every machine and `separ reload`.
- **Identity sensors** (sshd, Shibboleth, Keycloak, Postfix/Dovecot, M365): their rules start in
  observe mode for the roles `identity_provider` and `mail_server` (design decision A77); a story only
  they produced is capped at HOLD.

## 8. System commands the guides use

Standard tools of the target distributions, not part of Separ; the guides use only these forms:
`sha256sum --ignore-missing -c SHA256SUMS`, `curl -fLO <url>`, `sudo apt install ./<file>.deb`,
`sudo apt remove separ`, `sudo dnf install python3.12 ./<file>.rpm`, `sudo dnf remove separ`,
`sudo install -o root -g root -m 0644 <file> /etc/separ/<file>`, `sudo systemctl enable --now
separ.service`, `sudo systemctl status separ.service`, `sudo systemctl reload separ`,
`sudo systemctl restart separ`, `sudo systemctl edit separ` (a drop-in with `[Service]` and
`UMask=0077`), `sudo systemctl --global enable separ-user.service`, `crontab -e`,
`grep -c '<text>' <file>`, `scp <file> <host>:` and `uname -m`.
