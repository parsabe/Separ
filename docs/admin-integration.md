# Connecting sensors and login logs (v2.2): a guide for administrators

Refmon judges what it is told. On its own, the live daemon sees only what is sent to it: commands
through `refmon guard`, the browser extension, files in its sandbox, and its decoys. Seeing
everything on a server needs a sensor that the server's administrators install, because it needs
root: Falco, Tetragon, auditd, the Kubernetes audit log, login logs. This kit connects such a
sensor **without code**. A YAML *mapping file* says how one line of the sensor's output becomes a
Refmon event, and `refmon serve --ingest ingest.yaml` feeds it into the daemon.

## 1. Choose and copy a template

```sh
refmon ingest list
```

| Template | Sensor | Gives Refmon | `provides` |
|---|---|---|---|
| `tetragon.yaml` | Cilium Tetragon (`process_exec`, `tcp_connect` kprobe) | every process start, outbound connections | `process_ancestry`, `network_connections` |
| `falco.yaml` | Falco JSON alerts (syscall source) | the processes, connections and file writes Falco's rules match | none (rule matches only) |
| `sshd-journald.yaml` | OpenSSH via `journalctl -o json` | SSH logins, failed and invalid-user attempts | none |
| `keycloak.yaml` | Keycloak jboss-logging event listener | SSO logins and login errors | none |
| `shibboleth-idp.yaml` | Shibboleth IdP `idp-audit.log` | successful SSO logins | none |
| `m365-audit.yaml` | Microsoft 365 unified audit log | sign-ins, failed sign-ins, inbox and mailbox forwarding, app consents | none |
| `postfix-dovecot.yaml` | Dovecot and Postfix via journald | IMAP/POP logins, auth failures, SMTP SASL failures | none |

Every template is a **starting point**, written against the documented output format of its
system and tested on synthetic samples (`tests/ingest/`). Field names and messages differ between
versions, so check the template against your own sensor before relying on it (step 3).

`provides` names the heartbeat capabilities a sensor really supplies. Refmon reports everything
the policy relies on and no sensor provides as *degraded protection*, so be honest here. Falco
reports only what its rules match, which is not full process ancestry.

## 2. Adjust it to your servers

The parts you will change:
- **`tables.roles`**: program name → role. The role decides which contract applies (CLAUDE.md
  C4): `php-fpm` → `web_worker` means a PHP worker that starts a shell breaks its contract.
  `strip_version` turns `php-fpm8.2` into `php-fpm`.
- **`path_group`, `web_root`, `executable`** (Falco file writes): regex tables that classify a raw
  path. Use the path groups your contracts name (`cache`, `sessions`, `uploads_non_executable`
  for the web worker).
- **the identity policy section** (in the signed policy, not the mapping):

```yaml
identity:
  internal_mail_domains: [tu-freiberg.de]   # forwarding elsewhere counts as forwarding outside
  approved_apps: [Zoom, Moodle]             # app consents outside this list count as persistence
  min_logins: 20                            # an account's networks count only after this many logins
  failure_burst: 10                         # failed attempts for one account within burst_window
  burst_window: 5m
destinations:                               # name your own networks; logins from them get that class
  - {name: campus, match: {cidr: [192.0.2.0/24]}}    # your campus ranges here
  - {name: vpn, match: {cidr: [198.51.100.0/24]}}    # your VPN pool here
```

The mapping language, in short:
- **Paths:** `a.b.c` walks objects, `a[b.c]` reads a key with dots in it (Falco, journald), `a.0`
  indexes a list.
- **Values:** a literal, a template such as `"{x}@{y}"`, or `{from: path}` with any of `map`
  (inline, or a table name), `default`, `regex` plus `group`, `classify`, `find` (in a
  `[{Name, Value}]` list), `first` (alternatives), `prefix`, `basename`, `strip_version`, `lower`,
  `as` (int, float, bool, str).
- **Rule selection:** the first rule whose `match` conditions all hold (`equals`, `in`, `regex`,
  `exists`) builds the event.
- **Formats:** `json`, `kv` (key=value) or `delimited` (with `fields`). `_line` is the whole line.

## 3. Check it on real output, safely

```sh
refmon ingest check my-falco.yaml --input /tmp/falco-sample.jsonl --judge
```

For each line this prints the outcome (`mapped`, `unmatched`, `unparsable`, `invalid`), the event
type, the role, the attribute keys and the *length* of the content. It **never prints the content
itself**, so tuning a mapping on real output does not copy commands or addresses into a terminal
log. `--judge` also shows the decision each story would get. Delete the sample afterwards.

## 4. Run it

```yaml
# /etc/refmon/ingest.yaml
sensors:
  - mapping: /etc/refmon/mappings/tetragon.yaml
    source: {socket: /run/refmon/tetragon.sock}
  - mapping: /etc/refmon/mappings/sshd-journald.yaml
    source: {socket: /run/refmon/sshd.sock}
  - mapping: /etc/refmon/mappings/falco.yaml
    source: {file: /var/log/falco/events.json}
```

```sh
refmon serve --port 0 --ingest /etc/refmon/ingest.yaml
journalctl -o json -f _COMM=sshd _COMM=sshd-session | socat - UNIX-CONNECT:/run/refmon/sshd.sock
tetra getevents -o json | socat - UNIX-CONNECT:/run/refmon/tetragon.sock
```

- **Prefer a socket.** Refmon creates it with mode 0600, and the sensor (usually root) connects.
  Nothing raw is written to disk on the way, which is what Refmon's privacy rule asks for.
- **A file** (`file:`) is followed from its end and across rotation. That file is the *sensor's*
  log, not Refmon's: its contents and retention are your responsibility. Keep it short or use a
  socket.
- **Health.** A sensor that stops is a critical *Sensor stopped* alert. The heartbeat lists the
  capabilities still missing. Lines that do not map are counted, never judged.

Privacy, unchanged: raw values reach Observe in memory and are fingerprinted or reduced to a class
there. The source address of a login becomes a named class (`campus`, `vpn`), or a bucket of its
/16 prefix keyed with the device key (`net-3fa9…`); the address itself is never kept. Account names
stay on the device and are pseudonymised in every verdict that leaves it.

## 5. What hacked-account detection does (v2.2)

Every account is its own actor (`acct:<name>`), with a counted baseline of the network classes it
logs in from. These signals reuse weights that were already approved, and no new weight was added
(owner decision, 2026-11-03):

| What happens | Signal | Weight |
|---|---|---|
| a login from a network class the account never used (only once the account has `min_logins` logins and a stable set of networks) | `contract_surprisal` | 2.0 |
| `failure_burst` failed attempts in `burst_window` (password guessing, MFA push fatigue) | `effect_credential` | 3.5 |
| a mailbox rule forwarding to a domain outside `internal_mail_domains` | `effect_exfil`, `effect_persist` | 2.5 |
| consent to an application not on `approved_apps` | `effect_persist` | 2.5 |
| any attempt on a **decoy account** (a canary of class `account`) | canary override | block |
| a login from an address on a threat list (e.g. an approved decoy source) | `effect_threat_list_hit` | 4.5 |

How it decides:
- **Never more than a hold.** A story made only of login and mail events is held at most, even
  when its evidence crosses the block threshold: "was this you?". When the hold is enforced it
  pauses **that account's session** (the account actor); no answer ends the session. The account
  is never locked. An override (decoy account) still blocks.
- **Observe mode first.** The four reused rules run in *observe* mode for the roles
  `identity_provider` and `mail_server`, and only for them. They record verdicts and act on
  nothing until a pilot has measured their false alarms. To enforce after the pilot, change those
  `rules` entries in the signed policy to `mode: block`.
- **A login never creates an origin label.** Otherwise every command an administrator types over
  SSH would look like it came from outside.
- **Learning.** A new network seen during an open incident is parked. It is learned once the
  account has been quiet for `rates.long_window`, so a user who moved is held once, not forever.
  Limit: an attacker who waits out that window is learned too.

## 6. Containers, Kubernetes and Terraform (v2.3)

| Template | What it maps |
|---|---|
| `k8s-audit.yaml` | `pods/exec`, privileged pods, pods mounting the host root or sharing its process table, RBAC bindings, DaemonSets, CronJobs and admission webhooks, reads of secrets |
| `tetragon.yaml` | the role of a container from its **image**; Terraform/OpenTofu as `iac_tool` and their providers; reads of service-account tokens, kubeconfigs, Terraform state and cloud credentials |

The default policy's contracts for these roles (CLAUDE.md C4 style) are starting points. Adjust
them in your signed policy:

| Role | May | May not (a Contract signal) |
|---|---|---|
| `k8s_api_client` (everyone not listed below) | ordinary API use | exec into pods, create DaemonSets, CronJobs or webhooks, privileged pods or RBAC bindings, read secrets |
| `k8s_admin` (group `system:masters` in the template) | all of that | — |
| `ci_deployer` (service accounts of CI namespaces) | create workloads | exec into pods, change privilege, read secrets |
| `container_workload` (any container image the table does not name) | its work | read protected assets (tokens, credentials), change privilege |
| `iac_tool` (terraform, tofu) | run providers, git and ssh; reach the registry and the cloud API; read its state and cloud credentials | start anything else (a `local-exec` provisioner), connect elsewhere, persist |

Things to know:
- **The cloud metadata service** (169.254.169.254) is listed in no contract, so every connection
  there is a `fetch`. A container that asks it for credentials is caught by what it does, not by
  what it is.
- **Name your own cloud API hosts** in the `cloud_api` destination (the default is a placeholder).
- **CI that deploys DaemonSets or CronJobs** is held: a persist has no role allowance in the
  specification (finding F13). Give the CI role a scoped, expiring exception:

```yaml
exceptions:
  - {id: X-CI-01, reason: "CI deploys node agents", scope: {role: ci_deployer},
     disables: [R-EFF-PERSIST], expires: 2027-06-30}
```

- **`local-exec` provisioners that your modules legitimately use** are a contract violation by
  default. Name the programs they run as an executable class and add it to `iac_tool.may_exec`.

## 7. Not covered yet

- **Linking sources.** A login and the processes that follow it on the same server are separate
  stories: the sensors use different ids (an SSH session's pid against Tetragon's exec ids).
- **A container escape without an API call** (a kernel exploit) is seen only by what the process
  does next on the host.
- **Field names.** The templates have not been run against real Falco, Tetragon, Keycloak,
  Shibboleth, M365 or Dovecot output here; only against synthetic samples. Step 3 is how you check
  them.
