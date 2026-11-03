# Deception: decoys, decoy services, tarpit (v2.1)

This is a guide for the administrators who run Refmon on a server. Decoys are things that no
legitimate work ever touches: a planted `.env` with a database password, cloud keys, a production
kubeconfig, a "password vault" sheet, a port where no real service runs. Anyone who touches one is
looking for secrets or scanning the network. Refmon treats every touch as a canary hit (an absolute
block), names it in a notification, and proposes the source for blocking.

Nothing here changes the policy on its own. Planting writes a *proposal*. A person approves it and
it is signed into the policy. A source address is blocked only after a person approves it.

## 1. Write `decoys.yaml`

```yaml
plant:
  dir: /srv/share/finance            # a place an intruder would search; NOT inside a backup set
  beacon_url: http://files.example.internal:8088   # your own decoy HTTP listener (below)
  age_months: 18                     # file times are scattered over this many months
  ignore_roles: [backup_job]         # roles allowed to read decoys (needs an attributing sensor)
  org_domain: example.internal       # makes host names inside the decoys look local
  # files: [env, cloud_keys, kubeconfig, pgpass, password_vault, beacon_doc]   (default: all)
  # names: {password_vault: "Finanzen/Passwoerter_GF.csv"}                       (your own names)
listen:
  max_concurrent: 16                 # tarpits at once; more connections are reported and closed
  max_seconds: 300                   # the longest a client is held
  services:
    - {name: ssh-legacy, port: 2222, banner: "SSH-2.0-OpenSSH_8.0", endless: true}
    - {name: files-http, port: 8088, kind: http, server_header: "Apache/2.4.37 (Red Hat Enterprise Linux)",
       tarpit_bytes_per_s: 2}
watch: true
proposal: proposals/decoys.json      # in the daemon's work directory (owner-only)
```

## 2. Plant, approve, run

```sh
refmon decoy plant --config decoys.yaml                    # writes the decoys and the proposal
refmon decoy approve-canaries --config decoys.yaml --by "A. Admin"
refmon serve --port 0 --decoys decoys.yaml                 # listeners + watcher inside the daemon
```

- **Plant** refuses to overwrite an existing file or to write outside `dir`.
- **Approve** first verifies the current policy's signature, so a tampered policy is never
  re-signed. It then adds the canaries (one `file` canary per decoy, the secrets inside them, the
  beacon path, one `service` canary per listener) and signs the result. A running daemon adopts the
  signed policy at its next health tick.
- Until a listener's canary is approved, the heartbeat reports it as *degraded: decoy services
  without an approved canary*.

Keep the decoys alive: run `refmon decoy refresh --config decoys.yaml` from cron now and then. It
moves the times of a few decoys to recent working hours. It changes times only, so it never trips
the watcher.

## 3. What happens on a touch

| What | Refmon does | Notification |
|---|---|---|
| a connection to a decoy service | judges it as a request of the channel role `decoy_service`: canary override, **block** of the story; the listener keeps running (A70); the source address becomes a proposal | *Blocked* and *Decoy source proposed for blocking* |
| the beacon image of a decoy document is fetched (the document was taken and opened elsewhere) | the same, through the `beacon` canary | as above |
| a decoy file is opened, changed or removed | an **alert** only: the unprivileged watcher (inotify) cannot name the process, so nothing can be stopped (A72) | *Decoy file touched* (critical) |
| a decoy credential is read by a judged command (`refmon guard`, the lab) | canary override, block | *Blocked* |

## 4. Proposals and blocking

```sh
refmon decoy sources                       # list proposals
refmon decoy approve-source DS-0001-ab12cd --by "A. Admin" \
    --firewall-command 'nft add element inet filter refmon_block { {ip} }'
```

- **An external address** (outside RFC 1918, carrier-grade NAT, loopback, link-local, IPv6 ULA and
  the policy's internal ranges) is kept raw in `proposals/decoy-sources.json`. That file is mode
  0600 in a 0700 directory, and an entry is deleted 7 days after its last hit unless approved.
  Approving it adds the address to the `decoy-sources` host list of the signed policy. From then
  on, a request from it or a connection to it is a threat-list hit everywhere Refmon judges. The
  firewall command (yours, optional) runs once after approval, with `{ip}` replaced and no shell.
- **An internal address** may be a colleague's computer: a curious student, or a machine that is
  itself compromised. It is personal data, so it is stored only as a pseudonym, with the address
  sealed under the daemon's vault key. `approve-source` refuses it. Revealing it needs the four-eyes
  re-identification of `refmon.pseudonym.Vault`: a request, two approvers who sign it, each use
  logged in a hash chain.
- Nothing blocks an address automatically. Source addresses can be spoofed, and an automatic
  network-wide block would let an attacker make you block your own partners.

## 5. Realism: not looking like a trap

Built in:
- **File times.** They are scattered over months, never shared, and every decoy was last read
  after it was last changed.
- **No giveaways.** Nothing in the decoy directory says "Refmon" or "decoy". The list of what was
  planted is in the proposal file in Refmon's own work directory.
- **Plausible contents.** Secrets look like what people really use (`Winter2024!`, a 40-character
  cloud key, a JWT-like token), host names use your own domain, and `.pgpass` has the 0600 mode
  `psql` insists on.
- **Decoy services.** They show only what you configure (banner, `Server` header, page) and answer
  after a random delay. A beacon image is answered at once, so the document looks normal.

Up to you:
- Put decoys where real secrets would be (project shares, deploy directories, home directories of
  service accounts), with names in the local language.
- Keep decoys **out of backups, indexers and antivirus scan paths**. In inotify mode Refmon cannot
  tell a backup from an intruder; with an attributing sensor, `ignore_roles` can.
- Pick decoy ports that make sense for the host (an "old" SSH on 2222, a file share UI on 8088). Do
  not put a decoy where a real service might later be started.

## 6. Deliberately not built (and why)

| Idea | Why not here |
|---|---|
| Disguising a VM (MAC vendor, CPU flags), fake desktops and browser history, synthetic user traffic | needs root and a separate honeypot host; it is honeypot engineering, not pipeline logic. A full honeypot can run its own Refmon with empty contracts and send its proposals here |
| A "dirty line" that lets intruders download real malware for inspection | the project never handles real malware (CLAUDE.md Part A) |
| Automatic network-wide IP blocking (SOAR "touch = block everywhere") | spoofable, and it breaks "nothing changes the policy without approval"; proposals plus one approval command instead |
| Tracking pixels to outside services | a beacon goes only to your own decoy listener |

## 7. Stronger with root: an attributing sensor

With root, a fanotify sensor knows which process opened a decoy. It sends the touch as an
`asset_access` event with a raw `path` (handed to Observe in memory). Observe matches the `file`
canary, and the story **blocks the opening process** (scenario S53), with `ignore_roles` sparing
the backup job (S56). The decoys and canaries stay the same; only the sensor changes.

## Manual checklist for the lab

1. Plant into a test directory and approve. `refmon health --json` shows no *decoy_unarmed*.
2. `nc 127.0.0.1 2222`: the banner appears slowly, the dashboard shows a blocked *Decoy service*
   story, and `refmon decoy sources` lists an internal pseudonym.
3. `cat` a planted file: a *Decoy file touched* notification appears within a second.
4. Fetch the board document's image path (`/assets/img/<token>.png`) from the decoy HTTP listener on `localhost:8088`: an image
   comes back at once and a block is recorded.
5. `grep -r` the work directory's `logs/` for the decoy secrets and the test addresses: nothing is
   found.
