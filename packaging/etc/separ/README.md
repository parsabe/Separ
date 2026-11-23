# Separ Server Configuration Guide (TUBAF IT Service / URZ)

Separ operates as a behavioral reference monitor daemon on servers. It evaluates commands, logins, and process actions against behavioral contracts rather than static signatures.

## Quick Start for System Administrators

### 1. Verify Configuration Files
Configuration files live in `/etc/separ/`:
- **`ingest.yaml`**: Configures which sensors feed into Separ (Tetragon, SSH, Shibboleth, Dovecot).
- **`policy.yaml`**: University security policy (campus CIDR ranges, internal domains), signed.
- **`admin.pub`**: The admin's public key. The daemon verifies `policy.yaml` with it and refuses to
  start without both (run `sudo separ setup --server --campus-cidr CIDR` first). Both files must be root-owned 0644;
  the daemon refuses a policy or key that group/others can write.
- **`mappings/`**: Ready-to-use YAML mapping definitions for external sensors.

The **private** signing key is never on a server: `separ setup` creates it in the admin's
`~/.separ-admin/admin.key` (or `--key PATH`). Keep it on the admin's machine and copy only
`policy.yaml` and `admin.pub` to the servers. Changes are made there and then reloaded:
```bash
separ policy set-mode block --policy policy.yaml --key ~/.separ-admin/admin.key
separ policy sign --policy policy.yaml --key ~/.separ-admin/admin.key   # after editing
separ policy show --policy /etc/separ/policy.yaml                       # verify
sudo separ reload --workdir /var/lib/separ    # or: sudo systemctl reload separ
```
The daemon has no API to change its mode or sign anything; `separ reload` only makes it re-read
and verify the file.

### 2. Test Sensor Mappings Safely
Test your mapping against real log lines without leaking sensitive data into terminal history:
```bash
separ ingest check /etc/separ/mappings/sshd-journald.yaml --input /tmp/ssh-sample.jsonl --judge
```

### 3. Connect Sensors
Create Unix domain sockets and feed sensor streams:
```bash
# SSH Login stream:
journalctl -o json -f _COMM=sshd _COMM=sshd-session | socat - UNIX-CONNECT:/run/separ/sshd.sock

# Tetragon eBPF stream:
tetra getevents -o json | socat - UNIX-CONNECT:/run/separ/tetragon.sock
```

### 4. Containment: simulated until you enable it
By default the daemon decides and logs, but contains nothing (`separ health` says
`containment: simulated`). Add `--enforce` to `ExecStart` in `separ.service` (it needs root) to
make holds and blocks real: SIGSTOP/SIGKILL of the process tree (cgroup v2 freezer when the
process has its own cgroup), an nftables rule in table `inet separ` that cuts the process's
network (needs `nft` and cgroup v2), and a root-owned quarantine for files. Only processes whose
real pid a sensor reported (Tetragon, Falco) can be touched; without one the action is logged as
`unavailable`. Never PID 1, never Separ itself. `separ health` lists each action as available or
unavailable.

### 5. Enable and Start the System Service
```bash
systemctl daemon-reload
systemctl enable --now separ.service
```

Check service status and daemon health:
```bash
systemctl status separ.service
separ health
```
