# Separ Server Configuration Guide (TUBAF IT Service / URZ)

Separ operates as a behavioral reference monitor daemon on servers. It evaluates commands, logins, and process actions against behavioral contracts rather than static signatures.

## Quick Start for System Administrators

### 1. Verify Configuration Files
Configuration files live in `/etc/separ/`:
- **`ingest.yaml`**: Configures which sensors feed into Separ (Tetragon, SSH, Shibboleth, Dovecot).
- **`policy.yaml`**: University security policy (campus CIDR ranges, internal domains).
- **`mappings/`**: Ready-to-use YAML mapping definitions for external sensors.

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

### 4. Enable and Start the System Service
```bash
systemctl daemon-reload
systemctl enable --now separ.service
```

Check service status and daemon health:
```bash
systemctl status separ.service
separ health
```
