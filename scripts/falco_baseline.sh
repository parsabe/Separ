#!/usr/bin/env bash
# Measured Falco baseline on the Attack Lab templates (see scripts/falco_baseline.py).
#
# Needs Falco installed with no service (modern eBPF needs no kernel headers):
#   curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
#     sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
#   echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
#     sudo tee /etc/apt/sources.list.d/falcosecurity.list
#   sudo apt-get update
#   sudo FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=none FALCOCTL_ENABLED=no apt-get install -y falco
#
# Then, from the repository root, in a normal terminal (not inside a sandbox):
#   sudo scripts/falco_baseline.sh
#
# Two passes, each with a fresh lab: Falco's default (stable) rules, then stable + incubating +
# sandbox rules. Falco runs only while the templates run and is stopped afterwards; no service
# is enabled. The templates themselves run as the invoking user, never as root.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
U=${SUDO_USER:?run through sudo from your own account}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/.falco-baseline
PY=$ROOT/.venv/bin/python
command -v falco >/dev/null || { echo "falco is not installed (see the header of $0)" >&2; exit 1; }
[ -x "$PY" ] || { echo "no virtual environment at $ROOT/.venv" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT/rules"
STABLE=/etc/falco/falco_rules.yaml

echo "== fetching the incubating and sandbox rules (falcoctl)"
EXTRA=()
if falcoctl artifact install falco-incubating-rules falco-sandbox-rules \
     --rulesfiles-dir "$OUT/rules" --resolve-deps=false >"$OUT/falcoctl.log" 2>&1; then
  for f in "$OUT"/rules/falco-incubating_rules.yaml "$OUT"/rules/falco-sandbox_rules.yaml; do
    [ -f "$f" ] && EXTRA+=("$f")
  done
fi
# keep only the extra files Falco accepts together with the stable rules
ALL=("$STABLE")
for f in "${EXTRA[@]}"; do
  args=(); for g in "${ALL[@]}" "$f"; do args+=(-V "$g"); done
  if falco "${args[@]}" >>"$OUT/validate.log" 2>&1; then
    ALL+=("$f")
  else
    echo "   rejected by this Falco: $(basename "$f") (see $OUT/validate.log)"
  fi
done
echo "   rules of the second pass: $(printf '%s ' "${ALL[@]##*/}")"

write_config() {  # $1 = pass name, rest = rules files
  local pass=$1; shift
  "$PY" - "$OUT/falco-$pass.yaml" "$OUT/alerts-$pass.jsonl" "$@" <<'EOF'
import sys, yaml
cfg = yaml.safe_load(open("/etc/falco/falco.yaml"))
out, alerts, rules = sys.argv[1], sys.argv[2], sys.argv[3:]
cfg.update({
    # config_files and load_plugins stay as installed: the default rules need the container
    # plugin that /etc/falco/config.d loads (Falco >= 0.41), even on a host without containers
    "rules_files": rules, "priority": "debug",
    "json_output": True, "json_include_output_property": True,
    "stdout_output": {"enabled": False},
    "file_output": {"enabled": True, "keep_alive": True, "filename": alerts},
    "append_output": [{"suggested_output": True},
                      {"match": {"source": "syscall"},
                       "extra_fields": ["proc.sid", "proc.pid", "proc.ppid"]}],
    "webserver": {"enabled": False},
})
cfg.setdefault("engine", {})["kind"] = "modern_ebpf"
if isinstance(cfg.get("metrics"), dict):
    cfg["metrics"]["enabled"] = False
yaml.safe_dump(cfg, open(out, "w"), sort_keys=False)
EOF
}

run_pass() {  # $1 = pass name, rest = rules files
  local pass=$1; shift
  write_config "$pass" "$@"
  echo "== pass '$pass': starting Falco"
  falco -c "$OUT/falco-$pass.yaml" >"$OUT/falco-$pass.log" 2>&1 &
  local fpid=$!
  # positive control: Falco's stable rule "Read sensitive file untrusted" must see this
  local ok=0
  for _ in $(seq 1 30); do
    setsid cat /etc/shadow >/dev/null 2>&1 || true
    sleep 2
    if grep -q '/etc/shadow' "$OUT/alerts-$pass.jsonl" 2>/dev/null; then ok=1; break; fi
    kill -0 "$fpid" 2>/dev/null || break
  done
  if [ "$ok" != 1 ]; then
    echo "Falco raised no alert on the positive control; see $OUT/falco-$pass.log" >&2
    kill -INT "$fpid" 2>/dev/null || true; wait "$fpid" 2>/dev/null || true
    exit 1
  fi
  echo "   Falco is watching (positive control seen); running the templates as $U"
  chown -R "$U" "$OUT"
  sudo -u "$U" "$PY" "$ROOT/scripts/falco_baseline.py" run --out "$OUT/runs-$pass.json"
  sleep 5
  kill -INT "$fpid"; wait "$fpid" 2>/dev/null || true
}

"$PY" - "$OUT/meta.json" "${ALL[@]}" <<'EOF'
import json, platform, subprocess, sys, hashlib, pathlib
v = subprocess.run(["falco", "--version"], capture_output=True, text=True).stdout.splitlines()
files = {pathlib.Path(p).name: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()[:16]
         for p in sys.argv[2:]}
json.dump({"falco_version": v[0] if v else "unknown", "engine": "modern_ebpf",
           "kernel": platform.release(), "rules_sha256_16": files,
           "templates_run_as": "the invoking user, lab sandbox, 5 s timeout"},
          open(sys.argv[1], "w"), indent=1)
EOF

run_pass stable "$STABLE"
run_pass all "${ALL[@]}"

chown -R "$U" "$OUT"
sudo -u "$U" "$PY" "$ROOT/scripts/falco_baseline.py" analyse --dir "$OUT" \
  --out "$ROOT/docs/evaluation/falco-baseline-v2.4.json"
echo "== done: docs/evaluation/falco-baseline-v2.4.json (raw alerts stay in $OUT)"
