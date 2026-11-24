"""Measured Falco baseline on the Attack Lab templates (paper, Evaluation: "A Falco baseline").

Falco judges system calls, so it can only judge what really runs. This script runs every lab
template that the lab itself may run (the 22 runnable attack stand-ins and the 6 benign commands)
in the same sandbox the Attack Lab uses (cwd = the lab workspace, HOME = the fake home, 5 s
timeout), each in its own session, while Falco watches. Falco's alerts are then attributed to a
template by the session id (`proc.sid`) and joined with Separ's recorded verdicts
(docs/evaluation/lab-reference-run-v2.4.json). Templates marked `never_run` (they would touch the
real system) and the recorded controls are not run and are reported as not measured.

Started by scripts/falco_baseline.sh (which runs Falco as root); the two steps here run as the user:

    python scripts/falco_baseline.py run --out <dir>/runs-<pass>.json
    python scripts/falco_baseline.py analyse --dir <dir> \
        --out docs/evaluation/falco-baseline-v2.4.json

Only template ids, rule names and priorities are written to the committed file; Falco's raw alerts
(command lines, paths) stay in <dir>, which git ignores.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from refmon import attacklab as al  # noqa: E402

REFERENCE = ROOT / "docs" / "evaluation" / "lab-reference-run-v2.4.json"
PASSES = ("stable", "all")  # Falco's default rules; stable + incubating + sandbox
GAP_S = 1.5  # quiet time between two templates

WEB_SHELL = (
    "import pathlib,sys;u=pathlib.Path(sys.argv[1])/'uploads';u.mkdir(exist_ok=True);"
    "(u/'cmd_falco.php').write_text("
    "\"<?php /* refmon lab stand-in, does nothing */ echo 'lab'; ?>\\n\")"
)
RANSOM = (
    "import os,pathlib,sys;b=pathlib.Path(sys.argv[1])/'docs'/'burst'\n"
    "b.mkdir(parents=True,exist_ok=True)\n"
    "docs=[b/f'file-{i:02d}.txt' for i in range(60)]\n"
    "[d.write_text('lab document\\n') for d in docs]\n"
    "for d in docs:\n d.with_name(d.name+'.locked').write_bytes(os.urandom(64)); d.unlink()"
)


def _spawn(argv_or_cmd, *, shell: bool, cwd: Path, env: dict) -> dict:
    t0 = datetime.now(UTC).isoformat(timespec="milliseconds")
    p = subprocess.Popen(
        argv_or_cmd, shell=shell, cwd=str(cwd), env=env, start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        code = p.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        code = "timeout"
    return {"sid": p.pid, "start": t0, "end": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "exit": code}  # fmt: skip


def run(out: Path) -> int:
    """Run every runnable template once, as the lab would run it, and record its session id."""
    rows = []
    with tempfile.TemporaryDirectory(prefix="separ-falco-") as name:
        lab = al.AttackLab(Path(name) / "lab", out=io.StringIO(), color=False)
        ws, web_root = lab.barrier.workspace_dir, lab.barrier.web_root_dir
        env = dict(os.environ, HOME=str(lab.home), HISTFILE=str(lab.home / ".bash_history"))
        for n, t in enumerate(al._ordered(), start=1):
            row = {"template_number": n, "template_id": t.id, "kind": t.expect}
            if t.never_run or t.expect == "control":
                row["ran"] = False
            elif t.kind == "webshell_drop":
                row |= {"ran": True, **_spawn([sys.executable, "-c", WEB_SHELL, str(web_root)],
                                              shell=False, cwd=ws, env=env)}  # fmt: skip
            elif t.kind == "ransomware_burst":
                row |= {"ran": True, **_spawn([sys.executable, "-c", RANSOM, str(ws)],
                                              shell=False, cwd=ws, env=env)}  # fmt: skip
            else:
                row |= {"ran": True, **_spawn(t.command, shell=True, cwd=ws, env=env)}
            rows.append(row)
            if row["ran"]:
                time.sleep(GAP_S)
    out.write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    print(f"{sum(r['ran'] for r in rows)} of {len(rows)} templates run; written to {out}")
    return 0


def _alerts(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            with contextlib.suppress(json.JSONDecodeError):
                out.append(json.loads(line))
    return out


def analyse(d: Path, out: Path) -> int:
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))["results"]
    ref = {r["template_id"]: r for r in reference}
    meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
    per: dict[str, dict] = {}
    passes = {}
    for p in PASSES:
        runs_path = d / f"runs-{p}.json"
        if not runs_path.exists():
            continue
        runs = json.loads(runs_path.read_text(encoding="utf-8"))
        by_sid = {r["sid"]: r["template_id"] for r in runs if r.get("ran")}
        alerts = _alerts(d / f"alerts-{p}.jsonl")
        hits: dict[str, list[dict]] = {}
        control = outside = 0
        for a in alerts:
            f = a.get("output_fields", {})
            tid = by_sid.get(f.get("proc.sid"))
            if tid is not None:
                hit = {"rule": a.get("rule"), "priority": a.get("priority")}
                hits.setdefault(tid, []).append(hit)
            elif f.get("fd.name") == "/etc/shadow" and f.get("proc.name") == "cat":
                control += 1
            else:
                outside += 1
        passes[p] = {"alerts_total": len(alerts), "positive_control_alerts": control,
                     "alerts_outside_the_templates": outside}  # fmt: skip
        for r in runs:
            row = per.setdefault(r["template_id"], {
                "template_number": r["template_number"], "template_id": r["template_id"],
                "kind": r["kind"], "ran": r["ran"],
                "separ_decision": ref.get(r["template_id"], {}).get("decision"),
            })  # fmt: skip
            if r["ran"]:
                rules = sorted({(h["rule"], h["priority"]) for h in hits.get(r["template_id"], [])})
                row[f"falco_{p}"] = [{"rule": a, "priority": b} for a, b in rules]
                row[f"exit_{p}"] = r.get("exit")
    doc = {
        "source": "scripts/falco_baseline.py with scripts/falco_baseline.sh; rule names and "
        "priorities only, Falco's raw alerts are not committed",
        "meta": meta | {"passes": passes, "separ_reference": REFERENCE.name},
        "results": sorted(per.values(), key=lambda r: r["template_number"]),
    }
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(summary(doc))
    return 0


def summary(doc: dict) -> str:
    res = doc["results"]
    lines = []
    for p in PASSES:
        key = f"falco_{p}"
        ran = [r for r in res if r["ran"] and key in r]
        if not ran:
            continue
        att = [r for r in ran if r["kind"] in ("stop", "miss")]
        ben = [r for r in ran if r["kind"] == "allow"]
        lines.append(
            f"[{p}] attacks run {len(att)}: Falco alerted on {sum(bool(r[key]) for r in att)}, "
            f"Separ held or blocked {sum(r['separ_decision'] in ('block', 'hold') for r in att)}; "
            f"benign run {len(ben)}: Falco alerted on {sum(bool(r[key]) for r in ben)}, Separ "
            f"held or blocked {sum(r['separ_decision'] in ('block', 'hold') for r in ben)}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", required=True, type=Path)
    a = sub.add_parser("analyse")
    a.add_argument("--dir", required=True, type=Path)
    a.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    return run(args.out) if args.cmd == "run" else analyse(args.dir, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
