"""Record the Attack Lab reference run of the current version, for the paper and the docs.

    python scripts/lab_reference_run.py --out docs/evaluation/lab-reference-run-v2.4.json

Mode block, default policy. The 35 attack, benign and known-limit templates run in one lab, as
`separ lab --test-all` runs them. The recorded controls (review 2026-11, item 12) run in a fresh lab
per group: typing the very text a page just pasted inherits that page's label (propagation rule 3),
which is correct but would not measure "typed". Allowed commands really run in the lab sandbox, as
in `--test-all`. Command text, paths and output are left out of the record (the template id names
the command; `src/refmon/attacklab.py` has the text).
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import refmon  # noqa: E402
from refmon import attacklab as al  # noqa: E402
from refmon import labreport  # noqa: E402

DROP = {"seq", "ts", "command", "output", "explanation", "watcher", "story_id", "outcome", "mode"}


def run_group(templates: list, tmp: Path) -> tuple[list[dict], al.AttackLab]:
    lab = al.AttackLab(tmp / "lab", out=io.StringIO(), color=False)
    numbers = {t.id: n for n, t in enumerate(al._ordered(), start=1)}
    for t in templates:
        lab.run_template(t)
    rows = []
    for r, rec in zip(lab.results, lab.records(), strict=True):
        row = {k: v for k, v in asdict(rec).items() if k not in DROP}
        row["template_number"] = numbers.get(r.template_id)
        row["group"] = r.group
        row["kind"] = r.expect  # stop | allow | miss | control
        rows.append(row)
    return rows, lab


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    ordered = al._ordered()
    groups = [
        [t for t in ordered if t.expect != "control"],
        [t for t in ordered if t.group == al.G_CTRL_WEB],
        [t for t in ordered if t.group == al.G_CTRL_TYPED],
    ]
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="separ-lab-ref-") as name:
        for i, templates in enumerate(groups):
            rows, lab = run_group(templates, Path(name) / f"g{i}")
            results += rows
            if i == 0:
                first = lab
    m = first.barrier.policy.math
    meta = {
        "refmon_version": refmon.__version__,
        "git_commit": _commit(),
        "policy_mode": first.mode,
        **first.thresholds(),
        "decision_rule": m.decision_rule,
        "origin_combination": m.origin_combination,
        "weights": dict(m.weights),
        "policy_digest": first.barrier.policy_digest[:16],
        "groups": "templates in one lab; each control group in a fresh lab",
    }
    doc = {
        "source": "scripts/lab_reference_run.py (mode=block); command text, paths and output "
        "left out",
        "meta": meta,
        "summary": labreport.summary([labreport.Record(**_full(r)) for r in results]),
        "results": results,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"{len(results)} results written to {args.out}")
    return 0


def _commit() -> str:
    """HEAD, marked when tracked files differ from it (untracked files, such as this run's own
    output, do not count)."""
    import subprocess

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True,
                              check=True).stdout.strip()  # fmt: skip

    dirty = git("status", "--porcelain", "--untracked-files=no")
    return git("rev-parse", "--short", "HEAD") + ("+uncommitted-changes" if dirty else "")


def _full(row: dict) -> dict:
    """A Record again (for labreport.summary), with the dropped fields empty."""
    fields = labreport.Record.__dataclass_fields__
    return {
        k: row.get(k, [] if k == "watcher" else 0 if k == "seq" else "")
        for k in fields
        if k in row or k in DROP
    }


if __name__ == "__main__":
    raise SystemExit(main())
