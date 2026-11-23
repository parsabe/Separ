"""Regenerate the command-line part of docs/it-facts.md: the exact `--help` of every command the
IT guide and the paper may name (SEPAR_DOCS.md step 0.1). The guides may only use commands and
flags that appear here.

    python scripts/it_facts.py > docs/it-facts-cli.md    # or: --check docs/it-facts.md

The output is deterministic (COLUMNS=100, the program name `separ`).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COMMANDS = [
    ["--version"],
    ["setup", "--help"],
    ["policy", "--help"],
    ["policy", "show", "--help"],
    ["policy", "sign", "--help"],
    ["policy", "set-mode", "--help"],
    ["reload", "--help"],
    ["serve", "--help"],
    ["gui", "--help"],
    ["health", "--help"],
    ["scan-rootkit", "--help"],
    ["browser-install", "--help"],
    ["ingest", "--help"],
    ["ingest", "list", "--help"],
    ["ingest", "check", "--help"],
    ["guard", "--help"],
    ["decoy", "--help"],
    ["audit", "--help"],
    ["keygen", "--help"],
    ["verify", "--help"],
]


def run(args: list[str]) -> str:
    env = {**os.environ, "COLUMNS": "100", "NO_COLOR": "1"}
    code = (
        "import sys; sys.argv[0] = 'separ'; from refmon.cli import main; "
        "raise SystemExit(main(sys.argv[1:]))"
    )
    done = subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=False,
    )
    return (done.stdout + done.stderr).rstrip() + "\n"


def render() -> str:
    out = []
    for args in COMMANDS:
        out += [f"### `separ {' '.join(args)}`", "", "```text", run(args).rstrip(), "```", ""]
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", help="fail if this file does not contain the current output")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        if text not in Path(args.check).read_text(encoding="utf-8"):
            print(f"{args.check} is out of date: run scripts/it_facts.py", file=sys.stderr)
            return 1
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
