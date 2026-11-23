"""SEPAR_DOCS.md step 0.3: the paper's numbers come from one script, and they are the numbers of
docs/v2.4-evaluation.md and of the Attack Lab reference run."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def numbers(tmp_path_factory) -> dict[str, str]:
    out = tmp_path_factory.mktemp("paper") / "numbers.tex"
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "paper_numbers.py"), "--out", str(out)],
        capture_output=True, text=True, check=False, cwd=ROOT,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    text = out.read_text(encoding="utf-8")
    return dict(re.findall(r"\\newcommand\{\\(\w+)\}\{(.*?)\}(?:  %|$)", text, re.M))


def test_every_macro_is_defined_once_and_the_committed_file_is_current(numbers):
    committed = (ROOT / "documentation" / "numbers.tex").read_text(encoding="utf-8")
    names = re.findall(r"\\newcommand\{\\(\w+)\}", committed)
    assert len(names) == len(set(names))
    for name, value in numbers.items():
        if name.startswith(("Aud",)):
            continue  # the audit draws a fresh key: its counts are checked below
        assert f"\\newcommand{{\\{name}}}{{{value}}}" in committed, name


def test_the_totals_add_up(numbers):
    n = {k: int(v) for k, v in numbers.items() if re.fullmatch(r"-?\d+", v)}
    assert n["MalBlock"] + n["MalEffHold"] + n["MalHoldNothing"] + n["MalAllow"] == n["MalTotal"]
    assert n["MalContained"] == n["MalBlock"] + n["MalEffHold"]
    for g in ("Neutral", "Added", "AddedContract", "AddedEffect"):
        assert n[f"Ben{g}Allow"] + n[f"Ben{g}Hold"] + n[f"Ben{g}Block"] == n[f"Ben{g}Total"]
    assert n["BenAddedContractTotal"] + n["BenAddedEffectTotal"] == n["BenAddedTotal"]
    assert n["BenNeutralTotal"] + n["BenAddedTotal"] == n["BenTotal"]
    assert n["MalTotal"] + n["BenTotal"] == n["VarTotal"]
    for g in ("Web", "Typed"):
        assert n[f"Ctl{g}Allow"] + n[f"Ctl{g}Hold"] + n[f"Ctl{g}Block"] == n[f"Ctl{g}Total"]
    assert n["LabAblSilent"] + n["LabAblHeld"] + n["LabAblStill"] == n["LabScored"]
    assert n["LabAttacks"] + n["LabLimits"] == n["LabAttacksAll"]


def test_the_numbers_are_those_of_the_v2_4_evaluation(numbers):
    doc = (ROOT / "docs" / "v2.4-evaluation.md").read_text(encoding="utf-8")
    g = numbers.get
    assert f"**{g('Seed')}**" in doc
    assert f"| malicious ({g('MalTotal')}) |" in doc
    assert f"| block | {g('MalBlock')} | {g('MalBlock')} |" in doc
    assert f"| effective hold | {g('MalEffHold')} | {g('MalEffHold')} |" in doc
    assert (f"**{g('MalContained')} ({g('MalContainedPct')} %, [{g('MalContainedLo')}, "
            f"{g('MalContainedHi')}])**") in doc  # fmt: skip
    assert f"| allow | {g('MalAllow')} | {g('MalAllow')} |" in doc
    assert f"| hold that pauses nothing | {g('MalHoldNothing')} |" in doc
    neutral = f"{g('BenNeutralAllow')} / {g('BenNeutralHold')} / {g('BenNeutralBlock')}"
    assert f"| neutral ({g('BenNeutralTotal')}): allow / hold / block | {neutral} |" in doc
    con = (
        f"{g('BenAddedContractAllow')} / {g('BenAddedContractHold')} / {g('BenAddedContractBlock')}"
    )
    assert (
        f"adds a Contract violation ({g('BenAddedContractTotal')}): allow / hold / block | {con}"
        in doc
    )
    eff = f"{g('BenAddedEffectAllow')} / {g('BenAddedEffectHold')} / {g('BenAddedEffectBlock')}"
    assert f"adds an Effect ({g('BenAddedEffectTotal')}): allow / hold / block | {eff}" in doc
    assert f"**{g('GoldenOk')} of {g('GoldenTotal')}**" in doc
    web = f"{g('CtlWebAllow')} / {g('CtlWebHold')} / {g('CtlWebBlock')}"
    typed = f"{g('CtlTypedAllow')} / {g('CtlTypedHold')} / {g('CtlTypedBlock')}"
    assert f"(lab guard path) | {web} |" in doc
    assert f"typed network controls: allowed / held / blocked** | {typed} |" in doc
    assert f"| attacks detected (block or hold) | {g('LabDetected')}/{g('LabAttacks')} |" in doc
    assert g("LabAttacksAll") == "29" and g("LabDetected") == "28"  # the limit counts (SEPAR_DOCS)


def test_the_audit_numbers(numbers):
    assert numbers["AudPass"] == "PASS"
    assert numbers["AudRawFindings"] == "0" and numbers["AudReversals"] == "0"
    assert int(numbers["AudControl"]) > 0 and numbers["AudReidOk"] == "0"
