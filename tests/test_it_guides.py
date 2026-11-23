"""The IT guides use only commands and options recorded in docs/it-facts.md (SEPAR_DOCS step 2)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FACTS = (ROOT / "docs" / "it-facts.md").read_text(encoding="utf-8")
GUIDES = ["guide.tex", "guide-de.tex"]


@pytest.mark.parametrize("name", GUIDES)
def test_guide_options_are_in_it_facts(name):
    text = (ROOT / "it-service-desk" / name).read_text(encoding="utf-8")
    flags = set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]+", text))
    assert flags, "no options found: the pattern is wrong"
    assert sorted(f for f in flags if f not in FACTS) == []


@pytest.mark.parametrize("name", GUIDES)
def test_guide_subcommands_are_in_it_facts(name):
    text = (ROOT / "it-service-desk" / name).read_text(encoding="utf-8")
    subs = set(re.findall(r"\bsepar ([a-z][a-z-]+)", text))
    assert subs
    assert sorted(s for s in subs if f"separ {s}" not in FACTS) == []


def test_guides_use_only_the_project_contact():
    for name in GUIDES:
        text = (ROOT / "it-service-desk" / name).read_text(encoding="utf-8")
        mails = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text))
        assert mails <= {"parsa@parsabe.com", "admin@example.org"}, name
