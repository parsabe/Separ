"""The browser extension and the Python side must agree (v2.1). No browser runs in CI, so this
checks the contract between them statically: names, kinds, actions, limits, privacy."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from refmon.browser_host import FIREFOX_EXTENSION_ID, FORWARDED_KINDS, HOST_NAME
from refmon.live import BROWSER_KINDS, BROWSER_MAX_TEXT, BROWSER_MAX_URL, browser_action
from refmon.schemas import Decision, Mode

EXT = Path(__file__).resolve().parent.parent / "browser" / "extension"
SCRIPTS = sorted(EXT.glob("*.js"))


def manifest() -> dict:
    return json.loads((EXT / "manifest.json").read_text())


def background() -> str:
    return (EXT / "background.js").read_text()


def test_manifest_is_mv3_and_names_the_firefox_id_the_host_allows():
    m = manifest()
    assert m["manifest_version"] == 3
    assert m["browser_specific_settings"]["gecko"]["id"] == FIREFOX_EXTENSION_ID
    assert "nativeMessaging" in m["permissions"]


def test_every_file_the_manifest_names_exists():
    m = manifest()
    names = {m["background"]["service_worker"], *m["background"]["scripts"]}
    names |= {js for cs in m["content_scripts"] for js in cs["js"]}
    names |= set(m["icons"].values()) | {
        m["action"]["default_icon"],
        m["storage"]["managed_schema"],
    }
    names |= {"offscreen.html", "offscreen.js", "blocked.html"}
    for name in names:
        assert (EXT / name).is_file(), name
    json.loads((EXT / "schema.json").read_text())


def test_the_page_world_hook_runs_first_in_every_frame():
    first = manifest()["content_scripts"][0]
    assert first["world"] == "MAIN" and first["run_at"] == "document_start" and first["all_frames"]


def test_the_extension_talks_to_the_host_by_its_name():
    assert f'"{HOST_NAME}"' in background()


def test_every_kind_the_extension_sends_is_one_the_host_forwards():
    sent = set(re.findall(r'kind:\s*"([a-z_]+)"', background()))
    assert sent, "no kinds found"
    assert sent <= FORWARDED_KINDS | {"ping"}
    assert set(BROWSER_KINDS) <= sent  # every observation kind is used


def test_every_action_the_daemon_can_return_is_handled():
    handled = set(re.findall(r'case\s+"([a-z_]+)"', background()))
    returned = {
        browser_action(mode, decision, kind)
        for mode in Mode
        for decision in Decision
        for kind in BROWSER_KINDS
    } - {"none"}
    assert returned <= handled


def test_the_limits_match_the_daemon():
    bg = background()
    assert f"slice(0, {BROWSER_MAX_TEXT})" in bg
    assert f"slice(0, {BROWSER_MAX_URL})" in bg


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_no_script_talks_to_the_network_or_stores_content(path):
    src = path.read_text()
    for banned in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage",
                   "storage.local", "storage.sync", "indexedDB", "console.log"):  # fmt: skip
        assert banned not in src, f"{path.name}: {banned}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_scripts_parse(path):
    esprima = pytest.importorskip("esprima")  # optional: not a project dependency
    esprima.parseScript(path.read_text())
