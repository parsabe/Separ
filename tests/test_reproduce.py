"""The reproduction and publishability scripts: the pieces that can be tested without replaying
everything. `make reproduce` itself is the end-to-end test and is run by hand and in the release
check."""

import re
import sys

import pytest

from scenario_run import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import check_publishable as cp
import reproduce as rp

BLOCKS = ["versions", "matrix", "stats", "golden", "coverage", "audit", "publishable", "tests"]


def test_every_generated_block_of_the_results_file_exists_once_and_is_closed():
    text = (ROOT / "docs" / "results.md").read_text()
    for name in BLOCKS:
        assert len(re.findall(rf"<!-- BEGIN GENERATED: {name} -->", text)) == 1, name
        assert len(re.findall(rf"<!-- END GENERATED: {name} -->", text)) == 1, name
    found = set(re.findall(r"<!-- BEGIN GENERATED: (\w+) -->", text))
    assert found == set(BLOCKS)


def test_replace_block_rewrites_only_its_block():
    text = "a\n<!-- BEGIN GENERATED: x -->\nold\n<!-- END GENERATED: x -->\nb\n"
    out = rp.replace_block(text, "x", "new\nlines")
    assert out == "a\n<!-- BEGIN GENERATED: x -->\nnew\nlines\n<!-- END GENERATED: x -->\nb\n"
    assert rp.replace_block(out, "x", "new\nlines") == out  # idempotent
    with pytest.raises(SystemExit):
        rp.replace_block(text, "missing", "z")


def test_the_tags_the_reproduction_needs_exist():
    import subprocess

    tags = subprocess.run(
        ["git", "-C", str(ROOT), "tag", "-l"], capture_output=True, text=True, check=True
    ).stdout.split()
    assert set(rp.TAGS) <= set(tags)


def test_the_active_seed_names_the_versions_it_evaluates():
    from refmon import variants

    assert list(rp.SEED_VERSIONS[variants.SEED]) == rp.TAGS
    assert all(tag in rp.NOTES for tag in rp.TAGS)
    with pytest.raises(SystemExit, match="no recorded versions"):
        rp.versions_for(1)


def test_a_tree_without_the_package_is_refused(tmp_path):
    """Before: the replay of such a tag silently imported the installed, current code."""
    (tmp_path / "LICENSE").write_text("x")
    with pytest.raises(SystemExit, match="holds no src/refmon"):
        rp.check_tree("v-empty", tmp_path)


def test_a_tree_that_would_import_other_code_is_refused(tmp_path):
    pkg = tmp_path / "src" / "refmon"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("raise ImportError('broken on purpose')\n")
    with pytest.raises(SystemExit, match="would import"):
        rp.check_tree("v-broken", tmp_path)


def test_every_tag_the_reproduction_uses_holds_its_code(tmp_path):
    for tag in rp.TAGS:
        rp.extract(tag, tmp_path / tag)  # raises when the tag holds no Refmon


def test_comparison_pairs():
    assert rp.comparison_pairs(["a", "b"]) == [("a", "b")]
    assert rp.comparison_pairs(["a", "b", "c"]) == [("a", "c"), ("a", "b"), ("b", "c")]


def findings(line):
    return cp.line_findings(line, {"labhost"})


def test_the_publishability_check_finds_what_it_should():
    assert findings("key = '-----BEGIN RSA PRIVATE KEY-----'")
    assert findings("aws AKIAABCDEFGHIJKLMNOP here")
    assert findings('password = "hunter2hunter2hunter2"')
    assert any("e-mail" in f for f in findings("write to someone@gmail.com"))
    assert any("home path" in f for f in findings("see /home/alice/projects"))
    assert any("public IP" in f for f in findings("connect 8.8.8.8"))
    assert any("url" in f for f in findings("fetch https://evil.org/x"))
    assert any("name of this machine" in f for f in findings("ssh labhost"))


def test_the_publishability_check_leaves_synthetic_data_alone():
    for line in (
        "bob@corp.example",
        "connect 10.1.2.3 and 192.168.0.9 and 203.0.113.5",
        "see https://pypi.org/project/x and http://x.invalid/a",
        'secret = "zz-secret-command-zz"',
        "plain prose with no data",
    ):
        assert findings(line) == [], line


def test_badges_and_the_project_repository_are_allowed_and_nothing_more():
    """Round 2, A2: img.shields.io badges and github.com/parsabe are publishable; a URL that only
    contains those strings, and every other host, is still reported."""
    assert findings("[![v](https://img.shields.io/badge/Version-2.4.0-0f766e)](docs/x.md)") == []
    assert findings("see https://github.com/parsabe/Separ/releases/download/v2.4/x.deb") == []
    assert any("url" in f for f in findings("https://evil.org/?u=img.shields.io/badge/x"))
    assert any("url" in f for f in findings("https://img.shields.io.evil.org/badge/x"))
    assert any("url" in f for f in findings("https://evil.org/github.com/parsabe/x"))
    assert any("url" in f for f in findings("https://img.shields.io/endpoint?url=x"))
    assert any("url" in f for f in findings("https://lwn.net/Articles/1/"))  # not on any list


def test_the_owner_decisions_of_round_2_and_nothing_more():
    """README reference hosts (anchored), the one project contact, example addresses; the paper is
    skipped like ruff skips it; a report quoting a finding is not a finding again."""
    for line in (
        "https://docs.pydantic.dev/latest/", "https://www.keycloak.org/", "https://falco.org/docs",
        "https://hypothesis.readthedocs.io/en/latest/", "https://docs.astral.sh/ruff/",
        "write to parsa@parsabe.com", "mail -s alert admin@example.org",
    ):  # fmt: skip
        assert findings(line) == [], line
    for line in (
        "https://evil.org/?next=https://falco.org/", "https://falco.org.evil.org/x",
        "https://docs.pydantic.dev.evil.org/", "write to someone@parsabe.com",
        "write to parsa@parsabe.com.evil.org", "https://notpython.org/",
    ):  # fmt: skip
        assert findings(line), line
    assert cp.SKIPPED_DIRS == ("documentation/",)
    reported = findings("connect 8.8.8.8")
    assert reported == ["public IP 8.8.x.x"] and findings(reported[0]) == []
    assert findings(f"  {reported[0]}") == []


def test_the_repository_itself_has_no_content_findings():
    names = cp.own_names()
    assert cp.scan_tree(names) == []
    count, bad = cp.scan_events()
    assert count > 300 and bad == []


def test_identities_are_masked_in_the_output_that_goes_into_the_results_file():
    masked = cp.mask("Jane Doe <jane.doe@university.edu>")
    assert "jane" not in masked.lower() and "university" not in masked and "@" in masked
    assert cp.mask("x <y@z.org>").endswith(".org>")


def test_the_results_file_holds_no_e_mail_address_at_all():
    text = (ROOT / "docs" / "results.md").read_text()
    assert not cp.EMAIL.search(text)


def test_a_missing_tag_is_named_and_the_run_stops(capsys, monkeypatch):
    """Review 2026-11, Part 3: from a fresh clone without tags, reproduce.py says which tag is
    missing and exits non-zero, before it extracts anything."""
    monkeypatch.setattr(rp, "TAGS", ["v0.0-never-tagged", *rp.TAGS])
    with pytest.raises(SystemExit) as stop:
        rp.main(["--skip-tests"])
    assert stop.value.code == 2
    err = capsys.readouterr().err
    assert "v0.0-never-tagged" in err and "git fetch --tags" in err
    assert "v0.0-never-tagged" in rp.missing_tags(rp.TAGS)


def test_dump_matrix_can_replay_with_a_policy_flag(tmp_path):
    import dump_matrix

    policy = dump_matrix.with_settings(["math.decision_rule=expected_cost",
                                        "math.origin_combination=noisy_or"])  # fmt: skip
    assert policy.math.decision_rule == "expected_cost"
    assert policy.math.origin_combination == "noisy_or"


def _repo(tmp_path, monkeypatch, *, new_line: str):
    """A repository whose published commit (origin/master) has a finding, plus one new commit."""
    import subprocess

    def g(*args):
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@x.test",
                        *args], check=True, capture_output=True)  # fmt: skip

    g("init", "-q", "-b", "main")
    (tmp_path / "a.txt").write_text("connect 8.8.8.8\n")
    g("add", "a.txt")
    g("commit", "-q", "-m", "published")
    g("update-ref", "refs/remotes/origin/master", "HEAD")
    (tmp_path / "b.txt").write_text(new_line + "\n")
    g("add", "b.txt")
    g("commit", "-q", "-m", "new")
    monkeypatch.setattr(cp, "ROOT", tmp_path)
    monkeypatch.setattr(cp, "scan_tree", lambda names: [])
    monkeypatch.setattr(cp, "scan_events", lambda: (0, []))
    monkeypatch.setattr(cp, "identities", lambda: set())
    return g


def test_a_finding_in_a_new_commit_fails(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, new_line="mail someone@gmail.com")
    new, published, base = cp.history_findings(set())
    assert base and len(new) == 1 and "e-mail" in new[0]
    assert len(published) == 1 and "public IP 8.8.x.x" in published[0]
    assert cp.main([]) == 1
    out = capsys.readouterr().out
    assert "findings in new commits (not on origin/master; failing): 1" in out
    assert "already published on origin/master (reported, not failing): 1" in out


def test_a_finding_only_in_published_history_does_not_fail(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, new_line="plain prose")
    new, published, _ = cp.history_findings(set())
    assert new == [] and len(published) == 1
    assert cp.main([]) == 0
    assert "content: CLEAN" in capsys.readouterr().out


def test_without_the_published_ref_every_commit_counts_as_new(tmp_path, monkeypatch):
    g = _repo(tmp_path, monkeypatch, new_line="plain prose")
    g("update-ref", "-d", "refs/remotes/origin/master")
    new, published, base = cp.history_findings(set())
    assert not base and published == [] and any("8.8.x.x" in f for f in new)
    assert cp.main([]) == 1
