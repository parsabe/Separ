"""Review 2026-11, item 14: the workspace watcher reports `new_file` truthfully and feeds only changes
to existing files to the mass-change detector, so unzip or git checkout is not ransomware."""

from __future__ import annotations

from tests.livehelp import make_barrier


def _signals(barrier, story_id):
    return {s.name for s in barrier.pipeline.judge(barrier.pipeline.record(story_id)).signals}


def _seed_files(barrier, n, folder="docs"):
    d = barrier.workspace_dir / folder
    d.mkdir(parents=True, exist_ok=True)
    files = [d / f"report-{i:03d}.txt" for i in range(n)]
    for f in files:
        f.write_text("quarterly figures\n")
    barrier.scan_sandbox_once()  # seen once: from now on they exist
    return files


def test_extracting_200_new_files_is_no_mass_change(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    tree = barrier.workspace_dir / "linux-6.1"
    for i in range(200):
        sub = tree / f"dir{i % 7}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"file{i}.c").write_text("int main(void) { return 0; }\n")
    incidents = barrier.scan_sandbox_once()
    assert incidents == [
        {"kind": "workspace_new_files", "files": 0, "new_files": 200, "story_id": None,
         "decision": "not_judged"}
    ]  # fmt: skip
    assert not any("mass_change" in s for sid in barrier.pipeline.linker.records
                   for s in _signals(barrier, sid))  # fmt: skip


def test_rewriting_60_existing_files_is_a_mass_change(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    files = _seed_files(barrier, 60)
    for f in files:
        f.write_text("ENCRYPTED " * 4)
    (inc,) = barrier.scan_sandbox_once()
    assert inc["kind"] == "workspace_write_batch" and inc["files"] == 60
    assert inc["new_files"] == 0 and inc["decision"] == "block"
    assert "effect_mass_change" in _signals(barrier, inc["story_id"])
    rec = barrier.pipeline.record(inc["story_id"])
    assert {e.attrs.get("new_file") for e in rec.events} == {False}  # truthful


def test_renaming_60_existing_files_is_a_mass_change(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    for f in _seed_files(barrier, 60):
        f.rename(f.with_name(f.name + ".locked"))
    (inc,) = barrier.scan_sandbox_once()
    assert inc["files"] == 60 and inc["new_files"] == 0
    assert "effect_mass_change" in _signals(barrier, inc["story_id"])


def test_encrypt_a_copy_then_delete_the_original_is_a_mass_change(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    for f in _seed_files(barrier, 60):
        f.with_suffix(".locked").write_bytes(b"\x00" * 32)
        f.unlink()
    (inc,) = barrier.scan_sandbox_once()
    assert inc["files"] == 60 and inc["new_files"] == 0
    assert "effect_mass_change" in _signals(barrier, inc["story_id"])


def test_a_few_rewrites_next_to_many_new_files_feed_only_the_rewrites(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    files = _seed_files(barrier, 3)
    for f in files:
        f.write_text("edited\n")
    for i in range(120):  # a checkout in another folder at the same time
        (barrier.workspace_dir / f"new{i}.py").write_text("x = 1\n")
    (inc,) = barrier.scan_sandbox_once()
    assert (inc["files"], inc["new_files"]) == (3, 120)
    assert "effect_mass_change" not in _signals(barrier, inc["story_id"])
    assert inc["decision"] == "allow"
