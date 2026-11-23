"""Review 2026-11, item 17: rootkit scanner coverage, on fake /proc trees.

Kernel modules are compared in every direction (sysfs, /proc/modules, /proc/kallsyms), each
discrepancy its own kind; hidden PIDs are found by a read-only os.stat sweep; the transient
discrepancy rate p_race is measured (`separ scan-rootkit --calibrate N`) instead of assumed.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.test_rootkit import _cfg, _make_clean_tree

from refmon.cli import main as cli_main
from refmon.keys import LAB_REPLAY_KEY
from refmon.rootkit import (
    CALIBRATION_FILE,
    SCANNER_WEIGHTS,
    RootkitScanner,
    calibrate,
    crossview_nats,
    evaluate_rootkit_scan,
    format_scan_report,
    load_calibration,
)


def _kinds(report):
    return sorted(f.kind for f in report.findings)


def _hide_from_readdir(proc: Path, *names: str):
    real = Path.iterdir

    def hooked(self):
        for item in real(self):
            if self == proc and item.name in names:
                continue  # a getdents hook hides these from readdir("/proc")
            yield item

    return patch.object(Path, "iterdir", hooked)


def test_clean_tree_with_kallsyms_is_clean(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "kallsyms").write_text(
        "0000000000000000 t ext4_fill_super\t[ext4]\n"
        "0000000000000000 t nv_open\t[nvidia]\n"
        "0000000000000000 t bpf_prog_6deef7357e7b4530\t[bpf]\n"
        "0000000000000000 t ftrace_trampoline\t[__builtin__ftrace]\n"
        "0000000000000000 T start_kernel\n"
    )
    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    assert report.findings == ()


def test_a_module_listed_but_without_its_sysfs_entry_is_its_own_kind(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "modules").write_text(
        "ext4 900000 1 - Live 0x0\nnvidia 50000000 4 - Live 0x0\nghost 16384 0 - Live 0x0\n"
    )
    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    assert _kinds(report) == ["module_missing_from_sysfs"]
    assert report.calculus_decision.value == "block"
    assert "ghost" not in format_scan_report(report)


def test_a_module_seen_only_in_kallsyms_is_its_own_kind(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "kallsyms").write_text(
        "0000000000000000 t ext4_fill_super\t[ext4]\n"
        "0000000000000000 t hook_getdents64\t[reptile]\n"
    )
    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    assert _kinds(report) == ["module_only_in_kallsyms"]


def test_every_direction_is_reported_separately_with_the_existing_weight(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (sys_ / "module" / "diamorphine").mkdir()
    (sys_ / "module" / "diamorphine" / "initstate").write_text("live\n")
    (proc / "modules").write_text(
        "ext4 900000 1 - Live 0x0\nnvidia 50000000 4 - Live 0x0\nghost 16384 0 - Live 0x0\n"
    )
    (proc / "kallsyms").write_text("0000000000000000 t x\t[reptile]\n")
    report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    assert _kinds(report) == [
        "hidden_kernel_module", "module_missing_from_sysfs", "module_only_in_kallsyms",
    ]  # fmt: skip
    assert {f.nats for f in report.findings} == {
        max(SCANNER_WEIGHTS["hidden_kernel_module"], crossview_nats(2, 1e-3, 8.0))
    }


def test_unreadable_kallsyms_raises_nothing(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)  # no kallsyms file at all
    scanner = RootkitScanner(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    views, _ = scanner._snapshot_hidden_modules()
    assert "module_only_in_kallsyms" not in views  # missing information is not evidence


def _hidden_leader_tree(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    (proc / "sys" / "kernel" / "pid_max").write_text("5000\n")
    leader = proc / "4242"
    leader.mkdir()
    (leader / "status").write_text("Name:\trk\nTgid:\t4242\nPid:\t4242\nPPid:\t1\n")
    thread = proc / "101"  # a thread of the visible process 100: on direct lookup, not in readdir
    thread.mkdir()
    (thread / "status").write_text("Name:\tpython3\nTgid:\t100\nPid:\t101\nPPid:\t1\n")
    return proc, sys_, etc


def test_the_sweep_finds_a_hidden_process_nobody_references(tmp_path):
    proc, sys_, etc = _hidden_leader_tree(tmp_path)
    with _hide_from_readdir(proc, "4242", "101"):
        report, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
        without, _ = evaluate_rootkit_scan(_cfg(proc, sys_, etc, pid_sweep="off"),
                                           key=LAB_REPLAY_KEY)  # fmt: skip
    hidden = [f for f in report.findings if f.kind == "hidden_pid_discrepancy"]
    assert len(hidden) == 1  # the leader 4242; the thread 101 is not a process
    assert report.calculus_decision.value == "block"
    assert [f for f in without.findings if f.kind == "hidden_pid_discrepancy"] == []


def test_the_sweep_is_read_only_and_two_passes_remove_churn(tmp_path):
    proc, sys_, etc = _hidden_leader_tree(tmp_path)
    scanner = RootkitScanner(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    with patch.object(os, "kill", side_effect=AssertionError("no signal may be sent")):
        snapshots = [{4242}, set()]  # seen in one pass only: a process that started and ended
        with patch.object(scanner, "_snapshot_hidden_pids", side_effect=snapshots):
            findings, *_ = scanner.scan()
    assert [f for f in findings if f.kind == "hidden_pid_discrepancy"] == []


def test_the_sweep_limit(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    kernel = proc / "sys" / "kernel"
    (kernel / "pid_max").write_text("4194304\n")
    (kernel / "ns_last_pid").write_text("7000\n")
    full = RootkitScanner(_cfg(proc, sys_, etc), key=LAB_REPLAY_KEY)
    bounded = RootkitScanner(_cfg(proc, sys_, etc, pid_sweep="bounded"), key=LAB_REPLAY_KEY)
    assert full._sweep_limit({100}) == 4194304
    assert bounded._sweep_limit({100}) == 7000 + 1024
    assert bounded._sweep_limit({9000}) == 9000 + 1024


def test_calibration_measures_p_race_with_laplace_smoothing(tmp_path):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    clean = calibrate(_cfg(proc, sys_, etc), 10, key=LAB_REPLAY_KEY)
    assert clean["race_prob"] == pytest.approx(1 / 12)
    assert clean["snapshots_with_a_discrepancy"] == 0
    noisy = [({"hidden_kernel_module": {"m"}}, 2) if i < 3 else ({}, 2) for i in range(10)]
    with patch.object(RootkitScanner, "_snapshot_hidden_modules", side_effect=noisy):
        measured = calibrate(_cfg(proc, sys_, etc), 10, key=LAB_REPLAY_KEY)
    assert measured["race_prob"] == pytest.approx(4 / 12)
    assert measured["by_view"]["modules"] == 3


def test_cli_calibrate_stores_the_rate_and_the_next_scan_weighs_with_it(tmp_path, capsys):
    proc, sys_, etc = _make_clean_tree(tmp_path)
    from refmon import rootkit

    real = rootkit.ScanConfig

    def fake_cfg(**kw):  # the CLI scans this fake host instead of the real one
        return real(**{**kw, "proc_root": proc, "sys_root": sys_, "etc_root": etc,
                       "target_uid": os.getuid(), "self_pid": 100})  # fmt: skip

    wd = tmp_path / "state"
    with patch.object(rootkit, "ScanConfig", fake_cfg):
        assert cli_main(["scan-rootkit", "--calibrate", "18", "--workdir", str(wd),
                         "--interval-ms", "0"]) == 0  # fmt: skip
        stored = load_calibration(wd / CALIBRATION_FILE)
        assert stored == pytest.approx(1 / 20)
        capsys.readouterr()
        cli_main(["scan-rootkit", "--json", "--workdir", str(wd), "--interval-ms", "0"])
    report = json.loads(capsys.readouterr().out)
    assert report["race_prob"] == pytest.approx(1 / 20)
    assert report["race_prob_source"] == "calibrated"
    # the cross-view weight follows the measured rate: ln(0.99) - 2 ln(p_race)
    assert crossview_nats(2, 1 / 20, 8.0) == pytest.approx(math.log(0.99) - 2 * math.log(1 / 20))
