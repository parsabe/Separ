"""Review 2026-11, item 9: no hard-coded campus networks or device ids.

`separ setup --server` needs the admin's campus network; VPN and WLAN are optional; the mail domain
defaults to tu-freiberg.de; the output says exactly what was configured; the live daemon names this
host by its pseudonym.
"""

from __future__ import annotations

from pathlib import Path

from tests.livehelp import make_barrier

from refmon.cli import main as cli_main
from refmon.policy_io import read_document

SRC = Path(__file__).resolve().parents[1] / "src" / "refmon"


def _setup(tmp_path: Path, *args: str) -> int:
    return cli_main(
        ["setup", "--config-dir", str(tmp_path / "cfg"), "--key", str(tmp_path / "k" / "a.key"),
         *args]
    )  # fmt: skip


def test_server_mode_requires_a_campus_network(tmp_path, capsys):
    assert _setup(tmp_path, "--server") == 1
    assert "--campus-cidr" in capsys.readouterr().err
    assert not (tmp_path / "cfg" / "policy.yaml").exists()


def test_server_mode_writes_exactly_the_named_networks(tmp_path, capsys):
    code = _setup(tmp_path, "--server", "--campus-cidr", "192.0.2.0/24",
                  "--campus-cidr", "2001:db8::/32", "--vpn-cidr", "198.51.100.0/24",
                  "--mail-domain", "Example.ORG")  # fmt: skip
    assert code == 0
    out = capsys.readouterr().out
    doc = read_document(tmp_path / "cfg" / "policy.yaml")
    dests = {d["name"]: d for d in doc["destinations"]}
    assert dests["campus"]["match"]["cidr"] == ["192.0.2.0/24", "2001:db8::/32"]
    assert dests["vpn"]["match"]["cidr"] == ["198.51.100.0/24"]
    assert dests["campus"]["internal"] and dests["vpn"]["internal"]
    assert "wlan" not in dests and "eduroam" not in dests
    assert [d["name"] for d in doc["destinations"]][:2] == ["campus", "vpn"]  # first match wins
    assert "package_index" in dests  # the reference classes are kept
    assert doc["identity"]["internal_mail_domains"] == ["example.org"]
    assert "Campus networks       : 192.0.2.0/24, 2001:db8::/32" in out
    assert "Vpn networks          : 198.51.100.0/24" in out
    assert "Wlan" not in out and "139.18" not in out and "eduroam" not in out


def test_laptop_mode_prints_no_server_networks(tmp_path, capsys):
    assert _setup(tmp_path, "--laptop") == 0
    out = capsys.readouterr().out
    assert "Campus" not in out and "Vpn" not in out and "Wlan" not in out
    assert "Internal mail domain  : tu-freiberg.de" in out
    doc = read_document(tmp_path / "cfg" / "policy.yaml")
    names = [d["name"] for d in doc["destinations"]]
    assert names[0] == "local" and "campus" not in names


def test_a_malformed_network_is_refused(tmp_path, capsys):
    assert _setup(tmp_path, "--server", "--campus-cidr", "198.51.100.1/24") == 1  # host bits set
    assert "CIDR" in capsys.readouterr().err
    assert _setup(tmp_path, "--server", "--campus-cidr", "campus") == 1


def test_no_campus_network_is_built_into_the_code():
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "139.18." not in text, path
        assert "eduroam" not in text.lower(), path


def test_the_daemon_names_this_host_by_its_pseudonym(tmp_path):
    barrier = make_barrier(tmp_path / "wd")
    barrier.guard_command("echo hello", execute=False)
    barrier.guard_command("sh -c id", role="web_worker", execute=False)
    log = barrier.events_log_path.read_text()
    assert "dev-7f3a" not in log and "dev-b21c" not in log
    assert barrier.device_pseudonym in log
    if len(barrier.device_name) >= 6:  # a very short name could occur by chance in a digest
        assert barrier.device_name not in log  # the host name itself never appears
    assert "dev-7f3a" not in (SRC / "live.py").read_text()
