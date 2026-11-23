"""Keep the suite independent of the machine it runs on."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_host_system_config(tmp_path_factory, monkeypatch):
    """A per-user daemon prefers /etc/separ when it exists (round 2, A3). Tests must not read the
    host's: the system configuration folder is a fresh, empty path for every test."""
    from refmon import config

    monkeypatch.setattr(config, "SYSTEM_CONFIG_DIR", tmp_path_factory.mktemp("etc") / "separ")
