"""The deception settings file (`decoys.yaml`) and the steps around it (v2.1).

    plant:                     # where and what to plant (deception/plant.py)
      dir: /srv/share/finance
      beacon_url: http://files.example.internal:8088
    listen:                    # decoy services (deception/listener.py)
      max_concurrent: 16
      max_seconds: 300
      services:
        - {name: ssh-legacy, port: 2222, banner: "SSH-2.0-OpenSSH_8.0", endless: true}
        - {name: files-http, port: 8088, kind: http, server_header: "Apache/2.4.37 (Red Hat)"}
    watch: true                # watch the planted files (deception/watch.py)
    proposal: proposals/decoys.json   # relative to the daemon's work directory

One file drives every step: `refmon decoy plant` plants and writes the proposal (with a `service`
canary for each listener), an admin approves it into the signed policy (`refmon decoy
approve-canaries`), and `refmon serve --decoys decoys.yaml` runs the listeners and the watcher.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..yamlio import read_document
from .listener import ListenConfig
from .plant import PlantConfig, Planted


class DecoySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plant: PlantConfig | None = None
    listen: ListenConfig = Field(default_factory=ListenConfig)
    watch: bool = True
    proposal: str = "proposals/decoys.json"

    def proposal_path(self, workdir: Path) -> Path:
        p = Path(self.proposal)
        return p if p.is_absolute() else Path(workdir) / p


def load_settings(path: Path | str) -> DecoySettings:
    return DecoySettings.model_validate(read_document(path))


def service_canary(service: str) -> dict:
    return {"name": f"decoy-service-{service}", "class": "service", "value": service}


def add_service_canaries(planted: Planted, listen: ListenConfig) -> Planted:
    """A listener is a trap only if its connections are canary hits: one `service` canary each."""
    have = {c["name"] for c in planted.canaries}
    for spec in listen.services:
        c = service_canary(spec.name)
        if c["name"] not in have:
            planted.canaries.append(c)
    return planted
