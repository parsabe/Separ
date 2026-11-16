"""Separ: judges behaviour (origin, contract, effect), not signatures."""

from pathlib import Path

import refmon
from refmon import *  # noqa: F403

# Allow separ to expose every submodule of refmon
__path__ = [str(Path(__file__).parent), *refmon.__path__]

__all__ = [*getattr(refmon, "__all__", [k for k in dir(refmon) if not k.startswith("_")]), "refmon"]
