"""Where ingested lines come from, and the runner that feeds them to the daemon (v2.2, A73).

    # /etc/refmon/ingest.yaml, used by: refmon serve --ingest /etc/refmon/ingest.yaml
    sensors:
      - mapping: /usr/share/refmon/mappings/falco.yaml
        source: {socket: /run/refmon/falco.sock}      # preferred: nothing raw is written to disk
      - mapping: /usr/share/refmon/mappings/tetragon.yaml
        source: {file: /var/run/cilium/tetragon/tetragon.log}

Sources:
- `socket`: Refmon listens on a Unix stream socket (mode 0600; the sensor, usually root, connects
  and writes one record per line). Nothing raw touches the disk, so this is the privacy-preferred
  way.
- `file`: Refmon follows a log file the sensor writes, from its end, across rotation. The file is
  the sensor's, not Refmon's: its retention is the admin's job (docs/admin-integration.md).
- a command's output goes to a socket with socat, e.g.
  `journalctl -o json -f -u sshd | socat - UNIX-CONNECT:/run/refmon/sshd.sock`.

A line that does not map is counted and dropped. It is never judged: missing information never
generates evidence.
"""

from __future__ import annotations

import contextlib
import os
import socket
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..schemas import RawEvent
from .mapping import Mapper, load_mapping

MAX_LINE = 1 << 20  # a longer line is dropped as unparsable


class SourceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: Path | None = None
    socket: Path | None = None
    stdin: bool = False
    from_start: bool = False  # file only: read what is already there (tests, one-off imports)

    @model_validator(mode="after")
    def _exactly_one(self):
        if (
            sum(
                x is not None and x is not False
                for x in (self.file, self.socket, self.stdin or None)
            )
            != 1
        ):
            raise ValueError("a source is exactly one of file, socket or stdin")
        return self


class SensorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mapping: Path
    source: SourceSpec


class IngestConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensors: list[SensorSpec] = Field(default_factory=list)


def load_config(path) -> IngestConfig:
    from ..yamlio import read_document

    cfg = IngestConfig.model_validate(read_document(path))
    base = Path(path).resolve().parent
    for s in cfg.sensors:  # a relative mapping path is relative to the config file
        if not s.mapping.is_absolute():
            s.mapping = base / s.mapping
    return cfg


# -- sources ----------------------------------------------------------------------------------


def follow_file(path: Path, stop: threading.Event, *, from_start: bool = False,
                poll: float = 0.25) -> Iterator[str]:  # fmt: skip
    """Yield new lines of `path`, reopening it after rotation (a new inode or a shorter file)."""
    fh: IO[str] | None = None
    inode = None
    pending = ""
    first = True
    while not stop.is_set():
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115
            except OSError:
                stop.wait(poll)
                continue
            st = os.fstat(fh.fileno())
            inode = st.st_ino
            if first and not from_start:
                fh.seek(0, os.SEEK_END)
            first = False
        chunk = fh.read(65536)
        if chunk:
            pending += chunk
            *lines, pending = pending.split("\n")
            yield from lines
            if len(pending) > MAX_LINE:
                pending = ""
            continue
        try:
            st = os.stat(path)
            rotated = st.st_ino != inode or st.st_size < fh.tell()
        except OSError:
            rotated = True
        if rotated:
            fh.close()
            fh = None
            pending = ""
            continue
        stop.wait(poll)
    if fh is not None:
        fh.close()


class SocketSource:
    """A Unix stream socket; every connection is read line by line."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            if self.path.is_socket():
                self.path.unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.sock.bind(str(self.path))
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        self.sock.listen(16)
        self.sock.settimeout(0.5)

    def lines(self, stop: threading.Event, emit: Callable[[str], None]) -> None:
        while not stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._read, args=(conn, stop, emit), daemon=True).start()

    @staticmethod
    def _read(conn: socket.socket, stop: threading.Event, emit: Callable[[str], None]) -> None:
        conn.settimeout(0.5)
        pending = b""
        with conn:
            while not stop.is_set():
                try:
                    data = conn.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not data:
                    break
                pending += data
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    emit(line.decode("utf-8", "replace"))
                if len(pending) > MAX_LINE:
                    pending = b""

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()
        with contextlib.suppress(OSError):
            self.path.unlink()


# -- the runner -------------------------------------------------------------------------------


class IngestRunner:
    """Maps the lines of one source and hands each RawEvent to `sink`. Counts outcomes only."""

    def __init__(self, mapper: Mapper, source: SourceSpec, sink: Callable[[RawEvent], None],
                 *, stdin: IO[str] | None = None) -> None:  # fmt: skip
        self.mapper, self.source, self.sink = mapper, source, sink
        self.name = mapper.mapping.name
        self.stats: Counter[str] = Counter()
        self.last_event: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: SocketSource | None = None
        self._stdin = stdin
        self._lock = threading.Lock()

    def handle(self, line: str) -> None:
        if len(line) > MAX_LINE:
            outcome, event = "unparsable", None
        else:
            event, outcome = self.mapper.map(line)
        if event is not None:
            try:
                self.sink(event)
            except Exception:  # a failing judgement must not stop the sensor
                outcome = "sink_failed"
            else:
                self.last_event = time.monotonic()
        with self._lock:
            self.stats[outcome] += 1

    def _run(self) -> None:
        src = self.source
        if src.socket is not None:
            self._socket.lines(self._stop, self.handle)
        elif src.file is not None:
            for line in follow_file(src.file, self._stop, from_start=src.from_start):
                self.handle(line)
        else:
            for line in self._stdin or ():
                if self._stop.is_set():
                    break
                self.handle(line)

    def start(self) -> None:
        if self.source.socket is not None:
            self._socket = SocketSource(self.source.socket)
        self._thread = threading.Thread(target=self._run, name=f"refmon-ingest-{self.name}",
                                        daemon=True)  # fmt: skip
        self._thread.start()

    def run_foreground(self) -> None:
        if self.source.socket is not None:
            self._socket = SocketSource(self.source.socket)
        try:
            self._run()
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict:
        with self._lock:
            return {"sensor": self.name, **dict(self.stats)}


def build_runners(cfg: IngestConfig, sink: Callable[[RawEvent], None], *,
                  extra_roles: tuple[str, ...]) -> list[IngestRunner]:  # fmt: skip
    return [
        IngestRunner(load_mapping(s.mapping, extra_roles=extra_roles), s.source, sink)
        for s in cfg.sensors
    ]
