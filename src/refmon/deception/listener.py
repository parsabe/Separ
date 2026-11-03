"""Decoy services and tarpit (v2.1, A72).

    refmon serve --decoys decoys.yaml      (the listeners run inside the daemon)

A decoy service listens on a port where no real service runs. Nobody legitimate connects to it,
so every connection is a canary hit: the daemon judges it as a `request_in` of the channel role
`decoy_service`, notifies, and proposes the source address for blocking (proposals.py).

What it shows comes from the configuration, never from defaults that give a honeypot away: the
banner, the HTTP `Server` header and the page are what the admin writes, and answers come after a
random human-scale delay. A service never runs, stores or forwards anything it receives; received
bytes are counted and dropped.

Tarpit: to slow a scanner down and buy the response team time, a service can drip its answer one
byte at a time (`tarpit_bytes_per_s`). `endless` keeps an SSH-style client waiting with harmless
pre-banner lines (allowed by RFC 4253 section 4.2) until `max_seconds`. Tarpits are bounded: at most
`max_concurrent` at once (further connections are reported and closed at once) and `max_seconds`
each, so a flood cannot exhaust the host.
"""

from __future__ import annotations

import contextlib
import secrets
import socket
import threading
import time
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# A 1x1 transparent PNG: a beacon image answers quickly and looks like any tracking-free image.
PIXEL = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082"
)


class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9_.:@-]{1,64}$")
    port: int = Field(ge=0, le=65535)  # 0: any free port (tests)
    bind: str = "0.0.0.0"
    kind: Literal["banner", "http"] = "banner"
    banner: str = ""  # banner kind: the first line a client sees, e.g. an SSH version string
    endless: bool = False  # banner kind: hold the client with pre-banner lines (tarpit)
    server_header: str = ""  # http kind
    page: str = (
        "<html><head><title>Sign in</title></head><body><form method=post>"
        "<input name=user><input name=password type=password></form></body></html>"
    )
    tarpit_bytes_per_s: float = Field(default=0.0, ge=0.0)  # 0: answer at normal speed
    delay_ms: tuple[int, int] = (40, 400)  # random answer delay, like a real loaded server


class ListenConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    services: list[ServiceSpec] = Field(default_factory=list)
    max_concurrent: int = Field(default=16, ge=1, le=1024)
    max_seconds: float = Field(default=300.0, gt=0.0, le=86400.0)
    read_limit: int = Field(default=8192, ge=64, le=1 << 20)


# (service name, raw source address, request path or None, first line of what the client sent)
OnTouch = Callable[[str, str, str | None, str], None]


class DecoyListener:
    def __init__(self, cfg: ListenConfig, on_touch: OnTouch) -> None:
        self.cfg, self.on_touch = cfg, on_touch
        self.ports: dict[str, int] = {}
        self.stats = {"connections": 0, "refused_busy": 0, "bytes_in": 0, "bytes_out": 0}
        self._slots = threading.BoundedSemaphore(cfg.max_concurrent)
        self._stop = threading.Event()
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    # -- lifecycle -----------------------------------------------------------------------------

    def start(self) -> None:
        for spec in self.cfg.services:
            family = socket.AF_INET6 if ":" in spec.bind else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((spec.bind, spec.port))
            sock.listen(64)
            sock.settimeout(0.5)
            self._socks.append(sock)
            self.ports[spec.name] = sock.getsockname()[1]
            t = threading.Thread(target=self._accept, args=(sock, spec), daemon=True,
                                 name=f"refmon-decoy-{spec.name}")  # fmt: skip
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for sock in self._socks:
            with contextlib.suppress(OSError):
                sock.close()
        for t in self._threads:
            t.join(timeout=2.0)

    @property
    def alive(self) -> bool:
        return bool(self._threads) and all(t.is_alive() for t in self._threads)

    # -- connections ---------------------------------------------------------------------------

    def _count(self, key: str, n: int = 1) -> None:
        with self._lock:
            self.stats[key] += n

    def _accept(self, sock: socket.socket, spec: ServiceSpec) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self._count("connections")
            if not self._slots.acquire(blocking=False):
                self._count("refused_busy")
                self._report(spec, addr[0], None, "")
                with contextlib.suppress(OSError):
                    conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, addr[0], spec), daemon=True).start()

    def _report(self, spec: ServiceSpec, ip: str, path: str | None, line: str) -> None:
        with contextlib.suppress(Exception):  # a failing judgement must not kill the listener
            self.on_touch(spec.name, ip, path, line)

    def _serve(self, conn: socket.socket, ip: str, spec: ServiceSpec) -> None:
        deadline = time.monotonic() + self.cfg.max_seconds
        try:
            conn.settimeout(1.0)
            if spec.kind == "http":
                self._http(conn, ip, spec, deadline)
            else:
                self._banner(conn, ip, spec, deadline)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            self._slots.release()

    def _pause(self, spec: ServiceSpec) -> None:
        lo, hi = spec.delay_ms
        self._stop.wait((lo + secrets.randbelow(max(1, hi - lo + 1))) / 1000.0)

    def _send(self, conn: socket.socket, data: bytes, spec: ServiceSpec, deadline: float) -> bool:
        """Send, dripping at the tarpit rate if one is set. False when time is up."""
        if spec.tarpit_bytes_per_s <= 0:
            conn.sendall(data)
            self._count("bytes_out", len(data))
            return True
        gap = 1.0 / spec.tarpit_bytes_per_s
        for i in range(len(data)):
            if self._stop.is_set() or time.monotonic() >= deadline:
                return False
            conn.sendall(data[i : i + 1])
            self._count("bytes_out")
            self._stop.wait(gap)
        return True

    def _drain(self, conn: socket.socket, deadline: float, limit: int) -> bytes:
        """Read what the client sends (at most `limit` bytes kept, the rest counted and dropped)."""
        kept = b""
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                chunk = conn.recv(4096)
            except TimeoutError:
                if kept:
                    break
                continue
            if not chunk:
                break
            self._count("bytes_in", len(chunk))
            if len(kept) < limit:
                kept += chunk[: limit - len(kept)]
            if b"\n" in kept:
                break
        return kept

    def _banner(self, conn: socket.socket, ip: str, spec: ServiceSpec, deadline: float) -> None:
        self._report(spec, ip, None, "")
        self._pause(spec)
        if spec.endless:
            # pre-banner lines, one every few seconds, until the deadline: the client waits
            while not self._stop.is_set() and time.monotonic() < deadline:
                line = secrets.token_hex(4 + secrets.randbelow(12)).encode() + b"\r\n"
                if not self._send(conn, line, spec, deadline):
                    return
                remaining = deadline - time.monotonic()
                self._stop.wait(max(0.0, min(remaining, 5.0 + secrets.randbelow(5))))
            return
        if spec.banner and not self._send(conn, spec.banner.encode() + b"\r\n", spec, deadline):
            return
        self._drain(conn, deadline, self.cfg.read_limit)

    def _http(self, conn: socket.socket, ip: str, spec: ServiceSpec, deadline: float) -> None:
        head = self._drain(conn, min(deadline, time.monotonic() + 10.0), self.cfg.read_limit)
        line = head.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        path = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else None
        self._report(spec, ip, path, line)
        self._pause(spec)
        is_image = path is not None and path.split("?", 1)[0].endswith(".png")
        body = PIXEL if is_image else spec.page.encode()
        ctype = "image/png" if is_image else "text/html; charset=utf-8"
        header = "HTTP/1.1 200 OK\r\n"
        if spec.server_header:
            header += f"Server: {spec.server_header}\r\n"
        header += (
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        )
        if is_image:  # a beacon answers at once, so the document looks normal
            conn.sendall(header.encode() + body)
            self._count("bytes_out", len(header) + len(body))
            return
        self._send(conn, header.encode() + body, spec, deadline)
