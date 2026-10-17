"""The lab engine: starts machines, manages ports, TLS and state.

Each machine is a bundle of services. The engine binds every service to its
primary port and — where Windows reserves the port — falls back to the
machine's declared fallback port. Findings that depend on well-known port
numbers (Redis 6379, Docker 2375, …) are best preserved on the primaries;
everything else is banner-driven and works on any port.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import sys

from . import certs


class ServiceDef:
    def __init__(self, name: str, handler: str, cfg: dict | None = None,
                 port: int | None = None, fallback_port: int | None = None,
                 tls: str | None = None, legacy_tls: bool = False,
                 service: str | None = None):
        self.name = name
        self.handler = handler           # key in handlers.HANDLERS or "http"
        self.cfg = cfg or {}
        self.port = port
        self.fallback_port = fallback_port
        self.tls = tls                   # cert kind, see certs.CERT_SPECS
        self.legacy_tls = legacy_tls     # offer TLS 1.0/1.1 too
        self.service = service


class Machine:
    def __init__(self, slug: str, name: str, description: str,
                 services: list[ServiceDef]):
        self.slug = slug
        self.name = name
        self.description = description
        self.services = services


def state_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(os.path.dirname(here), ".lab")
    os.makedirs(d, exist_ok=True)
    return d


def state_file() -> str:
    return os.path.join(state_dir(), "state.json")


def _read_state() -> dict:
    try:
        with open(state_file(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"instances": []}


def _write_state(state: dict) -> None:
    with open(state_file(), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def register_instance(slug: str, host: str, ports: dict[str, int]) -> None:
    """Record (or extend) this process' machine list in the state file."""
    state = _read_state()
    inst = None
    for entry in state.get("instances", []):
        if entry.get("pid") == os.getpid():
            inst = entry
            break
    if inst is None:
        inst = {"pid": os.getpid(), "host": host,
                "slugs": [], "ports": {}}
        state.setdefault("instances", []).append(inst)
    if slug not in inst.setdefault("slugs", []):
        inst["slugs"].append(slug)
    inst.setdefault("ports", {})[slug] = ports
    inst["host"] = host
    _write_state(state)


def remove_instance(pid: int | None = None) -> None:
    pid = pid or os.getpid()
    state = _read_state()
    state["instances"] = [i for i in state.get("instances", [])
                          if i.get("pid") != pid]
    _write_state(state)


async def _tls_context(service: ServiceDef) -> ssl.SSLContext:
    kind = service.tls
    cert, key = certs.ensure_cert(kind)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if service.legacy_tls:
        # attempt to also accept TLS 1.0/1.1 (needs SMALL security level)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except (ValueError, ssl.SSLError):
                pass
    return ctx


async def _bind_service(service: ServiceDef, host: str) -> tuple[int, object]:
    """Bind one service, returning (actual_port, asyncio.Server)."""
    from .handlers import HANDLERS
    handler = HANDLERS[service.handler]
    cfg = dict(service.cfg)
    cfg["host"] = host
    ssl_ctx = await _tls_context(service) if service.tls else None

    async def client_connected(reader, writer):
        await handler(reader, writer, cfg)

    candidates = [p for p in (service.port, service.fallback_port)
                  if p is not None]
    last_err: Exception | None = None
    for port in candidates:
        try:
            server = await asyncio.start_server(
                client_connected, host, port, ssl=ssl_ctx, backlog=64)
            return port, server
        except OSError as exc:
            last_err = exc
    raise OSError(
        f"could not bind {service.name} on ports {candidates}: {last_err}")


async def serve(machine: Machine, host: str = "127.0.0.1",
                bound_out: dict | None = None) -> dict[str, int]:
    """Run a machine until cancelled.  Returns {service_name: bound_port} and
    also fills ``bound_out`` (if given) as soon as the ports are bound."""
    running: list[object] = []
    bound: dict[str, int] = {}
    try:
        for service in machine.services:
            port, server = await _bind_service(service, host)
            bound[service.name] = port
            running.append(server)
        if not bound:
            raise RuntimeError("machine has no services")
    except Exception:
        for server in running:
            server.close()
        raise
    if bound_out is not None:
        bound_out.clear()
        bound_out.update(bound)
    try:
        await asyncio.Event().wait()   # sleep forever
    except asyncio.CancelledError:
        pass
    finally:
        for server in running:
            server.close()
        for server in running:
            try:
                await server.wait_closed()
            except Exception:
                pass
    return bound


def check_ports(host: str, ports: list[int], timeout: float = 0.4) -> list[bool]:
    """Sync port probe used by `vulnlab status`."""
    import socket
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results.append(True)
        except OSError:
            results.append(False)
    return results


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        # os.kill(pid, 0) is unreliable on Windows; use tasklist
        try:
            out = os.popen(f"tasklist /FI \"PID eq {pid}\" /NH").read()
            return str(pid) in out
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# convenience re-exports ------------------------------------------------------

from .certs import certificate_note  # noqa: E402  (used by cli/README text)
