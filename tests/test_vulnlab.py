"""End-to-end unittests for vulnlab (stdlib only).

The suite starts real services on ephemeral ports and probes them over the
wire — exactly what a scanner or exploit tool would see.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnlab.handlers import HANDLERS, http_service  # noqa: E402
from vulnlab.machines import MACHINES, get, machine_ports  # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _start(cfg_name: str, cfg: dict):
    handler = HANDLERS[cfg_name]
    cfg = dict(cfg)
    cfg["host"] = "127.0.0.1"
    loop = asyncio.get_running_loop()
    return await asyncio.start_server(
        lambda r, w: handler(r, w, cfg), "127.0.0.1", _free_port())


async def _read_up_to(reader, seconds=3):
    """Single read with timeout (services answer in one flush; on Windows the
    proactor loop misbehaves if reads are cancelled repeatedly)."""
    try:
        return await asyncio.wait_for(reader.read(65536), seconds)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return b""


class HttpBehaviour(unittest.TestCase):
    """Config-driven HTTP sever behaves like the vulnerable originals."""

    LEGACY = {
        "server": "Apache/2.4.49 (Unix)", "dir_listing": True,
        "stacktrace": True, "traversal_cve": "2.4.49",
        "cookie": "sid=VULNLAB",
        "params": [],
    }

    def _run(self, paths, cfg_name="http", **cfg):
        async def inner():
            server = await _start(cfg_name, cfg)
            port = server.sockets[0].getsockname()[1]
            out = []
            for path in paths:
                rr, wr = await asyncio.open_connection("127.0.0.1", port)
                wr.write(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
                await wr.drain()
                data = await asyncio.wait_for(rr.read(65536), 5)
                out.append(data)
                wr.close()
            server.close()
            return out
        return asyncio.run(inner())

    def test_apache_traversal_returns_passwd(self):
        (data,) = self._run(["/cgi-bin/.%2e/.%2e/etc/passwd"],
                            server="Apache/2.4.49 (Unix)",
                            traversal_cve="2.4.49")
        self.assertEqual(b"HTTP/1.1 200 OK", data.split(b"\r\n")[0])
        self.assertIn(b"root:x:0:0:root:/root:/bin/bash", data)

    def test_double_encoded_traversal_42013_style(self):
        (data,) = self._run(["/cgi-bin/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
                            server="Apache/2.4.50 (Unix)",
                            traversal_cve="2.4.50")
        self.assertIn(b"root:x:0:0", data)

    def test_directory_listing(self):
        (data,) = self._run(["/private-backups/"], server="nginx/1.14.0",
                            dir_listing=True)
        self.assertIn(b"Index of /private-backups/", data)
        self.assertIn(b"index.html", data)

    def test_stack_trace_leak(self):
        (data,) = self._run(["/phpMyAdmin/"], server="Apache/2.2.34",
                            stacktrace=True)
        self.assertEqual(b"HTTP/1.1 500 Internal Server Error",
                         data.split(b"\r\n")[0])
        self.assertIn(b"Traceback (most recent call last)", data)
        self.assertIn(b"Django Version", data)

    def test_cookie_without_flags(self):
        (data,) = self._run(["/"], server="Apache/2.4.49 (Unix)",
                            cookie="sid=VULNLAB")
        self.assertIn(b"Set-Cookie: sid=VULNLAB\r\n", data)
        self.assertNotIn(b"HttpOnly", data.split(b"Set-Cookie")[1])
        self.assertNotIn(b"Secure", data.split(b"Set-Cookie")[1])

    def test_version_disclosure_and_php_eol(self):
        (data,) = self._run(["/"], server="Apache/2.2.34 (CentOS)",
                            powered_by="PHP/5.6.40")
        self.assertIn(b"Server: Apache/2.2.34", data)
        self.assertIn(b"X-Powered-By: PHP/5.6.40", data)

    def test_docker_api_routes(self):
        # single-shot probes: /version serves the Engine API, /info 404s out
        docker = {"server": "Docker/20.10.6 (linux)", "plain_404": True}
        async def probe(paths, cfg):
            server = await asyncio.start_server(
                lambda r, w: http_service(r, w, dict(cfg, host="127.0.0.1")),
                "127.0.0.1", _free_port())
            port = server.sockets[0].getsockname()[1]
            outs = []
            for path in paths:
                rr, ww = await asyncio.open_connection("127.0.0.1", port)
                ww.write(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
                await ww.drain()
                outs.append(await asyncio.wait_for(rr.read(65536), 3))
                ww.close()
            server.close()
            return outs
        docker = dict(docker, routes=[
            ("/version", (200, "application/json",
                          json.dumps({"Version": "20.10.6"}).encode()))])
        home, version = asyncio.run(probe(["/", "/version"], docker))
        self.assertIn(b"404 page not found", home)
        body = version[version.find(b"\r\n\r\n") + 4:]
        self.assertEqual("20.10.6", json.loads(body)["Version"])


class WireServices(unittest.TestCase):
    """Raw socket probing of the non-HTTP emulations."""

    def _wire(self, name: str, service: object, payload: bytes | None,
              reads: int | None = None) -> dict:
        handler_name, cfg = service

        async def inner():
            server = await _start(handler_name, cfg)
            port = server.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                banner = await _read_up_to(reader, seconds=1.5)
                resp = b""
                if payload is not None:
                    chunks = payload if isinstance(payload, list) else [payload]
                    for chunk in chunks:
                        writer.write(chunk)
                        await writer.drain()
                    # first read: server's first reply frame
                    resp = await _read_up_to(reader, seconds=2.5)
                    for _ in range((reads or 1) - 1):
                        resp += await _read_up_to(reader, seconds=1.2)
                writer.close()
                return {"banner": banner, "resp": resp}
            finally:
                server.close()
        return asyncio.run(inner())

    def test_redis_info_shows_version(self):
        out = self._wire("redis", ("redis", {"version": "4.0.14"}),
                         b"*1\r\n$4\r\nINFO\r\n")
        self.assertIn(b"redis_version:4.0.14", out["resp"])
        # unauthenticated: no NOAUTH error, straight INFO response
        self.assertNotIn(b"NOAUTH", out["resp"])

    def test_redis_auth_refused_because_no_password(self):
        out = self._wire("redis", ("redis", {"version": "4.0.14"}),
                         b"*2\r\n$4\r\nAUTH\r\n$4\r\ntest\r\n")
        self.assertIn(b"no password is set", out["resp"])

    def test_memcached_stats(self):
        out = self._wire("memcached", ("memcached", {"version": "1.6.9"}),
                         b"stats\r\n")
        self.assertIn(b"STAT version 1.6.9", out["resp"])
        self.assertIn(b"END", out["resp"])

    def test_ftp_anonymous_login_accepted(self):
        out = self._wire("ftp", ("ftp", {"version": "2.3.4", "backdoor": False}),
                         b"USER anonymous\r\nPASS x@lab\r\n")
        self.assertIn(b"220 (vsFTPD 2.3.4)", out["banner"])
        # the handler answers 331 then PASS → 230
        self.assertIn(b"230 Login successful", out["resp"])

    def test_smtp_vrfy_leaks_account(self):
        out = self._wire("smtp", ("smtp", {"hostname": "mail.office.corp"}),
                         b"VRFY root\r\n")
        self.assertIn(b"220", out["banner"])
        self.assertIn(b"252", out["resp"])
        self.assertIn(b"root@", out["resp"])

    def test_telnet_banner(self):
        out = self._wire("telnet", ("telnet", {"hostname": "old-office"}),
                         None)
        self.assertIn(b"login:", out["banner"])

    def test_ssh_banner_range(self):
        out = self._wire("ssh", ("ssh", {"banner": "SSH-2.0-OpenSSH_9.6p1"}),
                         None)
        self.assertIn(b"SSH-2.0-OpenSSH_9.6p1", out["banner"])
        self.assertIn(b"SSH-2.0-", out["banner"])

    def test_mongo_op_query_replies(self):
        # minimal OP_QUERY hello: header(16) flags(4) name "admin.$cmd\0" skip/ret(8) doc
        q = b"admin.$cmd\x00"
        import struct
        body = struct.pack("<i", 0) + q + struct.pack("<ii", -1, 1) \
            + b"\x05\x00\x00\x00\x00"  # tiny empty doc
        total = 16 + 4 + len(q) + 8 + len(body)
        opcode = struct.pack("<i", 2004)
        pkt = struct.pack("<iii", total, 0, 0) + opcode + struct.pack("<i", 0) \
            + body
        out = self._wire("mongo", ("mongo", {}), pkt)
        self.assertIn(b"\x01\x00\x00\x00", out["resp"])  # OP_REPLY opcode 1

    def test_mysql_handshake_discloses_57(self):
        out = self._wire("mysql", ("mysql", {"version": "5.7.31-log"}), None)
        self.assertIn(b"5.7.31-log", out["banner"])

    def test_postgres_refuses_with_version(self):
        # startup packet (protocol 3, user admin) then password reply message
        out = self._wire("postgres",
                         ("postgres", {"version": "9.6.24"}),
                         [b"\x00\x03\x00\x00\x08\x04\xd2\x16\x00\x00\x00\x10",
                          b"p\x00\x00\x00\x0a\x6a\xff\x00\x00"],
                         reads=2)
        # first read: authentication md5 request; second: failure message
        self.assertIn(b"R\x00", out["resp"])  # md5 challenge frame
        self.assertIn(b"password authentication failed", out["resp"])

    def test_rsync_lists_module(self):
        out = self._wire("rsync", ("rsync", {}), b"#list\n")
        self.assertIn(b"@RSYNCD: 31.0", out["banner"])
        self.assertIn(b"backups", out["resp"])


class MachineLint(unittest.TestCase):
    def test_catalog_shape(self):
        self.assertEqual(4, len(MACHINES))
        for slug, m in MACHINES.items():
            self.assertTrue(m.services, slug)
            self.assertGreater(len(m.services), 2, slug)
            self.assertTrue(m.description, slug)

    def test_no_duplicate_ports_across_machines_when_all_runs(self):
        seen: dict[int, str] = {}
        for slug, m in MACHINES.items():
            for svc in m.services:
                candidates = [p for p in (svc.port, svc.fallback_port)
                              if p is not None]
                for p in candidates:
                    if p in seen:
                        # fallback ports may only collide with the SAME
                        # machine's canonical port
                        self.assertEqual(slug, seen[p],
                                         f"port {p} in {slug} and {seen[p]}")
                    seen[p] = slug

    def test_get_unknown_raises_helpful(self):
        with self.assertRaises(KeyError):
            get("nope")
        self.assertEqual([21, 23, 22, 25, 80, 6379],
                         machine_ports(get("old-office-server")))


class TLSCerts(unittest.TestCase):
    def test_expired_cert_is_actually_expired(self):
        from vulnlab.certs import ensure_cert
        cert, key = ensure_cert("expired")
        self.assertTrue(cert and key)
        # openssl should report notAfter in the past
        import subprocess
        out = subprocess.run(["openssl", "x509", "-enddate", "-noout",
                              "-in", cert], capture_output=True, text=True)
        self.assertIn("2021", out.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
