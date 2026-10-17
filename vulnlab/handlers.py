"""Vulnerable service emulations.

Every handler is an ``async`` callable ``(reader, writer, cfg) -> None``.
Handlers are deliberately *not* hardened: they accept connections from
anyone, reveal versions, skip authentication and, where marked, are
exploitable by design. They are lab targets — never expose them to networks
you do not own.

Handlers receive a per-service ``cfg`` dict from machines.py.
"""

from __future__ import annotations

import asyncio
import json
import struct

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _line(s) -> bytes:
    b = s.encode("latin-1") if isinstance(s, str) else s
    return b + b"\r\n"


async def _read_line(reader) -> str:
    data = await reader.readline()
    if not data:
        return ""
    return data.decode("latin-1", "replace").rstrip("\r\n")


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


# ---------------------------------------------------------------------------
# Fake root shell behind the vsftpd 2.3.4 smiley backdoor (port 6200, CVE-2011-2523)
# ---------------------------------------------------------------------------

_CANNED = {
    "id": b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "whoami": b"root\r\n",
    "uname -a": b"Linux old-office 2.6.18-128.el5 #1 SMP x86_64 GNU/Linux\r\n",
    "cat /etc/passwd": (b"root:x:0:0:root:/root:/bin/bash\r\n"
                        b"daemon:x:1:1:daemon:/usr/sbin:/bin/sh\r\n"
                        b"ftp:x:107:65534::/srv/ftp:/bin/false\r\n"),
    "cat /etc/shadow": b"root:$1$lab$Qf4u9fl4sw4m5n0.:14640:0:99999:7:::\r\n",
    "pwd": b"/root\r\n",
    "ls": b"flag.txt  backup.tar.gz  notes-2008.txt\r\n",
    "ls -la": b"total 16\r\ndrwxr-xr-x 1 root root 4096 Jan 01  2008 .\r\n"
              b"-rw-r--r-- 1 root root   24 Jan 01  2008 flag.txt\r\n"
              b"-rw-r--r-- 1 root root 3329 Jan 01  2008 backup.tar.gz\r\n",
}

_backdoor_servers: set[tuple[str, int]] = set()


def ensure_backdoor_server(host: str, port: int = 6200) -> None:
    """Spawn the fake root shell once (triggered by USER command with ':)')."""
    key = (host, port)
    if key in _backdoor_servers:
        return

    async def handle(reader, writer):
        try:
            writer.write(b"root@old-office:~# ")
            await writer.drain()
            while True:
                data = await reader.readline()
                if not data:
                    break
                cmd = data.decode("latin-1", "replace").strip()
                if cmd in ("exit", "quit"):
                    break
                out = _CANNED.get(cmd.lower(),
                                  b"sh: %s: command not found\r\n"
                                  % cmd.encode("latin-1", "replace")[:120])
                writer.write(out + b"root@old-office:~# ")
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    async def _spawn():
        try:
            loop = asyncio.get_running_loop()
            server = await loop.create_server(
                lambda: _ShellProto(), host, port, backlog=8)
            _backdoor_servers.add(key)
            # keep server alive; closure is held by the loop running forever
            asyncio.ensure_future(server.serve_forever())
        except OSError:
            _backdoor_servers.discard(key)

    class _ShellProto(asyncio.Protocol):
        def connection_made(self, transport):
            self.transport = transport
            transport.write(b"root@old-office:~# ")

        def data_received(self, data):
            for line in data.split(b"\n"):
                cmd = line.strip().decode("latin-1", "replace").lower()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    self.transport.close()
                    return
                out = _CANNED.get(cmd, b"sh: %s: command not found\r\n"
                                  % cmd.encode("latin-1")[:120])
                self.transport.write(out + b"root@old-office:~# ")

    try:
        asyncio.ensure_future(_spawn())
    except RuntimeError:  # no running loop (should not happen)
        pass


# ---------------------------------------------------------------------------
# FTP — vsftpd 2.3.4, anonymous login accepted, !! smiley backdoor !!
# ---------------------------------------------------------------------------

async def ftp_service(reader, writer, cfg):
    version = cfg.get("version", "2.3.4")
    backdoor = cfg.get("backdoor", True)
    host = cfg["host"]

    def w(s):
        writer.write(_line(s))

    w(f"220 (vsFTPD {version})")
    await writer.drain()
    try:
        while True:
            line = await _read_line(reader)
            if not line:
                break
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                if ":)" in arg and backdoor:
                    ensure_backdoor_server(host)
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd == "PASS":
                writer.write(b"230 Login successful.\r\n")
            elif cmd == "SYST":
                writer.write(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                writer.write(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n"
                             b" SIZE\r\n UTF8\r\n211 End\r\n")
            elif cmd in ("PWD", "XPWD"):
                writer.write(b'257 "/" is the current directory\r\n')
            elif cmd in ("LIST", "NLST"):
                writer.write(b"150 Here comes the directory listing.\r\n"
                             b"-rw-r--r-- 1 ftp ftp  4102 Jan 01  2008 "
                             b"backup.tar.gz\r\n"
                             b"-rw-r--r-- 1 ftp ftp    24 Jan 01  2008 "
                             b"flag.txt\r\n226 Directory send OK.\r\n")
            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                break
            else:
                writer.write(b"502 Command not implemented.\r\n")
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Telnet — banner + login loop, accepts anything then "Login incorrect"
# ---------------------------------------------------------------------------

async def telnet_service(reader, writer, cfg):
    hostname = cfg.get("hostname", "old-office")
    name = hostname.encode("latin-1", "replace")
    try:
        writer.write(b"\r\nWelcome to the " + name
                     + b" appliance (build 2008.4)\r\n\r\nlogin: ")
        await writer.drain()
        while True:
            user = await _read_line(reader)
            if not user:
                break
            writer.write(b"Password: ")
            await writer.drain()
            await _read_line(reader)
            writer.write(b"\r\nLogin incorrect\r\n\r\nlogin: ")
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# SSH — version banner only (kex exchange is also emulated for realism)
# ---------------------------------------------------------------------------

def _sshr(s: str) -> bytes:
    b = s.encode("latin-1")
    return len(b).to_bytes(4, "big") + b


def _ssh_kexinit() -> bytes:
    cookie = b"LabKexInitCooky"
    algs = (_sshr("diffie-hellman-group14-sha256,curve25519-sha256")
            + _sshr("ssh-ed25519,rsa-sha2-256")
            + _sshr("aes128-ctr,aes256-ctr")
            + _sshr("aes128-ctr,aes256-ctr")
            + _sshr("hmac-sha1")
            + _sshr("hmac-sha1")
            + _sshr("none")
            + _sshr("none")
            + _sshr("")
            + _sshr("")
            + b"\x00"                    # first_kex_packet_follows
            + b"\x00\x00\x00\x01\x00")   # reserved
    payload = (b"\x14" + cookie + algs)
    return (len(payload) + 4).to_bytes(4, "big") + b"\x08" \
        + (len(payload)).to_bytes(4, "big") + payload  # simplified framing


def _ssh_packet(payload: bytes) -> bytes:
    # SSH binary packet: length(4) + padding_len(b) + payload + padding
    pad = (16 - ((4 + 1 + len(payload)) % 16)) or 1
    length = 1 + len(payload) + pad
    return length.to_bytes(4, "big") + bytes([pad]) + payload + b"\x00" * pad


async def ssh_service(reader, writer, cfg):
    banner = cfg.get("banner", "SSH-2.0-OpenSSH_9.6p1")
    try:
        writer.write(banner.encode("latin-1") + b"\r\n")
        await writer.drain()
        line = await reader.readline()
        if not line:
            return
        writer.write(_ssh_packet(_ssh_kexinit()))
        await writer.drain()
        # Let the client go through kex; close after soaking its packets.
        try:
            await asyncio.wait_for(reader.read(65536), timeout=5)
        except (OSError, asyncio.TimeoutError):
            pass
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# SMTP — dating Postfix with VRFY account disclosure
# ---------------------------------------------------------------------------

async def smtp_service(reader, writer, cfg):
    host = cfg.get("hostname", "mail.office.corp").encode("latin-1")
    try:
        writer.write(_line(b"220 %s ESMTP (Ubuntu)" % host))
        await writer.drain()
        while True:
            line = await _read_line(reader)
            if not line:
                break
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb in ("EHLO", "HELO"):
                writer.write(b"250-%s\r\n250-PIPELINING\r\n"
                             b"250-SIZE 10240000\r\n250-VRFY\r\n250 ETRN\r\n" % host)
            elif verb == "MAIL":
                writer.write(b"250 2.1.0 Ok\r\n")
            elif verb == "RCPT":
                writer.write(b"250 2.1.5 Ok\r\n")
            elif verb == "VRFY":
                who = (arg.split("@")[0].strip() or "root").encode("latin-1")[:64]
                writer.write(b"252 2.0.0 <%s@%s>\r\n" % (who, host))
            elif verb == "DATA":
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                await writer.drain()
                while True:
                    chunk = await reader.readline()
                    if chunk.rstrip(b"\r\n") == b"." or not chunk:
                        break
                writer.write(b"250 2.0.0 Ok: queued as 4C21F2E0129\r\n")
            elif verb == "QUIT":
                writer.write(b"221 2.0.0 Bye\r\n")
                break
            else:
                writer.write(b"502 5.5.2 Error: command not recognized\r\n")
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Redis — NO authentication at all; INFO/INFO/GET/SET/CONFIG live
# ---------------------------------------------------------------------------

async def redis_service(reader, writer, cfg):
    version = cfg.get("version", "4.0.14")
    store = dict(cfg.get("seed", {"session:1": "sessid-a1b2c3d4e5f6-admin"}))

    def bulk(s: str) -> bytes:
        b = s.encode("latin-1")
        return b"$%d\r\n%s\r\n" % (len(b), b)

    def info() -> str:
        keyspace = "".join(
            "db%d:keys=%d,expires=0,avg_ttl=0\r\n" % (i + 1, n)
            for i, n in enumerate([len(store)]))
        return ("# Server\r\nredis_version:%s\r\nredis_git_sha1:00000000\r\n"
                "redis_mode:standalone\r\nos:Linux 2.6.18 x86_64\r\n"
                "arch_bits:64\r\nrun_id:labdeadbeef0000000000000000000\r\n"
                "# Keyspace\r\n" % version) + keyspace

    def resp_array(items) -> bytes:
        out = b"*%d\r\n" % len(items)
        return out + b"".join(bulk(i) for i in items)

    try:
        while True:
            head = await reader.readline()
            if not head:
                break
            parts: list[str] = []
            hs = head.decode("latin-1", "replace").strip()
            if hs.startswith("*"):
                try:
                    count = int(hs[1:])
                except ValueError:
                    count = 0
                for _ in range(count * 2):
                    ln = await reader.readline()
                    if not ln:
                        break
                    if not ln.startswith(b"$") and not ln.startswith(b":"):
                        parts.append(ln.strip().decode("latin-1"))
            else:
                parts = hs.split()
            cmd = parts[0].upper() if parts else ""
            args = parts[1:]
            if cmd == "PING":
                writer.write(b"+PONG\r\n")
            elif cmd in ("INFO", "INFO ALL"):
                writer.write(bulk(info()))
            elif cmd == "AUTH":
                writer.write(b"-ERR Client sent AUTH, but no password is set.\r\n")
            elif cmd == "GET" and len(args) >= 1:
                v = store.get(args[0])
                writer.write(bulk(v) if v is not None else b"$-1\r\n")
            elif cmd == "SET" and len(args) >= 2:
                store[args[0]] = args[1]
                writer.write(b"+OK\r\n")
            elif cmd == "KEYS":
                writer.write(resp_array(list(store.keys())))
            elif cmd == "GETDEL" and len(args) >= 1:
                v = store.pop(args[0], None)
                writer.write(bulk(v) if v is not None else b"$-1\r\n")
            elif cmd in ("CONFIG", "CLIENT", "SLAVEOF", "REPLCONF", "SELECT"):
                sub = args[0].upper() if args else ""
                if sub == "GET" and len(args) >= 2:
                    writer.write(resp_array([args[1], ""]))
                else:
                    writer.write(b"+OK\r\n")
            elif cmd in ("DEL", "EXISTS"):
                writer.write(b":1\r\n")
            elif cmd in ("TYPE", "TTL"):
                writer.write(b":0\r\n")
            elif cmd == "QUIT":
                break
            else:
                writer.write(b"-ERR unknown command '%s', with args beginning with\r\n"
                             % cmd.encode("latin-1")[:64])
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# memcached — stats and keys readable without any auth
# ---------------------------------------------------------------------------

async def memcached_service(reader, writer, cfg):
    version = cfg.get("version", "1.6.9")
    vbytes = version.encode("latin-1")
    try:
        while True:
            line = await _read_line(reader)
            if not line:
                break
            words = line.split()
            verb = words[0].lower() if words else ""
            if verb == "version":
                writer.write(b"VERSION " + vbytes + b"\r\n")
            elif verb in ("stats", "stat"):
                writer.write(b"STAT pid 4242\r\nSTAT version " + vbytes
                             + b"\r\nSTAT cur_connections 3\r\n"
                             b"STAT cmd_get 89012\r\nSTAT curr_items 14\r\n"
                             b"STAT bytes_read 9601337\r\nSTAT bytes_written 4400137\r\n"
                             b"END\r\n")
            elif verb == "get":
                key = words[1] if len(words) > 1 else ""
                if key in ("session:1", "sess:1"):
                    writer.write(b"VALUE session:1 0 25\r\n"
                                 b"sessid-a1b2c3d4e5f6\r\nEND\r\n")
                else:
                    writer.write(b"END\r\n")
            elif verb in ("set", "add", "replace"):
                writer.write(b"STORED\r\n")
            elif verb == "flush_all":
                writer.write(b"OK\r\n")
            elif verb == "quit":
                break
            else:
                writer.write(b"ERROR\r\n")
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# MongoDB — legacy OP_QUERY hello + OP_MSG, no auth wire-ups
# ---------------------------------------------------------------------------

def _bson_encode(pairs) -> bytes:
    out = b""
    for key, value in pairs:
        kb = key if isinstance(key, bytes) else key.encode("latin-1")
        kb += b"\x00"
        if isinstance(value, bool):
            out += b"\x08" + kb + (b"\x01" if value else b"\x00")
        elif isinstance(value, float):
            out += b"\x01" + kb + struct.pack("<d", value)
        elif isinstance(value, int) and -2 ** 31 <= value < 2 ** 31:
            out += b"\x10" + kb + struct.pack("<i", value)
        elif isinstance(value, int):
            out += b"\x12" + kb + struct.pack("<q", value)
        else:
            vb = (value if isinstance(value, bytes) else str(value).encode("utf-8")) \
                + b"\x00"
            out += b"\x02" + kb + struct.pack("<i", len(vb)) + vb
    body = out + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _mongo_reply(opcode: bytes, body: bytes, response_to: int) -> bytes:
    total = 16 + len(body)
    return (struct.pack("<iiii", total, 0, response_to, int.from_bytes(opcode, "little"))
            + body)


async def mongo_service(reader, writer, cfg):
    hello_pairs = [(b"ismaster", True), (b"isWritablePrimary", True),
                   (b"maxWireVersion", 13), (b"minWireVersion", 0),
                   (b"maxBsonObjectSize", 16777216), (b"ok", 1.0)]
    msg_ok_pairs = [(b"ok", 1.0), (b"isWritablePrimary", True),
                    (b"maxWireVersion", 13)]
    body_open = struct.pack("<ii", 0, 0)  # flags, cursorID, startingFrom
    try:
        while True:
            header = await reader.readexactly(16)
            op_code = struct.unpack("<i", header[12:16])[0]
            response_to = struct.unpack("<i", header[8:12])[0]
            if op_code == 2004:  # OP_QUERY (legacy hello)
                # flags(4) + fullCollectionName(cstring: skip 4+. = read to NUL)
                await reader.readexactly(4)
                name = b""
                while True:
                    ch = await reader.readexactly(1)
                    if ch == b"\x00":
                        break
                    name += ch
                await reader.readexactly(8)   # numberToSkip + numberToReturn
                body = b"\x00\x00\x00\x00" + body_open + _bson_encode(hello_pairs)
                writer.write(_mongo_reply(struct.pack("<i", 1), body, response_to))
            else:  # OP_MSG (2013) or anything else → generic ok reply
                body = b"\x00" + _bson_encode(msg_ok_pairs)
                reply = _mongo_reply(struct.pack("<i", 2013), body, response_to)
                writer.write(reply)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# MySQL — 5.7.31 handshake, accepts any auth and returns OK
# ---------------------------------------------------------------------------

def _mysql_packet(payload: bytes, seq: int) -> bytes:
    return len(payload).to_bytes(4, "little")[:3] + bytes([seq]) + payload


async def mysql_service(reader, writer, cfg):
    version = cfg.get("version", "5.7.31-log")
    salt1 = b"\x41\x42\x43\x44\x45\x46\x47\x48"
    salt1 = b"abCdEfGh"  # 8 printable salt chars
    salt2 = b"IJkLmNoPQrSt"
    vbytes = version.encode("latin-1")
    plugin = b"mysql_native_password"
    caps = 0x030F            # CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | ...
    caps_hi = 0x8000         # CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    payload = (b"\x0a" + vbytes + b"\x00"
               + struct.pack("<I", 4242)          # thread id
               + salt1 + b"\x00"
               + struct.pack("<H", caps)
               + b"\x21"                          # charset utf8
               + struct.pack("<H", 0x0002)        # status: autocommit
               + struct.pack("<H", caps_hi)
               + bytes([len(salt1) + len(salt2)]) + b"\x00" * 10
               + salt2 + b"\x00" + plugin + b"\x00")
    ok_packet = b"\x00\x00\x00" + struct.pack("<H", 0x0002) + struct.pack("<H", 0) \
        + b""  # OK: affected 0, last_id 0, status, warnings, (no session track)
    try:
        writer.write(_mysql_packet(payload, 0))
        await writer.drain()
        while True:
            data = await reader.read(4096)
            if not data:
                break
            if len(data) > 4:
                writer.write(_mysql_packet(ok_packet, 2))
                await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# PostgreSQL — 9.6.24, md5 auth demanded then always failed; version leaks
# ---------------------------------------------------------------------------

def _pg_message(msg_type: bytes, fields: list[tuple[str, str]]) -> bytes:
    payload = b""
    for k, v in fields:
        payload += k.encode("ascii") + b"\x00" + v.encode("latin-1") + b"\x00"
    payload += b"\x00"
    length = len(payload) + 4
    return msg_type + struct.pack(">i", length) + payload


async def postgres_service(reader, writer, cfg):
    version = cfg.get("version", "9.6.24")
    md5_hi = b"R" + struct.pack(">i", 4 + 4 + 4) + struct.pack(">i", 3) + b"\x01\x02\x03\x04"
    fail = _pg_message(b"E", [
        ("S", "FATAL"),
        ("V", "FATAL"),
        ("C", "28P01"),
        ("M", 'password authentication failed for user "admin"'),
        ("D", f"PostgreSQL {version}, lab edition"),
    ])
    try:
        data = await reader.read(4096)
        if not data:
            return
        writer.write(md5_hi)
        await writer.drain()
        # reject immediately — the password message may have arrived in the
        # same chunk; real servers answer the failed exchange with an error
        writer.write(fail)
        await writer.drain()
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(fail)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# rsync — module list open (older rsync daemons)
# ---------------------------------------------------------------------------

async def rsync_service(reader, writer, cfg):
    try:
        writer.write(b"@RSYNCD: 31.0\n")
        await writer.drain()
        line = await _read_line(reader)   # client picks a module
        if not line:
            return
        if line.strip() in ("#list", "rsync", ""):
            writer.write(b"backups\tAll customer backups (rw)\r\n"
                         b"@RSYNCD: EXIT\r\n")
        else:
            writer.write(b"@RSYNCD: AUTHREQD 4b2fH1X\r\n")
            await writer.drain()
            await reader.readline()       # client sends user:pass
            writer.write(b"@RSYNCD: ERROR: auth failed on module backups\r\n"
                         b"@RSYNCD: EXIT\r\n")
        await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# HTTP engine + vulnerable web behaviours
# ---------------------------------------------------------------------------

_ETCPASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
              "bin:x:1:1:bin:/bin:/bin/false\n"
              "daemon:x:2:2:daemon:/sbin:/bin/false\n"
              "www-data:x:33:33:www-data:/var/www:/bin/false\n")

_STACKTRACE = ("Django Version: 1.11.29\n"
               "Python Version: 2.7.16\n"
               "Traceback (most recent call last):\n"
               '  File "/usr/lib/python2.7/site-packages/django/core/handlers/'
               'exception.py", line 41, in inner\n'
               "    response = get_response(request)\n"
               '  File "/srv/legacy-app/intranet/views.py", line 87, in index\n'
               "    row = database.query(rowid=user_input)\n"
               '  File "/srv/legacy-app/intranet/db.py", line 23, in query\n'
               "    dbcur.execute(sql)\n"
               'OperationalError: no such column rowid\n')


def _dir_listing(path: str) -> bytes:
    rows = ("index.html      4102\nindex.php.bak  388\nbackup.tar.gz 3329\n"
            "flag.txt         24\ndocs/            --\n")
    body = (f"<html><head><title>Index of {path}</title></head><body>\n"
            f"<h1>Index of {path}</h1><pre>{rows}</pre>"
            "<hr><i>nginx/1.14.0 (Ubuntu)</i>\n</body></html>")
    return body.encode("latin-1")


def _default_page(cfg: dict, path: str) -> bytes:
    title = cfg.get("title", "Lab Web Server")
    heading = cfg.get("heading", title)
    extra_rows = cfg.get("body_rows", "")
    body = ('<!DOCTYPE html><html><head><title>%s</title></head><body>'
            "<h1>%s</h1>%s<p>Contact the <a href='mailto:admin@office.corp'>"
            "webmaster</a>.</p></body></html>"
            % (title, heading, extra_rows))
    return body.encode("latin-1")


def _json_response(obj, status=200) -> bytes:
    return json.dumps(obj).encode("utf-8")


async def http_service(reader, writer, cfg):
    """Config-driven vulnerable HTTP server.

    cfg keys:
      server          → Server: header (version disclosure / fingerprints)
      powered_by      → X-Powered-By: header (PHP EOL detection)
      title, heading, body_rows → default page rendering
      headers         → dict of extra response headers
      cookie          → string like "sessionid=..." (emitted without flags)
      dir_listing     → True → directory listing on directory paths
      stacktrace      → True → 500 page leaking a stack trace on odd paths
      traversal_cve   → None | "2.4.49" | "2.4.50" → Apache path-traversal
      routes          → list of ("prefix", [(status, ctype, body_bytes, path)])
    """
    server = cfg.get("server", "nginx/1.14.0")
    powered = cfg.get("powered_by")
    extra = cfg.get("headers") or {}
    cookie = cfg.get("cookie")
    routes = cfg.get("routes") or []

    def build_resp(status: int, reason: str, ctype: str,
                   body: bytes, keep_alive: bool) -> bytes:
        head = f"HTTP/1.1 {status} {reason}\r\n"
        head += f"Content-Type: {ctype}\r\n"
        head += f"Content-Length: {len(body)}\r\n"
        head += f"Server: {server}\r\n"
        if powered:
            head += f"X-Powered-By: {powered}\r\n"
        for k, v in extra.items():
            head += f"{k}: {v}\r\n"
        if cookie:
            head += f"Set-Cookie: {cookie}\r\n"
        head += "Connection: keep-alive\r\n\r\n" if keep_alive \
            else "Connection: close\r\n\r\n"
        return head.encode("latin-1") + body

    def pick(path: str, method: str):
        # 0. plain 404 mode (kubelet/docker): no page, behaviour through routes
        # 1. Apache traversal emulation (CVE-2021-41773 / CVE-2021-42013)
        tve = cfg.get("traversal_cve")
        lowered = path.lower()
        if tve and ("%2e" in lowered and (".%2e" in lowered
                                          or "%2e%2e" in lowered)
                    or ".%2e" in lowered
                    or "/../" in path or "..\\" in path):
            return 200, "OK", "text/html", _ETCPASSWD.encode()
        # 2. dir_listing: only explicit directory requests (…/) get a listing,
        #    like Apache with Options +Indexes
        if cfg.get("dir_listing") and path.endswith("/") \
                and path not in ("/", "/index.html", "/index.php"):
            return 200, "OK", "text/html", _dir_listing(path)
        # 3. routes: exact match unless the prefix ends with "/"
        for prefix, spec in routes:
            hit = (path == prefix or
                   (prefix.endswith("/") and path.startswith(prefix)))
            if hit:
                if callable(spec):
                    return (*spec(path, method),)
                status, ctype, body = spec
                return status, "OK", ctype, body
        # 4. stack-trace leak on unknown paths when enabled
        if cfg.get("stacktrace") and path not in ("/", "/index.html"):
            return (500, "Internal Server Error", "text/html",
                    ("<!DOCTYPE html><html><head><title>Application Error"
                     "</title></head><body><h1>Oops… Internal Server Error"
                     f"</h1><pre>{_STACKTRACE}</pre></body></html>").encode())
        # 5. default page (or plain 404)
        if cfg.get("plain_404"):
            return 404, "Not Found", "text/plain", b"404 page not found\n"
        return 200, "OK", "text/html", _default_page(cfg, path)

    try:
        while True:
            head_data = await reader.readuntil(b"\r\n\r\n")
            first = head_data.decode("latin-1", "replace").split("\r\n")[0]
            method, _, target = first.partition(" ")
            if not method or not target:
                break
            path = target.split("?")[0].split(" ")[0] or "/"
            status, reason, ctype, body = pick(path, method)
            head_len_only = (method.upper() == "HEAD")
            payload = build_resp(status, reason, ctype, b"" if head_len_only
                                 else body, True)
            writer.write(payload)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


# JSON route helpers used by machines.py -------------------------------------

def es_root_body(version="7.17.1") -> bytes:
    return _json_response({
        "name": "node-1", "cluster_name": "elasticsearch-leak",
        "cluster_uuid": "xs8D4QWfS72aQM1YkFx8wQ",
        "version": {"number": version, "build_flavor": "default",
                    "build_type": "tar", "build_hash": "lab",
                    "lucene_version": "8.11.1",
                    "minimum_wire_compatibility_version": "6.8.0"},
        "tagline": "You Know, for Search"})


def es_cat_body() -> bytes:
    return b"health status index       uuid                   pri rep docs.count\n" \
           b"yellow open   customers   xs8D4QWfS72aQM1YkFx8wQ   1   1      4311\n" \
           b"yellow open   transactions n1rOQ2nRQ72iI1ZM2Mlblw   1   1      8792\n"


def docker_version_body() -> bytes:
    return _json_response({"Version": "20.10.6", "ApiVersion": "1.41",
                           "MinAPIVersion": "1.12",
                           "GitCommit": "lab", "GoVersion": "go1.16.2",
                           "Os": "linux", "Arch": "amd64", "KernelVersion": "5.4.0",
                           "BuildTime": "2021-04-06T12:40:31.000000000+00:00"})


def docker_info_body() -> bytes:
    return _json_response({"ID": "lab", "Containers": 3, "Images": 12,
                           "OperatingSystem": "Ubuntu 20.04 LTS",
                           "OSType": "linux", "MemorySize": 8589934592})


def kubelet_pods_body() -> bytes:
    return _json_response({
        "kind": "PodList", "apiVersion": "v1", "metadata": {},
        "items": [{"metadata": {"name": "vault-unseal", "namespace": "kube-system"},
                   "status": {"phase": "Running", "podIP": "10.0.0.42"}}]})


# Registry so machines.py can reference handlers by dotted name --------------

HANDLERS = {
    "ftp": ftp_service,
    "telnet": telnet_service,
    "ssh": ssh_service,
    "smtp": smtp_service,
    "redis": redis_service,
    "memcached": memcached_service,
    "mongo": mongo_service,
    "mysql": mysql_service,
    "postgres": postgres_service,
    "rsync": rsync_service,
    "http": http_service,
}
