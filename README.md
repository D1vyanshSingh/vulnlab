# vulnlab

**Deliberately vulnerable machines for security-tool testing.**

vulnlab spins up complete fake hosts — each a coherent set of insecure
services — on real listening ports, so your scanners, exploitation tools and
pipelines have something honest to shoot at. It is a standalone companion to a
network vulnerability scanner like [vulnscan](https://github.com/D1vyanshSingh).

```
python -m vulnlab list                     # show the catalog
python -m vulnlab start old-office-server  # one machine
python -m vulnlab start --all              # every machine at once
python -m vulnlab status                   # what's running, which ports
python -m vulnlab stop --all               # stop background instances
python -m vulnlab ports legacy-web-app     # port list for pipelines
```

Everything runs in a single Python process, uses **only the standard
library**, and binds to `127.0.0.1` by default.

**This is a lab tool for authorized testing on your own machine. The
vulnerabilities are planted on purpose. Never bind it to a public interface
(`--host 0.0.0.0`) on a network you do not own.**

## The machine catalog

| Machine | Story | Planted weaknesses |
|---|---|---|
| [old-office-server](vulnlab/machines.py) | 2008 SOHO box nobody patched | vtftpd **2.3.4 smiley backdoor** (CVE-2011-2523 — send `USER <ident>:) ` then connect to port 6200 for a fake root shell), anonymous FTP, telnet, OpenSSH 9.6p1 (regreSSHion-range banner), ancient Apache 2.2/PHP 5.6 with directory listing, **open Redis** (INFO, GET/SET live), VRFY-leaking SMTP |
| legacy-web-app | vulnerable web stack | **live CVE-2021-41773 path traversal emulation** (`.%2e` paths return /etc/passwd), directory listing, 500 pages leaking a Django stack trace, session cookies with **no Secure/HttpOnly**, **expired self-signed TLS** with legacy TLS 1.0 offered, EOL nginx |
| cloud-leak-box | the misconfigured cloud node | plain-HTTP **Docker daemon API** (`/version`, `/info`), Kubelet `/pods` JSON, **open Elasticsearch cluster** (root + `/_cat/indices`), unauthenticated Kibana & RabbitMQ consoles |
| db-dumpster | every database, no passwords | MySQL 5.7 handshake (accepts any auth, EOL), PostgreSQL 9.6 md5 challenge → always "password authentication failed" (leaks version), open **MongoDB** (OP_QUERY + OP_MSG hello), no-auth **memcached** (stats + keys), rsync daemon listing an `rw backups` module |

## Scan it with any tool

```bash
python -m vulnlab start --all
# each machine prints its own suggested scan line, e.g.:
python -m vulnscan 127.0.0.1 -p 21,22,23,25,6379      # → ~4 findings
python -m vulnscan 127.0.0.1 -p 8080,8443,8181        # → ~26 findings
python -m vulnscan 127.0.0.1 -p 2375,10250,9200,5601,15672
python -m vulnscan 127.0.0.1 -p 3306,5432,27017,11211,873
```

The emulations are designed to be detected *by the same rules real networks
trigger*: banners, live command exchanges (Redis INFO, memcached stats, FTP
USER/PASS), HTTP fingerprints, TLS certificate dates and wire-protocol
handshakes (MySQL/PostgreSQL/MongoDB). Verified against vulnscan's 34 rules:
every planted weakness above is detected, with severities matching reality
(critical for open Redis/Docker/2.3.4 backdoor, high for anon FTP/expired
cert, …).

## Architecture

```
vulnlab/
  handlers.py   # async service emulations (ftp, ssh, smtp, redis, mongo, http …)
  engine.py     # port binding (with Windows fallbacks), TLS contexts, state file
  machines.py   # the catalog: 4 machines, ~19 services
  certs.py      # mints self-signed / EXPIRED / not-yet-valid cert at runtime
  cli.py        # list / start / status / stop / ports
tests/
  test_vulnlab.py  # 22 wire-level unittests (no external deps)
docker/
  compose.yml   # same topology with real containers (needs Docker)
```

Two things worth knowing:

- **Windows port handling.** Some ports (21, 80…) can be reserved by Windows.
  Every service declares a fallback port (`:21 → :2121`) and `start` prints
  `(port 21 reserved, using 2121)`. Fallbacks are chosen so **all four machines
  can run simultaneously without collisions**. Port-keyed detection rules (e.g.
  Redis requires 6379) only hold on the primary port — banners carry the rest.
- **Certificates are minted at runtime** with your local `openssl` (ships with
  Git for Windows) into `.lab/certs/` — an *actually expired* cert, a *not yet
  valid* one, and a plain self-signed.

## Where simulated is enough — and where it isn't

Simulated machines are perfect for: scanner tuning, false-positive checks,
report formatting, CI smoke-tests, CVE-range matching, headers/cookie checks,
banner fuzzing and most exploitation logic.

Reaching for real containers (the `docker/` path) when: a tool needs a real
OS response, real TLS renegotiation, genuine packet timing, or shell sessions
that survive weird input.

## Testing

```bash
python -m unittest discover -s tests      # 22 tests, no dependencies
```

## License

MIT — see [LICENSE](LICENSE).
