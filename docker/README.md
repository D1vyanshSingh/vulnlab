# Vulnerable lab in real containers (Docker path)

The Python machines in this repo simulate the vulnerable hosts natively and run
anywhere without Docker. When you do have Docker, this compose file stands up
the *same topology* with **real software** instead of emulations — useful when
your tools depend on genuine OS behavior (real shells, real packet replies).

> You likely don't need this yet: Docker Desktop on Windows needs WSL2, and the
> current machine's WSL config reports an error. The simulated machines cover
> scanning and most exploitation at zero setup cost.

## What's in compose.yml

| Service | Container | Planted weakness |
|---|---|---|
| old-office ftp/backdoor | `vsftpd:2.3.4` build | CVE-2011-2523 smiley backdoor, anon FTP |
| old-office databases | `redis:5` (no requirepass) | unauthenticated Redis |
| old-office web | `httpd:2.2.34` + mod_php image | Apache 2.2/PHP 5.6 EOL, listing |
| legacy web | `httpd:2.4.49` | CVE-2021-41773 path traversal (2.4.49-2.4.50 prefix) |
| leak box | `dokken/ubuntu-20.04` + dockerd `-H tcp://0.0.0.0:2375` | plain Docker API (RCE) |
| leak box | `elasticsearch:7.17.1` (security disabled) | open cluster |
| leak box | `mongo:4.0` | unauthenticated MongoDB |
| db dumpster | `mysql:5.7` root/no password | EOL MySQL |
| db dumpster | `postgres:9.6` | EOL PostgreSQL |
| db dumpster | `memcached:1.6-alpine` | no SASL auth |

## Operation

```bash
cd docker
docker compose up -d            # start everything
docker compose ps               # what's listening
docker compose down             # stop and remove
docker compose down -v && rm -rf data   # nuke state too
```

Port conventions mirror the Python machines. GPU/low-port issues on Windows can
shift some bindings — `docker compose ps` shows the actual host ports.

## Caveats

- The MySQL container ships **no root password** (`MYSQL_ROOT_PASSWORD=` empty)
  and Redis without `requirepass` — exactly the vulnerability being modeled.
- The dockerd-in-docker service runs `privileged` and binds the Docker API on
  :2375 plain-HTTP. **Keep it on loopback** (default: `127.0.0.1:2377->2375`,
  behind your firewall, LAN unreachable).
- Everything is bound to `127.0.0.1` unless you edit `compose.yml`.
- NEVER expose these services to a network you do not own.
