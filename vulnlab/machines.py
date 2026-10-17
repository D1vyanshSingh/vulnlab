"""The vulnerable machine catalog.

Every machine is a complete fake host: a coherent set of services with
hand-planted weaknesses for scanners and exploitation tools to find.
Service names, banner versions and behaviours map to real findings.
"""

from __future__ import annotations

from .engine import Machine, ServiceDef
from .handlers import (
    docker_info_body, docker_version_body, es_cat_body, es_root_body,
    kubelet_pods_body,
)

MACHINES: dict[str, Machine] = {}


def _machine(slug, name, description, *services):
    MACHINES[slug] = Machine(slug, name, description, list(services))


# ---------------------------------------------------------------------------
# 1. old-office-server — a 2008-era SOHO server nobody ever patched
# ---------------------------------------------------------------------------

_machine(
    "old-office-server", "Old Office Server",
    "2008-era SOHO box: vsftpd 2.3.4 with the smiley backdoor (CVE-2011-2523), "
    "telnet, regreSSHion-era OpenSSH (CVE-2024-6387), ancient Apache/PHP with "
    "directory listing, and a completely open Redis.",
    ServiceDef("ftp", "ftp", {"version": "2.3.4", "backdoor": True},
               port=21, fallback_port=2121),
    ServiceDef("telnet", "telnet", {"hostname": "old-office"},
               port=23, fallback_port=2023),
    ServiceDef("ssh", "ssh", {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-2ubuntu2"},
               port=22, fallback_port=2022),
    ServiceDef("smtp", "smtp", {"hostname": "mail.office.corp"},
               port=25, fallback_port=2025),
    ServiceDef("http", "http", {
        "server": "Apache/2.2.34 (CentOS)", "powered_by": "PHP/5.6.40",
        "title": "Office Intranet 2008", "heading": "Office Intranet",
        "body_rows": "<p>Shared documents live in /files (backup every Sunday).</p>",
        "dir_listing": True, "cookie": "sessionid=0e5abc1d7f2a+VULNLAB",
    }, port=80, fallback_port=2080),
    ServiceDef("redis", "redis", {"version": "4.0.14",
                                  "seed": {"session:1": "sessid-a1b2c3d4e5f6-admin",
                                           "uploads:pending": "3"}},
               port=6379, fallback_port=16379),
)

# ---------------------------------------------------------------------------
# 2. legacy-web-app — path traversal, stack traces, broken TLS
# ---------------------------------------------------------------------------

_machine(
    "legacy-web-app", "Legacy Web App",
    "Vulnerable web stack: Apache 2.4.49 with the live path-traversal bug "
    "(CVE-2021-41773, returns /etc/passwd on '.%2e' paths), directory "
    "listing, leaking 500 pages, session cookies without Secure/HttpOnly, "
    "an expired self-signed HTTPS endpoint that still accepts TLS 1.0, and "
    "an EOL nginx fronting a Django-ish stack-trace page.",
    ServiceDef("http-apache", "http", {
        "server": "Apache/2.4.49 (Unix)", "powered_by": None,
        "title": "ACME Legacy Portal", "heading": "ACME Legacy Portal",
        "dir_listing": True, "stacktrace": True, "traversal_cve": "2.4.49",
        "cookie": "sid=" + "VULNLAB-" + "8f1f98bc56dc5b7072204fd616d7e542",
        "routes": [("/", (200, "text/html",
                           b"<html><head><title>ACME Legacy Portal"
                           b"</title></head><body><h1>ACME Legacy "
                           b"Portal</h1><p>Earning since 2008."
                           b"</p></body></html>"))],
    }, port=8080, fallback_port=18080),
    ServiceDef("https-expired", "http", {
        "server": "Apache/2.2.34 (Unix)",
        "title": "Internweb Portal (secure)", "heading": "Internweb Portal",
        "dir_listing": True, "plain_404": True,
    }, port=8443, fallback_port=18443, tls="expired", legacy_tls=True),
    ServiceDef("http-nginx", "http", {
        "server": "nginx/1.14.0 (Ubuntu)", "stacktrace": True,
        "title": "Intranet Services", "heading": "Intranet Services",
    }, port=8181, fallback_port=18181, tls="selfsigned"),
)

# ---------------------------------------------------------------------------
# 3. cloud-leak-box — misconfigured cloud services, all wide open
# ---------------------------------------------------------------------------

_machine(
    "cloud-leak-box", "Cloud Leak Box",
    "A cloud node that leaked everything: plain-HTTP Docker API (full daemon "
    "control), Kubelet reading /pods, an open Elasticsearch cluster with real "
    "indices, plus unauthenticated Kibana and RabbitMQ consoles.",
    ServiceDef("docker", "http", {
        "server": "Docker/20.10.6 (linux)", "plain_404": True,
        "routes": [("/version", (200, "application/json", docker_version_body())),
                   ("/info", (200, "application/json", docker_info_body())),
                   ("/v1.41/version", (200, "application/json",
                                       docker_version_body())),
                   ("/", (404, "application/json",
                          b'{"message":"page not found"}'))],
    }, port=2375, fallback_port=22375),
    ServiceDef("kubelet", "http", {
        "server": "",          # kubelet does not advertise Server
        "plain_404": True,
        "routes": [("/pods", (200, "application/json", kubelet_pods_body())),
                   ("/runningpods/", (200, "application/json",
                                      kubelet_pods_body())),
                   ("/", (404, "text/plain",
                          b"404 page not found\n"))],
    }, port=10250, fallback_port=20250),
    ServiceDef("elasticsearch", "http", {
        "server": "Elastic/7.17.1",
        "routes": [("/", (200, "application/json", es_root_body())),
                   ("/_cat/indices?v", (200, "text/plain", es_cat_body()))],
    }, port=9200, fallback_port=29200),
    ServiceDef("kibana", "http", {
        "server": "Kibana/7.17.1", "title": "Kibana",
        "routes": [("/", (200, "text/html",
                          b"<html><head><title>Kibana</title></head><body>"
                          b"<div data-testid=kibanaWelcome>kibana</div>"
                          b"</body></html>"))],
    }, port=5601, fallback_port=25601),
    ServiceDef("rabbitmq", "http", {
        "server": "Cowboy", "title": "RabbitMQ Management",
        "routes": [("/", (200, "text/html",
                          b"<html><head><title>RabbitMQ Management</title>"
                          b"</head><body><div id=login-console>"
                          b"RabbitMQ Management UI</div></body></html>"))],
    }, port=15672, fallback_port=45672),
)

# ---------------------------------------------------------------------------
# 4. db-dumpster — every database installed on one box, none locked down
# ---------------------------------------------------------------------------

_machine(
    "db-dumpster", "DB Dumpster",
    "A database server that never met a password: MySQL 5.7 (EOL, any "
    "credentials accepted), PostgreSQL 9.6 (EOL, md5 auth always refused), "
    "open MongoDB (OP_QUERY/OP_MSG hello answered without auth), memcached "
    "with clear stats, and an rsync daemon listing an rw backups module.",
    ServiceDef("mysql", "mysql", {"version": "5.7.31-log"},
               port=3306, fallback_port=13306),
    ServiceDef("postgres", "postgres", {"version": "9.6.24"},
               port=5432, fallback_port=15432),
    ServiceDef("mongo", "mongo", {}, port=27017, fallback_port=22179),
    ServiceDef("memcached", "memcached", {"version": "1.6.9"},
               port=11211, fallback_port=21121),
    ServiceDef("rsync", "rsync", {}, port=873, fallback_port=1873),
)


def get(slug: str) -> Machine:
    try:
        return MACHINES[slug]
    except KeyError as exc:
        raise KeyError(f"no machine named {slug!r}; try: "
                       + ", ".join(sorted(MACHINES))) from exc


def machine_ports(machine: Machine) -> list[int]:
    return [s.port for s in machine.services if s.port is not None]
