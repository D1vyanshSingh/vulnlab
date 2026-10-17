"""TLS certificate provisioning for the lab.

Three deliberately-bad certificate profiles are available, generated at
runtime with the local openssl binary into vulnlab/.lab/certs/:

  selfsigned     — 10-year self-signed cert (CN does not match the scan host)
  expired        — notBefore 2020, notAfter 2021-01-01 (expired)
  notyetvalid    — notBefore 2030-01-01 (not yet valid)

No third-party crypto dependency: certificates come from openssl as long as
it is available (it ships with Git for Windows and every Linux/macos box).
"""

from __future__ import annotations

import os
import subprocess
import sys

CERT_SPECS = {
    "selfsigned": {
        "cn": "lab-selfsigned.local",
        "args": ["-days", "3650"],
        "note": "self-signed",
    },
    "expired": {
        "cn": "intern-web.corp",
        "args": ["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"],
        "note": "expired",
    },
    "notyetvalid": {
        "cn": "future.local",
        "args": ["-not_before", "20300101000000Z", "-not_after", "20400101000000Z"],
        "note": "not yet valid",
    },
}


def lab_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(os.path.dirname(here), ".lab")
    os.makedirs(os.path.join(d, "certs"), exist_ok=True)
    return d


def ensure_cert(kind: str) -> tuple[str, str]:
    """Return (cert_pem, key_pem) paths, generating them if absent."""
    if kind not in CERT_SPECS:
        raise ValueError(f"unknown cert kind {kind!r}")
    spec = CERT_SPECS[kind]
    certs = os.path.join(lab_dir(), "certs")
    cert = os.path.join(certs, f"{kind}.pem")
    key = os.path.join(certs, f"{kind}.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    openssl = _find_openssl()
    cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", key, "-out", cert, "-subj", f"/CN={spec['cn']}",
           *spec["args"]]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not (os.path.exists(cert) and os.path.exists(key)):
        raise RuntimeError(
            f"openssl failed to generate the {kind} lab certificate: "
            f"{proc.stderr.strip()[-400:]}")
    # drop CRLF variants older Windows openssl may emit
    for path in (cert, key):
        _normalize_pem(path)
    return cert, key


def _normalize_pem(path: str) -> None:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    normalized = text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    if normalized != text:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(normalized)


def _find_openssl() -> str:
    from shutil import which
    for name in ("openssl",):
        p = which(name)
        if p:
            return p
    for extra in ("/mingw64/bin/openssl.exe", "/usr/bin/openssl.exe",
                  "C:/Program Files/Git/mingw64/bin/openssl.exe"):
        if os.path.exists(extra):
            return extra
    raise RuntimeError(
        "openssl is not on PATH — the lab uses it to mint deliberately-broken "
        "certificates. Install Git for Windows (it bundles openssl) or add "
        "openssl to PATH and retry.")


def certificate_note(kind: str) -> str:
    return CERT_SPECS[kind]["note"]
