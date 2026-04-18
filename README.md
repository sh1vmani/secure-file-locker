# secure-file-locker

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Flask](https://img.shields.io/badge/flask-3.1.0-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> Lab project implementing defense-in-depth remediation for OWASP path traversal (WSTG-ATHZ-01).

## Overview

This repository documents a self-directed lab exploring how path traversal vulnerabilities manifest in web applications and how to eliminate them through layered controls. The application serves files from a constrained upload directory and demonstrates that no single control is sufficient — effective remediation requires coordinated defenses at the OS, application, and network layers.

The lab is structured around a minimal Flask application hardened against CWE-22 (Improper Limitation of a Pathname to a Restricted Directory). Each layer is independently capable of blocking known attack variants, producing a resilient system where bypassing one layer still leaves the others intact.

## Threat Model

Attack patterns defended against:

| Pattern | Description |
|---|---|
| `../../etc/passwd` | Classic relative traversal using `../` sequences |
| `..\..\..\windows\system32` | Windows-style backslash traversal |
| `%2e%2e%2f` | URL-encoded dot-slash sequence |
| `%2e%2e%5c` | URL-encoded dot-backslash sequence |
| Symlink escape | Symlink inside `BASE_DIR` pointing outside it |
| Extension bypass | Accessing `.sh`, `.py`, `.conf`, or other non-allowlisted types |

Goal: an attacker with arbitrary control over the `?name=` query parameter cannot read files outside `/var/www/safe_uploads` or files with non-allowlisted extensions.

## Architecture

```
Client Request
      |
      v
[ Cloudflare WAF ]          <-- Layer 3: Edge pattern blocking (managed rulesets)
      |
      v
[ Nginx Reverse Proxy ]     <-- Layer 2: IP allowlist, deny all by default
      |
      v
[ Flask Middleware ]        <-- Layer 2: Regex-based traversal pattern rejection
      |
      v
[ App Logic ]               <-- Layer 1: Extension allowlist + canonical path check
      |
      v
[ OS Permissions ]          <-- Layer 0: Least-privilege user, restricted directory
      |
      v
 File Response / 404
```

## Defense Layers

### Layer 0 — System (OS Permissions)

The upload directory `/var/www/safe_uploads` is owned by a dedicated service account with no shell access. The Flask process runs as this user; it has read-only access to `safe_uploads` and no access to sensitive system paths. Even if all application-layer controls were bypassed, the OS would deny reads to `/etc/passwd` or `/root/`.

Reference: [CIS Benchmark — Linux File Permissions](https://www.cisecurity.org/cis-benchmarks/)

### Layer 1 — Application (Flask)

Two independent controls operate here:

**Extension allowlist** (`is_allowed_file`): Only `.txt`, `.pdf`, `.jpg`, and `.png` are permitted. Any other extension returns 404 before path resolution begins.

**Canonical path check** (`get_safe_path`): The filename is joined with `BASE_DIR` via `os.path.join`, normalized with `os.path.normpath`, and then resolved to an absolute real path with `os.path.realpath` (which resolves symlinks). The result must begin with the real path of `BASE_DIR`. If it does not, the function returns `None` and the request is rejected.

Reference: [OWASP WSTG-AUTHZ-01](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include), [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

### Layer 2 — Network (Nginx + Middleware)

**Flask `@before_request` middleware**: A compiled regex scans the full request path — including query string — for traversal patterns (`../`, `..\`, `%2e%2e`, `%2f`, `%5c`) before any route handler executes. Matched requests receive HTTP 400 immediately.

**Nginx IP allowlist**: The reverse proxy is configured with `allow 127.0.0.1; deny all;`, meaning only requests originating from localhost reach the Flask process at all. Direct external access to port 5000 is blocked at the network boundary.

Reference: [MITRE ATT&CK T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)

### Layer 3 — Edge (Cloudflare WAF)

The architecture diagram includes a Cloudflare WAF layer at the edge. Managed rulesets (OWASP Core Rule Set) provide signature-based blocking of known traversal payloads before they reach the origin. This layer is configuration-driven and not implemented in this repository, but is included to represent a realistic production deployment posture.

## Setup

```bash
git clone https://github.com/sh1vmani/secure-file-locker.git
cd secure-file-locker

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Create the upload directory and a test file
mkdir -p /var/www/safe_uploads
echo "hello world" > /var/www/safe_uploads/test.txt

python app.py
# Serving on http://127.0.0.1:5000
```

Retrieve a file:
```
GET http://127.0.0.1:5000/file?name=test.txt
```

## Attack Simulation Results

| Test Payload | Blocking Layer | HTTP Response |
|---|---|---|
| `../../etc/passwd` | Flask middleware (regex) | 400 |
| `%2e%2e/%2e%2e/etc/passwd` | Flask middleware (regex) | 400 |
| `secret.sh` | App logic (extension allowlist) | 404 |
| `test.txt` | — (valid request) | 200 |

All traversal payloads are caught at the middleware layer before reaching path resolution. The extension allowlist catches non-traversal attempts at disallowed file types. Valid requests pass all layers.

## What I Learned

- **Defense in depth is not redundancy** — each layer blocks a distinct attack class; together they cover more surface than any single control
- **`os.path.realpath` is essential for symlink safety** — `normpath` alone does not resolve symlinks and can be bypassed by placing a symlink inside the safe directory
- **Regex on raw request paths catches encoded variants** that would otherwise reach the application decoded and bypass string-level checks
- **Extension allowlisting beats denylisting** — maintaining a denylist of dangerous extensions is brittle; an allowlist of known-safe types is closed by default
- **Nginx `deny all` as a default posture** means any misconfiguration in upstream services fails closed rather than open

## References

- [OWASP WSTG-AUTHZ-01: Path Traversal](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE ATT&CK T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/3.1.x/security/)
