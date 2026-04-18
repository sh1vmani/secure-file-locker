# System Hardening

This document covers the OS-level controls that form the foundational layer of the defense-in-depth model. Application and network controls can be bypassed; OS controls operate independently of the application code and provide a last line of defense.

## Service Account Provisioning

The Flask application runs under a dedicated system account (`filelocker`) with no login shell and no home directory. This account is created specifically for this service and granted no privileges beyond what the application requires. Running a web service as a high-privilege account (e.g., root) means a successful code execution vulnerability gives an attacker full system access. A dedicated low-privilege account limits the blast radius of such a compromise.

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin filelocker
```

## SSH Hardening

Remote access to the VM is restricted to SSH key authentication. Password authentication is disabled in `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
```

This eliminates credential brute-force as an attack path. The only way to gain SSH access is to possess the private key corresponding to an authorized public key.

## Upload Directory Permissions

The upload directory is owned by `root` and readable by the `filelocker` account only:

```bash
mkdir -p /var/www/safe_uploads
chown root:filelocker /var/www/safe_uploads
chmod 750 /var/www/safe_uploads
```

Files within the directory are `640` (owner read/write, group read). The `filelocker` user can read files but cannot create, modify, or delete them — a write vulnerability in the app cannot be used to plant malicious files in the served directory.

## Firewall Rules

The host firewall (ufw) is configured to deny all inbound traffic by default and explicitly allow only SSH and the Nginx port:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw enable
```

Flask binds to `127.0.0.1:5000` and never listens on an externally accessible interface. Even if Nginx were misconfigured, the firewall provides a backstop.

## Why Layering at the OS Level Matters

OS-level controls are enforced by the kernel, outside the application's execution context. A bug in Flask, a vulnerable dependency, or a logic error in `app.py` cannot override file system permissions or firewall rules. This is why system hardening is considered Layer 0 — it provides guarantees that higher-level controls can rely on but cannot replicate.
