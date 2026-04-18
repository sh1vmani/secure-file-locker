# Secure Coding Practices

This document explains the application-layer controls in `app.py` — why each function was written the way it was, and what attacks each control prevents.

## The Core Problem: Path Traversal

When a web application accepts a filename from user input and constructs a file path from it, an attacker can inject traversal sequences (`../`) to escape the intended directory. For example, if the server naively does:

```python
path = os.path.join("/var/www/safe_uploads", user_input)
return send_file(path)
```

Then `user_input = "../../etc/passwd"` produces `/var/www/safe_uploads/../../etc/passwd`, which resolves to `/etc/passwd`. This is CWE-22 (Improper Limitation of a Pathname to a Restricted Directory).

## Extension Allowlisting (`is_allowed_file`)

```python
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}

def is_allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS
```

This check runs before any path resolution. If a filename does not end in a known-safe extension, the request is rejected immediately. This is intentionally an allowlist (not a denylist) — the set of safe types is small and closed. A denylist approach (blocking `.sh`, `.py`, `.conf`, etc.) fails when attackers use unexpected extensions or double extensions.

Calling `os.path.splitext` rather than splitting on `.` handles edge cases like `.htaccess` (no extension returns empty string, which is not in the allowlist) and `file.tar.gz` (only `.gz` is extracted).

## Canonical Path Enforcement (`get_safe_path`)

```python
def get_safe_path(filename: str) -> str | None:
    normalized = os.path.normpath(os.path.join(BASE_DIR, filename))
    real = os.path.realpath(normalized)
    if not real.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return None
    return real
```

Three operations are applied in sequence:

1. **`os.path.join`** — anchors the filename to `BASE_DIR`, preventing it from being treated as an absolute path
2. **`os.path.normpath`** — collapses `..` sequences and redundant separators; `../../etc/passwd` becomes `/etc/passwd`
3. **`os.path.realpath`** — resolves symlinks to their final physical path

The `realpath` call is critical. Without it, an attacker who can create a symlink inside `safe_uploads` pointing to `/etc/` could bypass the `normpath` check. After resolving the real path, the function verifies that the result begins with `BASE_DIR + os.sep`. The trailing `os.sep` prevents a `safe_uploads_backup` directory from matching a `safe_uploads` prefix.

## 404 for Security Errors

Both `is_allowed_file` returning false and `get_safe_path` returning `None` produce HTTP 404, not 400 or 403. This is an intentional information-reduction choice: returning 403 reveals that the path exists but is forbidden; returning 404 reveals nothing about whether the target exists. Attackers enumerating the filesystem get no useful signal.

The middleware layer uses 400 for traversal pattern matches, which is acceptable because it fires before any path lookup occurs.

## Minimal Import Surface

The application imports only `os`, `re`, and `flask`. No file-processing libraries, no template rendering, no database drivers. A smaller import surface means fewer transitive dependencies and a reduced attack surface from supply chain vulnerabilities.
