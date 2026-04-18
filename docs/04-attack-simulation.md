# Attack Simulation

This document describes the test cases used to validate each defense layer and explains which layer is responsible for blocking each attack variant.

## Test Environment

- Flask running on `127.0.0.1:5000` with middleware active
- `BASE_DIR` set to `/var/www/safe_uploads`
- One valid test file: `test.txt` in `BASE_DIR`
- No other files present in `BASE_DIR`

Requests were issued directly to the Flask process (bypassing Nginx) to isolate application-layer behavior. Nginx and OS controls were validated separately.

## Test Cases

### TC-01: Classic Path Traversal

**Payload:** `GET /file?name=../../etc/passwd`

**Expected blocking layer:** Flask middleware (regex pattern match on `../`)

**Result:** HTTP 400

**Explanation:** The raw query string contains `../` which matches `TRAVERSAL_PATTERNS` before any route handler executes. The request is rejected at `@before_request` and never reaches `get_safe_path`.

---

### TC-02: URL-Encoded Traversal

**Payload:** `GET /file?name=%2e%2e/%2e%2e/etc/passwd`

**Expected blocking layer:** Flask middleware (regex pattern match on `%2e%2e`)

**Result:** HTTP 400

**Explanation:** The middleware inspects `request.full_path` before URL decoding. The encoded form `%2e%2e` is matched directly by the regex with `re.IGNORECASE`. If the middleware were absent, Flask would decode `%2e%2e` to `..` before passing the value to the route handler, so the middleware must operate on the pre-decode string.

---

### TC-03: Disallowed Extension

**Payload:** `GET /file?name=secret.sh`

**Expected blocking layer:** Application logic (extension allowlist)

**Result:** HTTP 404

**Explanation:** `secret.sh` contains no traversal sequences so it passes the middleware check. `is_allowed_file` extracts `.sh` and finds it absent from `ALLOWED_EXTENSIONS`. The function returns false and the route handler calls `abort(404)`.

---

### TC-04: Valid Request

**Payload:** `GET /file?name=test.txt`

**Expected blocking layer:** None (valid request)

**Result:** HTTP 200, file content returned

**Explanation:** No traversal patterns present. Extension `.txt` is in `ALLOWED_EXTENSIONS`. `get_safe_path` resolves the path, confirms it is within `BASE_DIR`, and returns the real path. `os.path.isfile` confirms the file exists. `send_file` returns the content.

---

### TC-05: Symlink Escape Attempt

**Payload:** Symlink `safe_uploads/link` -> `/etc/`; `GET /file?name=link/passwd`

**Expected blocking layer:** Application logic (`os.path.realpath` in `get_safe_path`)

**Result:** HTTP 404

**Explanation:** `link/passwd` passes the middleware (no traversal patterns). The extension check also blocks it since `passwd` has no extension and is therefore not in the allowlist. For a more targeted variant: if a symlink `safe_uploads/notes.txt` pointed outside `BASE_DIR`, `get_safe_path` would call `os.path.realpath`, which resolves the symlink to its target path, and the `startswith(BASE_DIR)` check would then fail, returning `None`.

---

## Layer-by-Layer Summary

| Attack Variant | Middleware | Extension Check | Path Check | OS |
|---|---|---|---|---|
| `../../etc/passwd` | BLOCKED (400) | n/a | n/a | n/a |
| `%2e%2e%2f` traversal | BLOCKED (400) | n/a | n/a | n/a |
| `.sh` file request | pass | BLOCKED (404) | n/a | n/a |
| Symlink escape | pass | varies | BLOCKED (404) | BLOCKED |
| Valid `.txt` request | pass | pass | pass | pass |

The table illustrates why multiple layers are valuable: different attack classes bypass different controls. A system with only the middleware would be vulnerable to symlink attacks; a system with only the path check would be vulnerable to extension-based information disclosure.
