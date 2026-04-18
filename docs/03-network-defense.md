# Network Defense

This document covers the network-layer controls that intercept malicious requests before they reach application code: the Flask request middleware and the Nginx reverse proxy configuration.

## Flask Request Middleware

```python
TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%2f|%5c)", re.IGNORECASE
)

@app.before_request
def block_traversal():
    raw = request.full_path
    if TRAVERSAL_PATTERNS.search(raw):
        abort(400)
```

The `@before_request` decorator registers a function that runs before every route handler. It inspects `request.full_path`, which includes the path and the raw query string — importantly, *before* URL decoding by Flask's routing layer. This is why both literal (`../`) and URL-encoded (`%2e%2e`) forms are included in the pattern.

`re.IGNORECASE` catches mixed-case encodings (`%2E%2E`, `%2E%2e`, etc.). The pattern covers:
- `../` — Unix relative traversal
- `..\` — Windows relative traversal
- `%2e%2e` — encoded dots (both slashes handled separately)
- `%2f` — encoded forward slash
- `%5c` — encoded backslash

This middleware does not replace the canonical path check in `get_safe_path` — it adds a separate, earlier rejection point that reduces the attack surface reaching the path resolution logic.

## Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name filelocker-vm;

    allow 127.0.0.1;
    deny all;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

**`allow 127.0.0.1; deny all;`** — This is an IP-based access control list. Only requests from the loopback interface are forwarded to Flask. Any direct HTTP request from an external IP to port 80 receives a 403 before the request reaches the application. Combined with the firewall rules that prevent port 5000 from being externally accessible, the Flask process is only reachable through Nginx.

**Proxy headers** — `X-Real-IP` and `X-Forwarded-For` ensure that the origin IP of the client is passed to Flask even though the connection arrives from `127.0.0.1`. This matters for logging and rate limiting.

## Why Two Layers at the Network Level

The middleware and Nginx controls are not redundant — they cover different threat models:

- **Middleware** operates on the HTTP content: it can inspect request paths and query strings for attack patterns
- **Nginx IP allowlist** operates on the network layer: it controls who can send requests at all

An attacker who finds a way to route traffic directly to port 5000 (bypassing Nginx) would still face the middleware and application-layer controls. An attacker whose traversal payload evades the regex pattern would still face canonical path checking. Each layer fails independently, and the system is only compromised when all layers fail simultaneously.
