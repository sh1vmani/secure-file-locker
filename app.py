import os
import re
from flask import Flask, request, send_file, abort

app = Flask(__name__)

BASE_DIR = "/var/www/safe_uploads"

TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%2f|%5c)", re.IGNORECASE
)

ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}


@app.before_request
def block_traversal():
    raw = request.full_path
    if TRAVERSAL_PATTERNS.search(raw):
        abort(400)


def is_allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


def get_safe_path(filename: str) -> str | None:
    normalized = os.path.normpath(os.path.join(BASE_DIR, filename))
    real = os.path.realpath(normalized)
    if not real.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return None
    return real


@app.route("/file")
def serve_file():
    name = request.args.get("name", "")
    if not name:
        abort(400)
    if not is_allowed_file(name):
        abort(404)
    safe = get_safe_path(name)
    if safe is None:
        abort(404)
    if not os.path.isfile(safe):
        abort(404)
    return send_file(safe)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
