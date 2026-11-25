import os
import re
import sqlite3
import subprocess
from flask import Flask, request, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", os.urandom(32).hex())

HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Secure Coding Review — CodeAlpha</title>
  <style>
    :root {
      --bg: #0b1020; --card: #121a30; --border: #24335c;
      --text: #e8eeff; --muted: #96a6cb; --accent: #6366f1;
      --ok: #22c55e; --warn: #facc15; --bad: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", system-ui, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    .container { max-width: 1080px; margin: 0 auto; }
    header { padding-bottom: 16px; margin-bottom: 20px; border-bottom: 1px solid var(--border); }
    header p { color: var(--muted); font-size: 0.92rem; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 18px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }
    .card h2 { font-size: 1.1rem; margin-bottom: 10px; }
    .item { background: #0d1427; border: 1px solid rgba(36,51,92,0.75); border-radius: 9px; padding: 11px 13px; margin-bottom: 10px; font-size: 0.88rem; }
    .badge { display: inline-block; padding: 2px 7px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; margin-right: 6px; }
    .b-vuln { background: rgba(239,68,68,0.18); color: #fca5a5; }
    .b-fix { background: rgba(34,197,94,0.18); color: #86efac; }
    label { display: block; font-size: 0.82rem; color: var(--muted); margin-top: 10px; margin-bottom: 4px; }
    input { width: 100%; padding: 9px 11px; border-radius: 8px; border: 1px solid var(--border); background: #0d1427; color: var(--text); }
    .row-btns { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
    button { background: var(--accent); color: #fff; border: none; padding: 9px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 0.86rem; }
    button.secondary { background: #1c2848; border: 1px solid var(--border); }
    pre { margin-top: 12px; background: #090e1c; border: 1px solid var(--border); border-radius: 9px; padding: 12px; font-size: 0.82rem; color: #cbd5e1; overflow-x: auto; white-space: pre-wrap; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Secure Coding Review &amp; Hardening</h1>
      <p>Vulnerability audit findings, remediations, and live endpoint testing for <code>secure_app.py</code></p>
    </header>

    <div class="grid">
      <div class="card">
        <h2>Audit Findings &amp; Remediations</h2>
        <div class="item"><span class="badge b-vuln">SQLi</span> Concatenated f-string SQL queries in auth routes.</div>
        <div class="item"><span class="badge b-fix">FIX</span> Parameterized queries (<code>?</code>) &amp; unique constraints.</div>
        <div class="item"><span class="badge b-vuln">CMDi</span> Shell command string via <code>os.popen()</code> on <code>/ping</code>.</div>
        <div class="item"><span class="badge b-fix">FIX</span> Strict regex allowlist + <code>subprocess.run()</code> arg list.</div>
        <div class="item"><span class="badge b-vuln">CRYPTO</span> Unsalted MD5 hashing &amp; hardcoded secret/debug mode.</div>
        <div class="item"><span class="badge b-fix">FIX</span> Werkzeug salted password hashing &amp; env-based config.</div>
      </div>

      <div class="card">
        <h2>Live Endpoint Tester</h2>
        <label>Username</label>
        <input id="user" value="anil_test" />
        <label>Password (min 8 chars)</label>
        <input id="pass" type="password" value="SecurePass123" />
        <div class="row-btns">
          <button onclick="callAuth('/register')">POST /register</button>
          <button class="secondary" onclick="callAuth('/login')">POST /login</button>
        </div>

        <label style="margin-top:16px;">Ping Host (try <code>127.0.0.1</code> or <code>127.0.0.1;whoami</code>)</label>
        <input id="host" value="127.0.0.1" />
        <div class="row-btns">
          <button onclick="callPing()">GET /ping</button>
        </div>

        <pre id="out">Response will appear here...</pre>
      </div>
    </div>
  </div>

  <script>
    async function callAuth(endpoint) {
      const username = document.getElementById("user").value;
      const password = document.getElementById("pass").value;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      document.getElementById("out").textContent = `Status ${res.status}:\\n` + JSON.stringify(data, null, 2);
    }

    async function callPing() {
      const host = encodeURIComponent(document.getElementById("host").value);
      const res = await fetch(`/ping?host=${host}`);
      const data = await res.json();
      document.getElementById("out").textContent = `Status ${res.status}:\\n` + JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>
"""


def get_db_connection():
    conn = sqlite3.connect("users_secure.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )


@app.route("/", methods=["GET"])
def home():
    return render_template_string(HTML_PAGE)


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or len(password) < 8:
        return jsonify({"error": "Valid username and password (min 8 chars) required"}), 400

    pwd_hash = generate_password_hash(password)

    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pwd_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({"status": "registered", "user": username}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row and check_password_hash(row["password_hash"], password):
        return jsonify({"status": "authenticated", "user": row["username"]})

    return jsonify({"status": "invalid credentials"}), 401


@app.route("/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "127.0.0.1").strip()

    if not HOST_PATTERN.match(host):
        return jsonify({"error": "Invalid hostname or IP format"}), 400

    args = ["ping", "-n", "1", host] if os.name == "nt" else ["ping", "-c", "1", host]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return jsonify({"host": host, "return_code": completed.returncode, "output": completed.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping request timed out"}), 504


if __name__ == "__main__":
    from waitress import serve

    init_db()
    print("[*] Secure App running at http://127.0.0.1:5050")
    serve(app, host="127.0.0.1", port=5050, threads=8)