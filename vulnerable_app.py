import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: Hardcoded secret key & weak MD5 password hashing
app.config["SECRET_KEY"] = "dev-secret-key-12345"


def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_hash TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerability 2: SQL Injection via f-string concatenation
    query = f"INSERT INTO users (username, password_hash) VALUES ('{username}', '{hash_password_weak(password)}')"
    cursor.execute(query)
    conn.commit()
    conn.close()
    return jsonify({"status": "registered", "user": username})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    pwd_hash = hash_password_weak(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerability 2: SQL Injection in authentication query
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password_hash = '{pwd_hash}'"
    user = cursor.execute(query).fetchone()
    conn.close()

    if user:
        return jsonify({"status": "authenticated", "user": user[1]})
    return jsonify({"status": "invalid credentials"}), 401


@app.route("/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Vulnerability 3: OS Command Injection via shell string formatting
    cmd = f"ping -n 1 {host}" if os.name == "nt" else f"ping -c 1 {host}"
    output = os.popen(cmd).read()
    return jsonify({"command": cmd, "output": output})


if __name__ == "__main__":
    init_db()
    # Vulnerability 4: Debug mode enabled in application code
    app.run(host="127.0.0.1", port=5050, debug=True)