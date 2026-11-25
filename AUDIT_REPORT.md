# Secure Coding Review Report — `vulnerable_app.py`

## Scope & Methodology
- **Target:** `vulnerable_app.py` (Python / Flask authentication and diagnostic endpoints)
- **Tools Used:** Static analysis (`bandit`) and manual code inspection.

## Key Findings

### 1. SQL Injection (High Severity)
- **Location:** `/register` and `/login` in `vulnerable_app.py`
- **Issue:** User-supplied `username` and `password_hash` are concatenated directly into SQL strings via f-strings.
- **Remediation:** Replaced string interpolation with parameterized queries (`?` placeholders) in `secure_app.py`.

### 2. OS Command Injection (High Severity)
- **Location:** `/ping` in `vulnerable_app.py`
- **Issue:** `host` query parameter is interpolated into a shell command string passed to `os.popen()`, allowing arbitrary command execution if metacharacters are injected.
- **Remediation:** Enforced strict regex allowlisting (`HOST_PATTERN`) and executed `subprocess.run()` with a discrete argument list (no shell interpretation).

### 3. Weak Password Hashing — MD5 (Medium/High Severity)
- **Location:** `hash_password_weak()` in `vulnerable_app.py`
- **Issue:** Unsalted MD5 is fast and vulnerable to precomputed lookup/rainbow tables and collisions.
- **Remediation:** Used `werkzeug.security.generate_password_hash()` and `check_password_hash()` with salted hashing.

### 4. Hardcoded Secret & Debug Mode (Medium Severity)
- **Location:** `app.config["SECRET_KEY"]` and `app.run(..., debug=True)` in `vulnerable_app.py`
- **Issue:** Static secret in source code and enabled debug mode risk exposing sensitive runtime information.
- **Remediation:** Loaded secret dynamically from environment variables and kept debug mode disabled by default.