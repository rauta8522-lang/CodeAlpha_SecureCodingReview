# CodeAlpha_SecureCodingReview

A secure coding review and remediation project created for the **CodeAlpha Cyber Security Internship**.

## Contents
- `vulnerable_app.py`: Sample Flask app containing SQL injection, command injection, weak MD5 password hashing, and debug/secret misconfigurations.
- `secure_app.py`: Hardened version using parameterized SQL queries, input validation, `subprocess.run()` with argument lists, and salted password hashing.
- `AUDIT_REPORT.md`: Summary of vulnerabilities, risk impact, and remediation steps.

## Running Static Analysis (`bandit`)
```bash
pip install -r requirements.txt
bandit -r vulnerable_app.py
bandit -r secure_app.py

Run python secure_app.py