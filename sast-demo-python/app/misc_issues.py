"""
misc_issues.py — Miscellaneous SAST findings

SAST findings:
  - B110 (Bandit): try/except/pass — empty except block
  - B112 (Bandit): try/except/continue — silent exception in loop
  - B101 (Bandit): assert used for security / input validation
  - B108 (Bandit): probable insecure temp file usage (mktemp)
  - B322 (Bandit): input() in Python 2 (eval-like)
  - SonarQube S1854: unused variable assignment
  - SonarQube S2068: sensitive data logged
  - SonarQube S4790: weak hash for non-security use still flagged
  - SonarQube S5659: JWT decoded without signature verification
"""
import hashlib
import logging
import os
import tempfile

import jwt  # PyJWT — decode without verification


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# Finding 1: Empty except block (exception swallowing)
# -----------------------------------------------------------------------
def read_config(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        pass  # SAST: exception silently swallowed — B110


# -----------------------------------------------------------------------
# Finding 2: Logging sensitive data (password, token)
# -----------------------------------------------------------------------
def authenticate(username, password):
    # SAST: password written to log — sensitive data exposure
    logger.debug("Authenticating user=%s password=%s", username, password)
    return username == "admin" and password == "admin123"


# -----------------------------------------------------------------------
# Finding 3: assert used for access control / security check
# -----------------------------------------------------------------------
def admin_only(is_admin):
    # SAST: assert can be stripped with python -O — must not be used for security
    assert is_admin, "Access denied"
    return "Welcome, admin!"


# -----------------------------------------------------------------------
# Finding 4: Insecure temporary file (race condition — TOCTOU)
# -----------------------------------------------------------------------
def write_temp_data(data):
    # SAST: tempfile.mktemp() is insecure — use mkstemp() instead
    tmp_path = tempfile.mktemp(suffix=".tmp")
    with open(tmp_path, "w") as f:
        f.write(data)
    return tmp_path


# -----------------------------------------------------------------------
# Finding 5: Predictable temp directory with fixed name
# -----------------------------------------------------------------------
def get_cache_path(user_id):
    # SAST: fixed predictable path under /tmp — symlink attack risk
    path = f"/tmp/app_cache_{user_id}"
    os.makedirs(path, exist_ok=True)
    return path


# -----------------------------------------------------------------------
# Finding 6: JWT decoded without signature verification
# -----------------------------------------------------------------------
def decode_token(token):
    # SAST: verify=False disables signature check — JWT forgery possible
    return jwt.decode(token, options={"verify_signature": False})


# -----------------------------------------------------------------------
# Finding 7: Hardcoded IP address (server binding to all interfaces)
# -----------------------------------------------------------------------
BIND_ADDRESS = "0.0.0.0"  # SAST: binding to all interfaces — S1313


# -----------------------------------------------------------------------
# Finding 8: MD5 used for non-security checksum (still flagged by strict tools)
# -----------------------------------------------------------------------
def file_checksum(data: bytes) -> str:
    # SAST: MD5 flagged even for non-cryptographic use by some tools
    return hashlib.md5(data).hexdigest()


# -----------------------------------------------------------------------
# Finding 9: Sensitive information in exception message exposed to caller
# -----------------------------------------------------------------------
def connect_to_db(host, password):
    try:
        raise ConnectionError("connection refused")
    except ConnectionError as e:
        # SAST: sensitive credential included in raised exception message
        raise RuntimeError(f"Failed to connect to {host} with password {password}") from e


# -----------------------------------------------------------------------
# Finding 10: Insecure cookie (no secure / httponly flags) — Flask example
# -----------------------------------------------------------------------
def set_session_cookie(response, session_id):
    # SAST: missing Secure and HttpOnly flags on session cookie
    response.set_cookie("session", session_id)
    return response
