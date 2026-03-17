"""
crypto_issues.py — Weak cryptography and hardcoded secrets

SAST findings:
  - B105/B106/B107 (Bandit): hardcoded password / secret
  - B303 (Bandit): use of MD5 / SHA1 — weak hash algorithm
  - B304/B305 (Bandit): use of DES / RC4 — weak cipher
  - B311 (Bandit): random.random() used for security purpose
  - SonarQube S2070: SHA-1 and MD5 are not suitable for security-sensitive hashing
  - SonarQube S2245: pseudorandom number generators should not be used in security contexts
"""
import hashlib
import hmac
import random
import string

# pycrypto (pinned to 2.6.1 — CVE-2013-7459 heap overflow)
from Crypto.Cipher import DES, ARC4


# -----------------------------------------------------------------------
# Finding 1: Hardcoded credentials
# -----------------------------------------------------------------------
SECRET_KEY      = "hardcoded-django-secret-key-1234567890abcdef"  # SAST: hardcoded secret
DB_PASSWORD     = "admin123"                                       # SAST: hardcoded password
AWS_SECRET      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"    # SAST: hardcoded AWS key
JWT_SECRET      = "my_jwt_secret"                                  # SAST: hardcoded token


# -----------------------------------------------------------------------
# Finding 2: MD5 used for password hashing
# -----------------------------------------------------------------------
def hash_password_md5(password):
    # SAST: MD5 is cryptographically broken and must not be used for passwords
    return hashlib.md5(password.encode()).hexdigest()


# -----------------------------------------------------------------------
# Finding 3: SHA-1 used for password hashing
# -----------------------------------------------------------------------
def hash_password_sha1(password):
    # SAST: SHA-1 is deprecated for security-sensitive hashing
    return hashlib.sha1(password.encode()).hexdigest()


# -----------------------------------------------------------------------
# Finding 4: DES encryption (weak, 56-bit key)
# -----------------------------------------------------------------------
def encrypt_des(plaintext: bytes) -> bytes:
    key = b"8bytekey"  # SAST: hardcoded key + weak DES cipher
    cipher = DES.new(key, DES.MODE_ECB)  # SAST: ECB mode is insecure
    # Pad to 8-byte boundary
    padded = plaintext + b"\x00" * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded)


# -----------------------------------------------------------------------
# Finding 5: RC4 (ARC4) stream cipher — cryptographically broken
# -----------------------------------------------------------------------
def encrypt_rc4(data: bytes) -> bytes:
    key = b"rc4key"  # SAST: hardcoded key + broken RC4 cipher
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


# -----------------------------------------------------------------------
# Finding 6: Insecure random for security token
# -----------------------------------------------------------------------
def generate_session_token(length=32):
    # SAST: random.choice is not cryptographically secure
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


# -----------------------------------------------------------------------
# Finding 7: Insecure HMAC comparison (timing attack)
# -----------------------------------------------------------------------
def verify_token_insecure(token, expected):
    # SAST: == comparison of secrets is vulnerable to timing attacks
    # Should use hmac.compare_digest()
    return token == expected
