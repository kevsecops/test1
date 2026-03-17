"""
insecure_deserialization.py — Unsafe deserialization vulnerabilities

SAST findings:
  - B301 (Bandit): pickle.loads — arbitrary code execution on untrusted data
  - B302 (Bandit): marshal.loads — arbitrary code execution
  - B506 (Bandit): yaml.load without Loader — arbitrary code execution
  - SonarQube S5135: Deserializing objects from an untrusted source is security-sensitive
"""
import marshal
import pickle

import yaml  # PyYAML 3.13 — CVE-2017-18342


# -----------------------------------------------------------------------
# Finding 1: pickle.loads on untrusted network/user data
# -----------------------------------------------------------------------
def deserialize_user_data(raw_bytes):
    # SAST: pickle can execute arbitrary code during deserialization
    return pickle.loads(raw_bytes)


# -----------------------------------------------------------------------
# Finding 2: pickle.load from user-supplied file path
# -----------------------------------------------------------------------
def load_model(filepath):
    # SAST: pickle.load on attacker-controlled file — RCE risk
    with open(filepath, "rb") as f:
        return pickle.load(f)


# -----------------------------------------------------------------------
# Finding 3: marshal.loads on untrusted data
# -----------------------------------------------------------------------
def load_bytecode(raw_bytes):
    # SAST: marshal is not safe for untrusted data
    return marshal.loads(raw_bytes)


# -----------------------------------------------------------------------
# Finding 4: yaml.load without safe Loader (CVE-2017-18342)
# -----------------------------------------------------------------------
def parse_config(yaml_string):
    # SAST: yaml.load() with untrusted input can execute arbitrary Python
    # Fix: yaml.safe_load(yaml_string)
    return yaml.load(yaml_string)


# -----------------------------------------------------------------------
# Finding 5: yaml.load from user-supplied file
# -----------------------------------------------------------------------
def load_yaml_file(filepath):
    with open(filepath, "r") as f:
        # SAST: yaml.load without Loader argument — CVE-2017-18342
        return yaml.load(f)
