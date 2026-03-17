"""
command_injection.py — OS Command Injection vulnerabilities

SAST findings:
  - B602 (Bandit): subprocess call with shell=True
  - B605 (Bandit): os.system call
  - B607 (Bandit): start process with partial path
  - SonarQube S2076: OS commands should not be vulnerable to injection attacks
"""
import os
import subprocess


# -----------------------------------------------------------------------
# Finding 1: os.system with user-controlled input
# -----------------------------------------------------------------------
def ping_host(hostname):
    # SAST: os.system with unsanitized user input — command injection
    os.system("ping -c 1 " + hostname)


# -----------------------------------------------------------------------
# Finding 2: subprocess with shell=True and user input
# -----------------------------------------------------------------------
def compress_file(filename):
    # SAST: shell=True with user-controlled string — command injection
    subprocess.call("zip archive.zip " + filename, shell=True)


# -----------------------------------------------------------------------
# Finding 3: subprocess.Popen with shell=True
# -----------------------------------------------------------------------
def run_report(report_name):
    # SAST: shell=True with f-string user input — command injection
    proc = subprocess.Popen(f"/reports/{report_name}.sh", shell=True,
                            stdout=subprocess.PIPE)
    return proc.communicate()[0]


# -----------------------------------------------------------------------
# Finding 4: os.popen with user input
# -----------------------------------------------------------------------
def get_file_info(path):
    # SAST: os.popen with unsanitized input — command injection
    result = os.popen("ls -la " + path)
    return result.read()


# -----------------------------------------------------------------------
# Finding 5: eval() of user-supplied expression
# -----------------------------------------------------------------------
def calculate(expression):
    # SAST: B307 eval used — arbitrary code execution
    return eval(expression)


# -----------------------------------------------------------------------
# Finding 6: exec() of user-supplied code
# -----------------------------------------------------------------------
def run_script(code):
    # SAST: B102 exec used — arbitrary code execution
    exec(code)
