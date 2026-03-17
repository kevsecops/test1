"""
web_vulnerabilities.py — Web application vulnerabilities (Flask-based)

SAST findings:
  - B201 (Bandit): Flask app run with debug=True
  - B703 / B308 (Bandit): Jinja2 mark_safe / use of jinja2.Template with user input (SSTI)
  - B320 (Bandit): xml.etree.ElementTree — XXE vulnerable parser
  - B310 (Bandit): urllib.urlopen with user-controlled URL — SSRF
  - SonarQube S5131: XSS — user input rendered without escaping
  - SonarQube S5144: SSRF — server-side request forgery
  - SonarQube S2755: XXE — XML parsers should not be vulnerable to XXE
"""
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax import make_parser, handler

import jinja2
import requests
from flask import Flask, request, render_template_string
from markupsafe import Markup

app = Flask(__name__)


# -----------------------------------------------------------------------
# Finding 1: Flask running in debug mode — exposes interactive debugger
# -----------------------------------------------------------------------
if __name__ == "__main__":
    # SAST: debug=True exposes the Werkzeug interactive debugger (RCE)
    app.run(host="0.0.0.0", port=5000, debug=True)


# -----------------------------------------------------------------------
# Finding 2: Cross-Site Scripting (XSS) — user input in render_template_string
# -----------------------------------------------------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # SAST: user-controlled data rendered in template without escaping — XSS
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


# -----------------------------------------------------------------------
# Finding 3: Server-Side Template Injection (SSTI)
# -----------------------------------------------------------------------
@app.route("/render")
def render_page():
    user_template = request.args.get("template", "")
    # SAST: Jinja2 template built from user input — SSTI (RCE)
    t = jinja2.Template(user_template)
    return t.render()


# -----------------------------------------------------------------------
# Finding 4: Markup.escape bypass — deliberate use of Markup() on user input
# -----------------------------------------------------------------------
@app.route("/display")
def display():
    user_input = request.args.get("data", "")
    # SAST: Markup() marks string as safe without escaping — XSS
    safe_content = Markup(user_input)
    return render_template_string("<div>{{ content }}</div>", content=safe_content)


# -----------------------------------------------------------------------
# Finding 5: Server-Side Request Forgery (SSRF)
# -----------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # SAST: user-controlled URL passed to requests.get — SSRF
    response = requests.get(url)
    return response.text


# -----------------------------------------------------------------------
# Finding 6: SSRF via urllib
# -----------------------------------------------------------------------
@app.route("/proxy")
def proxy():
    target = request.args.get("target", "")
    # SAST: urllib.request.urlopen with user-controlled URL — SSRF
    with urllib.request.urlopen(target) as resp:
        return resp.read()


# -----------------------------------------------------------------------
# Finding 7: XML External Entity injection (XXE)
# ElementTree in CPython < 3.8 is not safe against XXE by default.
# -----------------------------------------------------------------------
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.data
    # SAST: xml.etree.ElementTree.fromstring with user data — XXE risk
    root = ET.fromstring(xml_data)
    return root.tag


# -----------------------------------------------------------------------
# Finding 8: XXE via SAX parser with external entity processing enabled
# -----------------------------------------------------------------------
def parse_xml_sax(xml_string):
    parser = make_parser()
    # SAST: external entities are NOT disabled — XXE
    parser.setFeature(handler.feature_external_ges, True)
    # (parsing would proceed with external entity expansion)


# -----------------------------------------------------------------------
# Finding 9: Open redirect
# -----------------------------------------------------------------------
@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")
    # SAST: user-controlled redirect target — open redirect
    from flask import redirect
    return redirect(next_url)


# -----------------------------------------------------------------------
# Finding 10: Path traversal via user-supplied filename
# -----------------------------------------------------------------------
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    # SAST: path traversal — unsanitized filename used in file open
    with open("uploads/" + filename, "rb") as f:
        return f.read()
