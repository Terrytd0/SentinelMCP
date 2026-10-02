"""Deliberately vulnerable sample code, for exercising the real Semgrep scanner.

This exists so the SAST path can be verified against a real static analyser
rather than only against canned fixtures. It is the *target* of a scan, never
imported by the application, and it lives under `data/` so nothing in `backend/`
can reach it by accident.

Every construct here maps to a CWE the remediation engine knows about, so a
Semgrep finding on this file is a finding the rest of the pipeline can act on.
Do not "fix" these -- that is the whole point of the file.
"""

import os
import subprocess  # noqa: S404 - deliberately vulnerable, never executed

import requests  # noqa: F401 - deliberately pinned to a vulnerable version below
from flask import Flask, request  # noqa: F401

app = Flask(__name__)

HARDCODED_API_KEY = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"  # CWE-798


def run_report(expression):  # CWE-95
    """Execute a caller-supplied expression as code."""
    return eval(expression)  # noqa: S307


def search_reports(term):  # CWE-89
    """Build a query by string interpolation."""
    import sqlite3

    connection = sqlite3.connect("reports.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM reports WHERE title LIKE '%{term}%'")  # noqa: S608
    return cursor.fetchall()


def convert_to_pdf(path):  # CWE-78
    """Run a shell command with an interpolated path."""
    subprocess.run(f"soffice --headless --convert-to pdf {path}", shell=True, check=True)  # noqa: S602


def render_template(user_template):  # CWE-1336
    """Render a Jinja template from user input."""
    from jinja2 import Environment

    env = Environment()
    return env.from_string(user_template).render()


def make_reference():  # CWE-338
    """Generate a predictable order reference."""
    import random

    return f"ord_{random.randint(1, 1000000)}"


def fetch_followed_link(url):  # CWE-200
    """Follow redirects on a proxied request."""
    return requests.get(url, allow_redirects=True)


if __name__ == "__main__":
    app.run(debug=True)  # CWE-489
