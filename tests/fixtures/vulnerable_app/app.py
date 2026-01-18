"""Vulnerable Flask Application for MrZero Testing.

This application contains INTENTIONAL security vulnerabilities for testing purposes.
DO NOT deploy this application in any environment.

Vulnerabilities included:
1. SQL Injection (Line ~45)
2. Command Injection (Line ~65)
3. Insecure Deserialization (Line ~85)
4. Path Traversal (see utils.py)
5. XSS (see templates/index.html)
6. Hardcoded Secrets (see config.py)
"""

import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, render_template, jsonify

from config import DATABASE_PATH, SECRET_API_KEY
from utils import read_user_file

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # VULN: Hardcoded secret


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    """Home page."""
    return render_template("index.html")


# =============================================================================
# VULNERABILITY 1: SQL Injection
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# =============================================================================
@app.route("/user/<user_id>")
def get_user(user_id):
    """Get user by ID - VULNERABLE TO SQL INJECTION."""
    conn = get_db_connection()

    # VULNERABLE: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor = conn.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/search")
def search_users():
    """Search users - VULNERABLE TO SQL INJECTION."""
    search_term = request.args.get("q", "")

    conn = get_db_connection()
    # VULNERABLE: User input directly in SQL query
    query = "SELECT * FROM users WHERE username LIKE '%" + search_term + "%'"
    cursor = conn.execute(query)

    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify(users)


# =============================================================================
# VULNERABILITY 2: Command Injection
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# =============================================================================
@app.route("/ping")
def ping_host():
    """Ping a host - VULNERABLE TO COMMAND INJECTION."""
    host = request.args.get("host", "localhost")

    # VULNERABLE: User input directly passed to shell command
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)

    return jsonify(
        {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    )


@app.route("/execute")
def execute_command():
    """Execute system command - VULNERABLE TO COMMAND INJECTION."""
    cmd = request.args.get("cmd", "echo 'No command'")

    # VULNERABLE: Direct execution of user-provided command
    output = os.popen(cmd).read()

    return jsonify({"output": output})


# =============================================================================
# VULNERABILITY 3: Insecure Deserialization
# CWE-502: Deserialization of Untrusted Data
# =============================================================================
@app.route("/load_session", methods=["POST"])
def load_session():
    """Load user session - VULNERABLE TO INSECURE DESERIALIZATION."""
    session_data = request.get_data()

    # VULNERABLE: Deserializing untrusted data with pickle
    try:
        session = pickle.loads(session_data)
        return jsonify({"session": str(session)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/import_data", methods=["POST"])
def import_data():
    """Import serialized data - VULNERABLE TO INSECURE DESERIALIZATION."""
    import base64

    encoded_data = request.form.get("data", "")

    # VULNERABLE: Decoding and deserializing user-provided data
    try:
        raw_data = base64.b64decode(encoded_data)
        imported = pickle.loads(raw_data)
        return jsonify({"imported": len(imported) if hasattr(imported, "__len__") else 1})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =============================================================================
# VULNERABILITY 4: Path Traversal (via utils.py)
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# =============================================================================
@app.route("/file")
def get_file():
    """Get file contents - VULNERABLE TO PATH TRAVERSAL."""
    filename = request.args.get("name", "readme.txt")

    # VULNERABLE: Uses vulnerable function from utils.py
    try:
        content = read_user_file(filename)
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =============================================================================
# VULNERABILITY 5: Server-Side Request Forgery (SSRF)
# CWE-918: Server-Side Request Forgery
# =============================================================================
@app.route("/fetch")
def fetch_url():
    """Fetch URL content - VULNERABLE TO SSRF."""
    import urllib.request

    url = request.args.get("url", "")

    # VULNERABLE: Fetching arbitrary URLs provided by user
    try:
        response = urllib.request.urlopen(url)
        content = response.read().decode("utf-8")[:1000]
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =============================================================================
# VULNERABILITY 6: Reflected XSS (also in template)
# CWE-79: Improper Neutralization of Input During Web Page Generation
# =============================================================================
@app.route("/greet")
def greet():
    """Greet user - VULNERABLE TO REFLECTED XSS."""
    name = request.args.get("name", "Guest")

    # VULNERABLE: User input directly in response without escaping
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


@app.route("/comment", methods=["POST"])
def post_comment():
    """Post a comment - VULNERABLE TO STORED XSS."""
    comment = request.form.get("comment", "")

    # In a real app, this would be stored in DB
    # VULNERABLE: Stored XSS when comment is displayed
    return render_template("index.html", comment=comment)


# =============================================================================
# Additional vulnerable patterns for comprehensive testing
# =============================================================================
@app.route("/debug")
def debug_info():
    """Debug endpoint - VULNERABLE: Exposes sensitive information."""
    return jsonify(
        {
            "api_key": SECRET_API_KEY,  # VULN: Exposing secret
            "database": DATABASE_PATH,
            "env": dict(os.environ),  # VULN: Exposing environment
        }
    )


@app.route("/admin")
def admin_panel():
    """Admin panel - VULNERABLE: No authentication."""
    # VULNERABLE: No authentication check
    is_admin = request.args.get("admin", "false")

    if is_admin == "true":
        return jsonify({"users": ["admin", "user1", "user2"], "secrets": "exposed"})

    return jsonify({"error": "Not authorized"}), 403


if __name__ == "__main__":
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host="0.0.0.0", port=5000)
