"""
Sample vulnerable application for BlindGuard demo.
THIS IS INTENTIONALLY INSECURE — used to demonstrate the security agent.
"""

import os
import pickle
import hashlib
import sqlite3
import yaml

# VULN: Hardcoded secrets
API_KEY = "sk-live-abc123def456ghi789jkl012mno345"
DATABASE_PASSWORD = "admin123!@#"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULN: Debug mode in production
DEBUG = True


def get_user(user_id):
    """VULN: SQL injection via string formatting."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


def search_users(name):
    """VULN: Another SQL injection."""
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    conn.execute(query)


def run_command(user_input):
    """VULN: Command injection."""
    os.system("echo " + user_input)


def process_backup(filename):
    """VULN: Command injection via subprocess."""
    import subprocess
    subprocess.call(f"tar -xf {filename}", shell=True)


def load_user_data(data_bytes):
    """VULN: Insecure deserialization with pickle."""
    return pickle.loads(data_bytes)


def load_config(config_string):
    """VULN: Insecure YAML loading."""
    return yaml.load(config_string)


def calculate_hash(data):
    """VULN: Using weak hash (MD5)."""
    return hashlib.md5(data.encode()).hexdigest()


def verify_token(token):
    """VULN: Using weak hash (SHA1)."""
    return hashlib.sha1(token.encode()).hexdigest()


def process_template(template_string):
    """VULN: Using eval on user input."""
    result = eval(template_string)
    return result


def execute_plugin(plugin_code):
    """VULN: Using exec on user input."""
    exec(plugin_code)


from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/redirect")
def open_redirect():
    """VULN: Open redirect."""
    url = request.args.get("url")
    return redirect(url)


# VULN: Running Flask in debug mode
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")


