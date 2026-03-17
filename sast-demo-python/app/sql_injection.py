"""
sql_injection.py — SQL Injection vulnerabilities

SAST findings:
  - B608 (Bandit): SQL query built via string formatting/concatenation
  - SonarQube S3649: SQL queries should not be vulnerable to injection attacks
"""
import sqlite3


DB_PATH = "users.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


# -----------------------------------------------------------------------
# Finding 1: SQL injection via % string formatting
# -----------------------------------------------------------------------
def find_user_by_name(username):
    conn = get_connection()
    cursor = conn.cursor()
    # SAST: user input directly interpolated into SQL — SQL injection
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)
    return cursor.fetchall()


# -----------------------------------------------------------------------
# Finding 2: SQL injection via f-string
# -----------------------------------------------------------------------
def find_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    # SAST: f-string interpolation in SQL query — SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


# -----------------------------------------------------------------------
# Finding 3: SQL injection via .format()
# -----------------------------------------------------------------------
def delete_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    # SAST: .format() interpolation in SQL — SQL injection
    query = "DELETE FROM users WHERE name = '{}'".format(username)
    cursor.execute(query)
    conn.commit()


# -----------------------------------------------------------------------
# Finding 4: SQL injection via concatenation with ORDER BY
# -----------------------------------------------------------------------
def list_users_sorted(sort_column):
    conn = get_connection()
    cursor = conn.cursor()
    # SAST: unsanitized ORDER BY clause — SQL injection
    query = "SELECT * FROM users ORDER BY " + sort_column
    cursor.execute(query)
    return cursor.fetchall()
