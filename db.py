"""Seed the SQLite database for the Acme Cloud Console lab."""

import os
import secrets
import sqlite3

from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "portal.db")

# Owner admin password. Set ACME_ADMIN_PASSWORD to pin it; otherwise a strong
# random one is generated (and printed to the server console at startup) so the
# host can log straight in. Players can't guess or crack it.
ADMIN_PASSWORD = os.environ.get("ACME_ADMIN_PASSWORD") or secrets.token_urlsafe(9)


def init_db():
    # Rebuild from scratch each run so the lab always starts clean.
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            display_name TEXT,
            email TEXT,
            role TEXT,
            note TEXT
        );
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            plan TEXT,
            ssn TEXT
        );
        CREATE TABLE tickets (
            id INTEGER PRIMARY KEY,
            subject TEXT,
            status TEXT,
            assignee TEXT,
            body TEXT
        );
        """
    )
    # Decoy support tickets (staff ticket lookup is a safe, parameterized decoy).
    db.executemany(
        "INSERT INTO tickets (subject, status, assignee, body) VALUES (?,?,?,?)",
        [
            ("Password reset request", "open", "helpdesk", "Customer cannot log in."),
            ("Billing discrepancy", "closed", "helpdesk", "Refund issued, resolved."),
            ("Increase API rate limit", "open", "helpdesk", "Customer wants higher quota."),
        ],
    )
    # Admin password is set by the host (ACME_ADMIN_PASSWORD) or random; it is
    # strong and not part of the puzzle -- you are NOT meant to crack it.
    db.execute(
        "INSERT INTO users (username, password_hash, display_name, email, role) "
        "VALUES (?,?,?,?,?)",
        ("admin", generate_password_hash(ADMIN_PASSWORD),
         "Site Admin", "admin@acme.example", "admin"),
    )
    # A seeded staff account (also not meant to be logged into directly).
    db.execute(
        "INSERT INTO users (username, password_hash, display_name, email, role) "
        "VALUES (?,?,?,?,?)",
        ("helpdesk", generate_password_hash(secrets.token_hex(16)),
         "Help Desk", "helpdesk@acme.example", "staff"),
    )
    db.executemany(
        "INSERT INTO customers (name, email, plan, ssn) VALUES (?,?,?,?)",
        [
            ("Alice Johnson", "alice@example.com", "Pro", "000-00-0001"),
            ("Bob Smith", "bob@example.com", "Basic", "000-00-0002"),
            ("Carol Lee", "carol@example.com", "Enterprise", "000-00-0003"),
        ],
    )
    db.commit()
    db.close()


if __name__ == "__main__":
    init_db()
    print("Database created at %s" % DB_PATH)
