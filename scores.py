"""Persistent timing / leaderboard store.

Kept in its OWN SQLite file so it survives restarts -- the challenge database
(db.py) is wiped and reseeded on every launch, but scores must persist.
"""

import os
import time
import secrets
import sqlite3

SCORES_PATH = os.path.join(os.path.dirname(__file__), "scores.db")


def _conn():
    c = sqlite3.connect(SCORES_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_scores():
    c = _conn()
    c.execute(
        """CREATE TABLE IF NOT EXISTS runs (
            game_id     TEXT PRIMARY KEY,
            handle      TEXT NOT NULL,
            started_at  REAL NOT NULL,
            finished_at REAL,
            seconds     REAL
        )"""
    )
    c.commit()
    c.close()


def start_run(handle):
    """Begin a timed run; return (game_id, started_at)."""
    handle = (handle or "anon").strip()[:24] or "anon"
    gid = secrets.token_urlsafe(12)
    now = time.time()
    c = _conn()
    c.execute(
        "INSERT INTO runs (game_id, handle, started_at) VALUES (?,?,?)",
        (gid, handle, now),
    )
    c.commit()
    c.close()
    return gid, now


def finish_run(gid):
    """Stop the clock the first time only; return (seconds, handle) or None."""
    if not gid:
        return None
    c = _conn()
    row = c.execute("SELECT * FROM runs WHERE game_id = ?", (gid,)).fetchone()
    if row is None:
        c.close()
        return None
    if row["finished_at"] is not None:  # idempotent: already finished
        c.close()
        return row["seconds"], row["handle"]
    now = time.time()
    secs = round(now - row["started_at"], 1)
    c.execute(
        "UPDATE runs SET finished_at = ?, seconds = ? WHERE game_id = ?",
        (now, secs, gid),
    )
    c.commit()
    c.close()
    return secs, row["handle"]


def top(n=10):
    c = _conn()
    rows = c.execute(
        "SELECT handle, seconds FROM runs WHERE finished_at IS NOT NULL "
        "ORDER BY seconds ASC LIMIT ?",
        (n,),
    ).fetchall()
    c.close()
    return [{"handle": r["handle"], "seconds": r["seconds"]} for r in rows]
