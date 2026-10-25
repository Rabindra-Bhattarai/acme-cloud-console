"""
Acme Cloud Console -- INTENTIONALLY VULNERABLE multi-tier practice target.

Local, authorized security-testing practice ONLY. Fake data throughout.
Binds to 127.0.0.1 on purpose. Do not deploy or expose beyond localhost.

Three roles: user -> staff -> admin. Each tier is locked to the one below.
Reaching admin takes a full chain, not a single payload -- see README.md.
"""

import os
import re
import time
import secrets
import sqlite3
import subprocess

from flask import Flask, request, session, redirect, g, render_template, render_template_string

from db import init_db, DB_PATH, ADMIN_PASSWORD
from scores import init_scores, start_run, finish_run, top

app = Flask(__name__)
# Random key per start: the signing key is NOT the puzzle here, so no forging.
app.secret_key = os.urandom(16)

BANNER = "INTENTIONALLY VULNERABLE PRACTICE TARGET - fake data, localhost only"

# The completion code. Injected into the server PROCESS environment only --
# never written to disk, never sent over HTTP. So it can be discovered solely by
# poking around with the code execution you earn (e.g. dumping the environment).
def _make_flag():
    code = "ACME{" + secrets.token_hex(8) + "}"
    os.environ["SESSION_CODE"] = code
    return code


FLAG = _make_flag()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Load the logged-in user fresh from the DB every request, so the role can't
# be forged in the cookie -- it always reflects the database.
def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


@app.context_processor
def inject_globals():
    u = current_user()
    return {"banner": BANNER, "me": u, "role": (u["role"] if u else None)}


def require(role):
    """Return the user if they have at least `role`, else None."""
    order = {"user": 1, "staff": 2, "admin": 3}
    u = current_user()
    if u is None or order.get(u["role"], 0) < order[role]:
        return None
    return u


# --- Auth --------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --- Game timer + leaderboard ------------------------------------------------

@app.route("/start", methods=["POST"])
def start():
    data = request.get_json(silent=True) or request.form
    gid, started = start_run(data.get("handle"))
    resp = app.make_response({"ok": True, "started_at": started})
    resp.set_cookie("game_id", gid, httponly=True, samesite="Lax")
    return resp


@app.route("/leaderboard")
def leaderboard():
    return {"top": top(10)}


# Stage names are revealed one at a time, only after a player CLEARS that stage.
# Upcoming stages show a number, so the path is never spoiled in advance. The
# reveal is done server-side, so you can't read ahead in the response either.
STAGE_NAMES = ["User", "Staff", "RCE", "Admin", "Done"]  # stages 1..5


def _progress_level():
    u = current_user()
    if session.get("finished"):
        return 5
    if u and u["role"] == "admin":
        return 4
    if session.get("rce"):
        return 3
    if u and u["role"] == "staff":
        return 2
    if u:
        return 1
    return 0


@app.route("/progress")
def progress():
    level = _progress_level()  # 0..5
    steps = []
    for k in range(1, 6):
        if level >= k:                     # cleared -> reveal the real name
            steps.append({"t": STAGE_NAMES[k - 1], "s": "done"})
        elif level + 1 == k:               # the one you're working on -> number
            steps.append({"t": str(k), "s": "current"})
        else:                              # not reached yet -> number
            steps.append({"t": str(k), "s": "todo"})
    return {"level": level, "steps": steps}


# Flag check for the completion banner. The flag is never sent to the client --
# you must recover it from the server (via the RCE stage) first. A correct flag
# also stops the player's timer and records it on the leaderboard.
@app.route("/submit", methods=["POST"])
def submit_flag():
    data = request.get_json(silent=True) or request.form
    ok = (data.get("flag") or "").strip() == FLAG
    result = {"ok": ok}
    if ok:
        session["finished"] = True
        done = finish_run(request.cookies.get("game_id"))
        if done:
            result["seconds"], result["handle"] = done
    return result


# Open registration. Everyone starts as a plain "user".
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        from werkzeug.security import generate_password_hash
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Username and password required."
        else:
            try:
                db = get_db()
                cur = db.execute(
                    "INSERT INTO users (username, password_hash, display_name, email, role) "
                    "VALUES (?,?,?,?,?)",
                    (username, generate_password_hash(password), username, "", "user"),
                )
                db.commit()
                session["uid"] = cur.lastrowid
                return redirect("/dashboard")
            except sqlite3.IntegrityError:
                error = "That username is taken."
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        from werkzeug.security import check_password_hash
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["uid"] = row["id"]
            return redirect("/dashboard")
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# --- Tier 1: user ------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect("/login")
    return render_template("dashboard.html")


# Profile update. VULNERABLE: mass assignment. The only guard is a
# case-sensitive removal of the literal key "role" -- so "ROLE" slips through,
# and SQLite treats the column name case-insensitively.
@app.route("/profile", methods=["GET", "POST"])
def profile():
    u = current_user()
    if not u:
        return redirect("/login")
    saved = False
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form.to_dict()
        data.pop("role", None)  # "security": users may not change their role

        allowed = {"display_name": "display_name", "email": "email", "role": "role"}
        updates = {}
        for key, value in data.items():
            col = allowed.get(key.lower())
            if col:
                updates[col] = value
        # This path lets you escalate yourself only as far as staff. Reaching
        # admin is NOT possible here -- that takes the later stages.
        if updates.get("role") not in (None, "user", "staff"):
            updates.pop("role", None)
        if updates:
            sets = ", ".join("%s = ?" % c for c in updates)
            params = list(updates.values()) + [u["id"]]
            db = get_db()
            db.execute("UPDATE users SET %s WHERE id = ?" % sets, params)
            db.commit()
            saved = True
        u = current_user()
    return render_template("profile.html", saved=saved, u=u)


# User notes -- looks like a stored-content sink (XSS/SSTI bait), but Jinja
# auto-escapes it and the write is parameterized. A decoy: no bug here.
@app.route("/notes", methods=["GET", "POST"])
def notes():
    u = current_user()
    if not u:
        return redirect("/login")
    saved = False
    if request.method == "POST":
        body = request.form.get("note", "")
        db = get_db()
        db.execute("UPDATE users SET note = ? WHERE id = ?", (body, u["id"]))
        db.commit()
        saved = True
        u = current_user()
    return render_template("notes.html", u=u, saved=saved)


# --- Tier 2: staff -----------------------------------------------------------

# Staff-only customer search. VULNERABLE: blind boolean SQL injection.
# Only "found / no results" leaks back, so you extract data one bit at a time.
# A naive keyword filter blocks UNION / comments / time functions, so canned
# tooling trips -- a comment-less boolean injection still gets through.
_SEARCH_BLOCK = re.compile(r"(--|/\*|\*/|#|\bunion\b|\bsleep\b|pg_sleep|benchmark|waitfor|randomblob)", re.I)


@app.route("/staff/search")
def staff_search():
    if not require("staff"):
        return render_template("forbidden.html", need="staff"), 403
    q = request.args.get("q")
    result = None
    if q is not None:
        if _SEARCH_BLOCK.search(q):
            result = "blocked"
        else:
            sql = "SELECT id FROM customers WHERE name = '%s'" % q
            try:
                rows = get_db().execute(sql).fetchall()
                result = "found" if rows else "none"
            except sqlite3.Error:
                result = "error"
    return render_template("staff_search.html", q=q, result=result)


# Staff ticket lookup -- SAFE (parameterized query, staff are allowed to see all
# tickets). A decoy sitting right next to the injectable customer search, so an
# attacker can't tell at a glance which "lookup" feature is the vulnerable one.
@app.route("/staff/ticket")
def staff_ticket():
    if not require("staff"):
        return render_template("forbidden.html", need="staff"), 403
    tid = request.args.get("id")
    ticket = None
    if tid is not None:
        try:
            ticket = get_db().execute(
                "SELECT * FROM tickets WHERE id = ?", (tid,)
            ).fetchone()
        except sqlite3.Error:
            ticket = None
    return render_template("staff_ticket.html", tid=tid, ticket=ticket)


# Network diagnostics -- "is this host reachable from the server?" VULNERABLE:
# BLIND OS command injection. The host is concatenated into a shell command and
# the output is NEVER returned, so you confirm execution by timing or a side
# effect (e.g. write a file into the web-served static dir, then fetch it). This
# is the hidden RCE -- it is not labelled, and nothing is echoed back.
@app.route("/staff/diagnostics", methods=["GET", "POST"])
def staff_diagnostics():
    if not require("staff"):
        return render_template("forbidden.html", need="staff"), 403
    done = False
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        if re.search(r"[&|;`$><\n]", host):
            session["rce"] = True  # they're exploiting the injection (progress)
        ping_flag = "-n" if os.name == "nt" else "-c"
        cmd = "ping %s 1 %s" % (ping_flag, host)
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=25)
        except Exception:
            pass
        done = True  # blind: the command's output is deliberately discarded
    return render_template("staff_diagnostics.html", done=done, host=host)


# --- Tier 3: admin -----------------------------------------------------------

# Break-glass admin access: present the completion code (which lives only in the
# server's process environment -- you get it via the RCE above) to log in as
# admin. The code is NOT in the database, so the SQLi can't reveal it.
@app.route("/admin/recover", methods=["GET", "POST"])
def admin_recover():
    msg = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if code and code == FLAG:
            row = get_db().execute(
                "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
            ).fetchone()
            if row:
                session["uid"] = row["id"]
                return redirect("/admin")
        msg = "Recovery code rejected."
    return render_template("admin_recover.html", msg=msg)


@app.route("/admin")
def admin():
    u = require("admin")
    if not u:
        return render_template("forbidden.html", need="admin"), 403
    users = get_db().execute("SELECT username, role, email FROM users").fetchall()
    return render_template("admin.html", users=users)


if __name__ == "__main__":
    init_scores()   # persistent leaderboard (survives restarts)
    init_db()       # challenge data (reseeded every launch)
    host = os.environ.get("ACME_HOST", "127.0.0.1")
    port = int(os.environ.get("ACME_PORT", "5000"))
    print("\n*** %s ***" % BANNER)
    print("Owner admin login:  admin / %s" % ADMIN_PASSWORD)
    print("Serving on http://%s:%s   (debug OFF)\n" % (host, port))
    # debug=False: no reloader, no Werkzeug console, no stack-trace source leak.
    # threaded=True so multiple players can connect at once.
    app.run(host=host, port=port, debug=False, threaded=True)
