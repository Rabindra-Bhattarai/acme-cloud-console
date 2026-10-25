# Acme Cloud Console — Multi-Tier Vulnerable Lab

A deliberately vulnerable Flask web app for **authorized** security practice,
built as a timed, flag-based challenge with a leaderboard. All data is fake.

Three privilege tiers — **user → staff → admin**. Your role is re-read from the
database on every request, so you can't just edit a cookie. Debug mode is off
and the search has an input filter, so there are no easy shortcuts.

## ⚠️ Hosting warning — read this

The finish line is **real remote code execution on the server**. Anyone who
completes the challenge can run commands on the host. **Do not run this on your
own machine or any network you care about.** Host it only in a **disposable,
isolated VM or container** (e.g. a throwaway cloud VM), firewalled to the game
port, that you can destroy afterwards.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Local play binds to `127.0.0.1:5000`. To host for others (isolated box only):

```bash
# set a stable owner-admin password and bind to all interfaces
ACME_ADMIN_PASSWORD=choose-a-strong-one ACME_HOST=0.0.0.0 ACME_PORT=5000 python app.py
```

### Docker (recommended for hosting)

Runs as an unprivileged `player` user so the RCE is confined to the container:

```bash
docker build -t acme-cloud .
docker run --rm -p 5000:5000 --hostname acme-cloud \
  -e ACME_ADMIN_PASSWORD=choose-a-strong-one acme-cloud
```

The container prints the owner admin login on startup. Players connect to
`http://<host-ip>:5000`. Destroy the container/VM when you're done. (With
`--rm` the leaderboard resets on stop; drop `--rm` to keep it between runs.)

On startup the server prints the **owner admin login** (`admin / <password>`) so
you can sign in directly to manage the box without playing.

## How to play

1. Enter a name and hit **Start** in the bottom bar — your timer begins.
2. **Register** an account. You start as `user`.
3. Work up through the tiers and find a way to run commands on the server. The
   way in is not labelled, and it won't show you its output — you'll have to be
   clever to confirm it and get data back out.
4. A completion **code** is hidden on the running server — it's never shown in
   the UI or sent over HTTP. Once you can run commands, go find it.
5. Paste the code into the bar. Your timer stops and your time lands on the
   **Top 10**.

Only hint: no single request gets you in, and not every input field is a bug.
Watch what each page *does* with your input, and chain what you learn.

## Rules

- Authorized targets only. If you host it, host it isolated (see warning above).
- The seeded `admin`/`helpdesk` accounts have strong, unknown passwords — they
  are not meant to be logged into or cracked directly.

## Files

- `app.py` — the app and all routes. `db.py` — challenge data (reseeded each run).
- `scores.py` / `scores.db` — leaderboard, kept separate so it survives restarts.
- The completion code lives only in the server process environment at runtime.
