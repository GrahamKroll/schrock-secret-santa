"""Schrock Secret Santa — Flask application.

PIN-based auth with per-participant lockout after repeated failures. All data
lookups use the authenticated session name, never a name supplied in the request
body. The giftee -> santa mapping is never exposed.

Database: works with SQLite locally (no DATABASE_URL) and PostgreSQL in
production (DATABASE_URL set, e.g. on Render). A small abstraction layer hides
the driver differences.
"""
import os
import time

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "schrock_santa.db")

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Database abstraction: SQLite locally, PostgreSQL in production.
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")  # set on Render; absent locally = SQLite

if DATABASE_URL:
    import psycopg2
    import psycopg2.extras

    PH = "%s"  # PostgreSQL placeholder style

    def get_db():
        # Render provides postgres://... but psycopg2 expects postgresql://...
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
        conn.autocommit = False
        return conn
else:
    import sqlite3

    PH = "?"  # SQLite placeholder style

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def db_execute(conn, sql, params=()):
    """Execute a statement across either driver and return a cursor.

    SQL is written with `?` placeholders; they are translated to the active
    driver's placeholder style (`%s` for PostgreSQL). The returned cursor
    supports `.fetchone()` / `.fetchall()`, yielding dict-like rows for both
    drivers (sqlite3.Row for SQLite, RealDictRow for PostgreSQL).
    """
    sql = sql.replace("?", PH)
    if DATABASE_URL:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur
    return conn.execute(sql, params)


# Pre-drawn pairings, embedded so a fresh production deployment is fully seeded
# without needing the local SQLite file. (Never printed or logged.)
PRODUCTION_PAIRINGS = {
    "Callie": "Jason",
    "Graham": "Callie",
    "Jason": "Ryan",
    "Ryan": "Sara",
    "Sara": "Sophie",
    "Sophie": "Graham",
}


def init_production_db():
    """Create tables and seed participants in the PostgreSQL database.

    Idempotent: safe to run on every startup. Existing rows (and any PINs /
    wish lists already saved) are preserved. PINs stay NULL until first login.
    """
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS participants (
                name          TEXT PRIMARY KEY,
                pin_hash      TEXT,
                giftee        TEXT,
                wishlist      TEXT NOT NULL DEFAULT '',
                last_login_at DOUBLE PRECISION,
                revealed_at   DOUBLE PRECISION
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                name         TEXT PRIMARY KEY,
                attempts     INTEGER NOT NULL DEFAULT 0,
                locked_until DOUBLE PRECISION
            )
            """
        )
        for giver, giftee in PRODUCTION_PAIRINGS.items():
            cur.execute(
                "INSERT INTO participants (name, pin_hash, giftee, wishlist) "
                "VALUES (%s, NULL, %s, '') "
                "ON CONFLICT (name) DO NOTHING",
                (giver, giftee),
            )
        conn.commit()
    finally:
        conn.close()


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")


@app.route("/")
def index():
    conn = get_db()
    try:
        rows = db_execute(
            conn, "SELECT name FROM participants ORDER BY LOWER(name) ASC"
        ).fetchall()
        names = [r["name"] for r in rows]
    finally:
        conn.close()
    return render_template("index.html", names=names)


@app.route("/names")
def names():
    conn = get_db()
    try:
        rows = db_execute(
            conn, "SELECT name FROM participants ORDER BY LOWER(name) ASC"
        ).fetchall()
    finally:
        conn.close()
    return jsonify([r["name"] for r in rows])


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    pin = (data.get("pin") or "").strip()

    if not name or not pin:
        return jsonify({"error": "Name and PIN are required."}), 400

    conn = get_db()
    try:
        participant = db_execute(
            conn, "SELECT name, pin_hash FROM participants WHERE name = ?", (name,)
        ).fetchone()
        if participant is None:
            return jsonify({"error": "Unknown participant."}), 404

        # Check lockout first.
        attempt_row = db_execute(
            conn,
            "SELECT attempts, locked_until FROM login_attempts WHERE name = ?",
            (name,),
        ).fetchone()
        now = time.time()
        if attempt_row and attempt_row["locked_until"]:
            if attempt_row["locked_until"] > now:
                remaining = int(attempt_row["locked_until"] - now)
                return (
                    jsonify(
                        {
                            "error": "Too many attempts. Try again later.",
                            "locked": True,
                            "seconds_remaining": remaining,
                        }
                    ),
                    429,
                )

        if participant["pin_hash"] is None:
            # First login — set the PIN.
            pin_hash = generate_password_hash(pin, method="pbkdf2:sha256")
            db_execute(
                conn,
                "UPDATE participants SET pin_hash = ? WHERE name = ?",
                (pin_hash, name),
            )
            _clear_attempts(conn, name)
            db_execute(
                conn,
                "UPDATE participants SET last_login_at = ? WHERE name = ?",
                (time.time(), name),
            )
            conn.commit()
            session["name"] = name
            return jsonify({"ok": True, "first_login": True}), 200

        # Existing PIN — verify.
        if check_password_hash(participant["pin_hash"], pin):
            _clear_attempts(conn, name)
            db_execute(
                conn,
                "UPDATE participants SET last_login_at = ? WHERE name = ?",
                (time.time(), name),
            )
            conn.commit()
            session["name"] = name
            return jsonify({"ok": True}), 200

        # Wrong PIN — increment attempts.
        attempts = (attempt_row["attempts"] if attempt_row else 0) + 1
        locked_until = None
        if attempts >= MAX_ATTEMPTS:
            locked_until = now + LOCKOUT_SECONDS
        db_execute(
            conn,
            "INSERT INTO login_attempts (name, attempts, locked_until) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET attempts = ?, locked_until = ?",
            (name, attempts, locked_until, attempts, locked_until),
        )
        conn.commit()

        if locked_until is not None:
            return (
                jsonify(
                    {
                        "error": "Too many attempts. Locked for 5 minutes.",
                        "locked": True,
                        "seconds_remaining": LOCKOUT_SECONDS,
                    }
                ),
                429,
            )
        return (
            jsonify(
                {
                    "error": "Incorrect PIN.",
                    "attempts_remaining": MAX_ATTEMPTS - attempts,
                }
            ),
            401,
        )
    finally:
        conn.close()


def _clear_attempts(conn, name):
    db_execute(
        conn,
        "INSERT INTO login_attempts (name, attempts, locked_until) "
        "VALUES (?, 0, NULL) "
        "ON CONFLICT(name) DO UPDATE SET attempts = 0, locked_until = NULL",
        (name,),
    )


@app.route("/me")
def me():
    name = session.get("name")
    if not name:
        return jsonify({"error": "Not authenticated."}), 401

    conn = get_db()
    try:
        row = db_execute(
            conn,
            "SELECT name, giftee, wishlist, revealed_at FROM participants WHERE name = ?",
            (name,),
        ).fetchone()
        if row is None:
            session.clear()
            return jsonify({"error": "Not authenticated."}), 401

        giftee = row["giftee"]
        giftee_wishlist = ""
        if giftee:
            g = db_execute(
                conn, "SELECT wishlist FROM participants WHERE name = ?", (giftee,)
            ).fetchone()
            if g:
                giftee_wishlist = g["wishlist"] or ""

        return jsonify(
            {
                "name": row["name"],
                "giftee": giftee,
                "giftee_wishlist": giftee_wishlist,
                "own_wishlist": row["wishlist"] or "",
                "revealed": row["revealed_at"] is not None,
            }
        )
    finally:
        conn.close()


@app.route("/me/reveal", methods=["POST"])
def mark_revealed():
    name = session.get("name")
    if not name:
        return jsonify({"error": "Not authenticated."}), 401
    conn = get_db()
    try:
        db_execute(
            conn,
            "UPDATE participants SET revealed_at = ? WHERE name = ? AND revealed_at IS NULL",
            (time.time(), name),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True}), 200


@app.route("/me/wishlist", methods=["POST"])
def save_wishlist():
    name = session.get("name")
    if not name:
        return jsonify({"error": "Not authenticated."}), 401

    data = request.get_json(silent=True) or {}
    wishlist = data.get("wishlist")
    if wishlist is None:
        wishlist = ""
    wishlist = str(wishlist)

    conn = get_db()
    try:
        db_execute(
            conn,
            "UPDATE participants SET wishlist = ? WHERE name = ?",
            (wishlist, name),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# Seed/upgrade the production database on startup (import time under gunicorn).
if DATABASE_URL:
    init_production_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False, port=int(os.environ.get("PORT", 3000)))
