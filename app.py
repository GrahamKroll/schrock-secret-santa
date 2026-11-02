"""Schrock Secret Santa — Flask application.

PIN-based auth with per-participant lockout after repeated failures. All data
lookups use the authenticated session name, never a name supplied in the request
body. The giftee -> santa mapping is never exposed.
"""
import os
import sqlite3
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

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/names")
def names():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT name FROM participants ORDER BY name COLLATE NOCASE ASC"
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
        participant = conn.execute(
            "SELECT name, pin_hash FROM participants WHERE name = ?", (name,)
        ).fetchone()
        if participant is None:
            return jsonify({"error": "Unknown participant."}), 404

        # Check lockout first.
        attempt_row = conn.execute(
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
            conn.execute(
                "UPDATE participants SET pin_hash = ? WHERE name = ?",
                (pin_hash, name),
            )
            _clear_attempts(conn, name)
            conn.commit()
            session["name"] = name
            return jsonify({"ok": True, "first_login": True}), 200

        # Existing PIN — verify.
        if check_password_hash(participant["pin_hash"], pin):
            _clear_attempts(conn, name)
            conn.commit()
            session["name"] = name
            return jsonify({"ok": True}), 200

        # Wrong PIN — increment attempts.
        attempts = (attempt_row["attempts"] if attempt_row else 0) + 1
        locked_until = None
        if attempts >= MAX_ATTEMPTS:
            locked_until = now + LOCKOUT_SECONDS
        conn.execute(
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
    conn.execute(
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
        row = conn.execute(
            "SELECT name, giftee, wishlist FROM participants WHERE name = ?",
            (name,),
        ).fetchone()
        if row is None:
            session.clear()
            return jsonify({"error": "Not authenticated."}), 401

        giftee = row["giftee"]
        giftee_wishlist = ""
        if giftee:
            g = conn.execute(
                "SELECT wishlist FROM participants WHERE name = ?", (giftee,)
            ).fetchone()
            if g:
                giftee_wishlist = g["wishlist"] or ""

        return jsonify(
            {
                "name": row["name"],
                "giftee": giftee,
                "giftee_wishlist": giftee_wishlist,
                "own_wishlist": row["wishlist"] or "",
            }
        )
    finally:
        conn.close()


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
        conn.execute(
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


if __name__ == "__main__":
    app.run(debug=True, port=3000)
