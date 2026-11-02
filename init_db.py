"""Initialize the SQLite database from schema.sql.

Creates schrock_santa.db if it does not already exist. Running the schema is
idempotent (CREATE TABLE IF NOT EXISTS), so existing data is never overwritten.
"""
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "schrock_santa.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def init_db():
    existed = os.path.exists(DB_PATH)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()

    if existed:
        print(f"Database already present at {DB_PATH}; schema ensured (no data overwritten).")
    else:
        print(f"Database created at {DB_PATH}.")


if __name__ == "__main__":
    init_db()
