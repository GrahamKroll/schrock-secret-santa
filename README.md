# Schrock Secret Santa 🎅

A small festive Flask web app for a 6-person Secret Santa exchange. Each person
signs in with a self-chosen 4-digit PIN, sees who they're buying for, views their
giftee's wish list, and maintains their own wish list. The giftee → santa mapping
is never revealed to anyone.

Participants: Jason, Sara, Callie, Ryan, Sophie, Graham

## Features

- PIN-based login (PIN chosen on first sign-in, then reused)
- PINs are **hashed** (`pbkdf2:sha256`) — never stored in plain text
- Lockout after 5 failed attempts → 5-minute cooldown
- All data lookups use the authenticated **session** name, never a request-body name
- Festive, mobile-friendly single-page UI (vanilla JS + fetch, no framework)

## Run locally

```bash
cd schrock_secret_santa
python -m venv venv && source venv/bin/activate   # optional
pip install -r requirements.txt

cp .env.example .env            # set SECRET_KEY to a long random string
python init_db.py               # create schrock_santa.db
python draw.py                  # run the one-time draw and seed participants
flask run                       # or: python app.py   (serves on port 3000)
```

Then open the printed URL (default http://127.0.0.1:5000 for `flask run`, or
http://127.0.0.1:3000 for `python app.py`).

> Note: the draw script prints only `Draw complete. X participants seeded.` — it
> never reveals any pairings. Re-running `draw.py` only updates the `giftee`
> assignments; existing PINs and wish lists are preserved.

## Environment variables

| Var          | Purpose                                                      |
|--------------|-------------------------------------------------------------|
| `SECRET_KEY` | Flask session signing key. Use a long random string in prod.|

See `.env.example`.

## File structure

```
app.py               Flask application (routes + auth)
draw.py              One-time draw script (seeds giftees)
schema.sql           SQLite schema
init_db.py           Creates the DB from schema.sql (won't overwrite)
templates/index.html Single-page festive frontend
requirements.txt     Python dependencies
.env.example         Example environment variables
```

## API routes

| Method | Path           | Description                                             |
|--------|----------------|---------------------------------------------------------|
| GET    | `/`            | Serves the single-page app                              |
| GET    | `/names`       | JSON list of participant names (sorted)                 |
| POST   | `/login`       | `{name, pin}` → sets session; handles first-login/lockout |
| GET    | `/me`          | Session-only: `{name, giftee, giftee_wishlist, own_wishlist}` |
| POST   | `/me/wishlist` | Session-only: `{wishlist}` → saves own wish list        |
| GET    | `/logout`      | Clears session, redirects to `/`                        |

## Swapping to Supabase (production)

For deployment (e.g. Render + Supabase Postgres), replace the SQLite layer:

1. Add a Postgres client dependency (e.g. `psycopg2-binary` or `supabase`).
2. Set `SUPABASE_URL` / `SUPABASE_KEY` (or a standard `DATABASE_URL`) in the
   environment (see the commented lines in `.env.example`).
3. Replace the `get_db()` / `sqlite3` calls in `app.py`, `init_db.py`, and
   `draw.py` with the Postgres equivalents. The SQL is standard:
   - `participants(name PK, pin_hash, giftee, wishlist)`
   - `login_attempts(name PK, attempts, locked_until)`
   - Use `TIMESTAMP`/`BIGINT` for `locked_until` instead of SQLite `REAL` if
     preferred, and `ON CONFLICT` upserts work the same in Postgres.
4. Run the schema once against the Supabase database, then run `draw.py` to seed.
5. Set a strong `SECRET_KEY` on Render and deploy with `gunicorn app:app`.

The app logic, routes, and frontend stay identical — only the database access
layer changes.
