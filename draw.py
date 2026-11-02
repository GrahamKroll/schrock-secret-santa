"""One-time Secret Santa draw script.

Shuffles participants and assigns circular giftees (person[i] -> person[i+1],
last -> first). Circular assignment can never produce a self-assignment, but we
validate anyway and reshuffle if needed.

Seeds the SQLite database (schrock_santa.db). If participant rows already exist,
only the `giftee` column is updated — `pin_hash` and `wishlist` are preserved.

This script NEVER prints any pairings.
"""
import os
import random
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "schrock_santa.db")

PARTICIPANTS = ["Jason", "Sara", "Callie", "Ryan", "Sophie", "Graham"]


def make_draw(names):
    """Return a dict {giver: giftee} using a circular assignment on a shuffle."""
    people = list(names)
    while True:
        random.shuffle(people)
        pairing = {}
        n = len(people)
        for i in range(n):
            giver = people[i]
            giftee = people[(i + 1) % n]
            pairing[giver] = giftee
        # Validate nobody is assigned to themselves.
        if all(giver != giftee for giver, giftee in pairing.items()):
            return pairing


def seed(pairing):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        for giver, giftee in pairing.items():
            cur.execute("SELECT name FROM participants WHERE name = ?", (giver,))
            exists = cur.fetchone() is not None
            if exists:
                # Update giftee only; preserve pin_hash and wishlist.
                cur.execute(
                    "UPDATE participants SET giftee = ? WHERE name = ?",
                    (giftee, giver),
                )
            else:
                cur.execute(
                    "INSERT INTO participants (name, pin_hash, giftee, wishlist) "
                    "VALUES (?, NULL, ?, '')",
                    (giver, giftee),
                )
        conn.commit()
    finally:
        conn.close()


def main():
    pairing = make_draw(PARTICIPANTS)
    seed(pairing)
    print(f"Draw complete. {len(pairing)} participants seeded.")


if __name__ == "__main__":
    main()
