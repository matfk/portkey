import time

class Nonce:
    TABLE = "nonces"

    def __init__(self, value, seen_at, db):
        self.value = value
        self.seen_at = seen_at
        self.db = db

    @classmethod
    def ensure_table(cls, db):
        db.execute(
            f"CREATE TABLE IF NOT EXISTS {cls.TABLE} "
            f"(nonce BLOB PRIMARY KEY, seen_at REAL)"
        )
        db.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{cls.TABLE}_seen_at "
            f"ON {cls.TABLE}(seen_at)"
        )
        db.commit()

    @classmethod
    def exists(cls, value, db):
        cursor = db.execute(f"SELECT 1 FROM {cls.TABLE} WHERE nonce = ?", (value,))
        return cursor.fetchone() is not None

    @classmethod
    def create(cls, value, db, seen_at=None):
        if seen_at is None:
            seen_at = time.time()
        db.execute(
            f"INSERT INTO {cls.TABLE} (nonce, seen_at) VALUES (?, ?)",
            (value, seen_at),
        )
        db.commit()
        return cls(value, seen_at, db)

    @classmethod
    def delete_expired(cls, db, ttl):
        cutoff = time.time() - ttl
        cursor = db.execute(f"DELETE FROM {cls.TABLE} WHERE seen_at < ?", (cutoff,))
        db.commit()
        return cursor.rowcount

    def delete(self):
        self.db.execute(f"DELETE FROM {self.TABLE} WHERE nonce = ?", (self.value,))
        self.db.commit()
