from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger("portkey.database")


class Database:
    def __init__(self, db_path: str | Path = Path("portkey.db")):
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        logger.debug("Opened database %s (WAL mode, 5s busy timeout)", db_path)

    def execute(self, sql: str, params=()):
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()
        logger.debug("Database connection closed")
