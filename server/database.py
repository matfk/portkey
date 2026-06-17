import sqlite3


class Database:
    def __init__(self, db_path="portkey.db"):
        self.conn = sqlite3.connect(db_path)

    def execute(self, sql, params=()):
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()
