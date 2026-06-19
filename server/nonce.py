from __future__ import annotations

import logging
import threading

from server.database import Database
from server.models import Nonce

logger = logging.getLogger("portkey.nonce")


class NonceSet:
    def __init__(self, db: Database, ttl: int = 60, cleanup_interval: int = 60):
        self.ttl = ttl
        self.db = db
        self.stop_event = threading.Event()
        self.cleanup_thread: threading.Thread | None = None
        Nonce.ensure_table(self.db)

    def seen(self, nonce: bytes) -> bool:
        if Nonce.exists(nonce, self.db):
            return True
        Nonce.create(nonce, self.db)
        return False

    def cleanup(self) -> int:
        deleted = Nonce.delete_expired(self.db, self.ttl)
        if deleted:
            logger.debug("Cleaned up %d expired nonces", deleted)
        return deleted

    def start_cleanup_loop(self, interval: int = 60):
        if self.cleanup_thread is not None:
            return

        def loop():
            logger.info("Nonce cleanup thread started (interval=%ds, ttl=%ds)", interval, self.ttl)
            while not self.stop_event.wait(interval):
                try:
                    self.cleanup()
                except Exception:
                    logger.exception("Nonce cleanup failed")
            logger.info("Nonce cleanup thread stopped")

        self.cleanup_thread = threading.Thread(target=loop, daemon=True, name="nonce-cleanup")
        self.cleanup_thread.start()

    def stop_cleanup_loop(self):
        if self.cleanup_thread is None:
            return
        self.stop_event.set()
        self.cleanup_thread.join(timeout=5)
        self.cleanup_thread = None
