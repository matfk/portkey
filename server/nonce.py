from server.models import Nonce


class NonceSet:
	def __init__(self, db, ttl=60):
		self.ttl = ttl
		self.db = db
		Nonce.ensure_table(self.db)

	def seen(self, nonce):
		if Nonce.exists(nonce, self.db):
			return True
		Nonce.create(nonce, self.db)
		return False

	def cleanup(self):
		Nonce.delete_expired(self.db, self.ttl)
