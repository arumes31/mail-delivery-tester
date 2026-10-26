"""Exercise startup, schema setup, and ORM writes against CI PostgreSQL."""
import unittest
import uuid

import app
from sqlalchemy import inspect


class PostgreSQLStartupTest(unittest.TestCase):
    def test_startup_migrations_and_recipient_probe_lifecycle(self):
        self.assertEqual(app.engine.dialect.name, "postgresql")
        self.assertEqual(app.engine.dialect.driver, "psycopg2")
        self.assertTrue(app.CONFIG["DATABASE_URL"].startswith("postgresql://"))
        app.run_migrations()
        self.assertTrue({"recipients", "email_probes"}.issubset(inspect(app.engine).get_table_names()))

        with app.Session() as session:
            recipient = app.Recipient(email=f"{uuid.uuid4().hex}@example.invalid")
            session.add(recipient)
            session.commit()
            probe = app.EmailProbe(guid=uuid.uuid4().hex, recipient_email=recipient.email)
            session.add(probe)
            session.commit()
            probe_id = probe.id
            self.assertEqual(session.get(app.EmailProbe, probe_id).status, "PENDING")
            probe.status = "RECEIVED"
            probe.received_at = app.utc_now()
            session.commit()
            session.expire_all()
            self.assertEqual(session.get(app.EmailProbe, probe_id).status, "RECEIVED")
            session.delete(probe)
            session.delete(recipient)
            session.commit()
            self.assertIsNone(session.get(app.EmailProbe, probe_id))


if __name__ == "__main__":
    unittest.main()
