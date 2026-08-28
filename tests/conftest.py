import os
from pathlib import Path

TEST_DATABASE = Path(__file__).parent / 'maildt-test.sqlite3'
os.environ.setdefault('DATABASE_URL', f"sqlite:///{TEST_DATABASE.as_posix()}")
os.environ.setdefault('SECRET_KEY', 'test-only-session-secret-with-32-characters')
os.environ.setdefault('ADMIN_USER', 'test-admin')
os.environ.setdefault('ADMIN_PASSWORD', 'test-only-password-strong')
os.environ.setdefault('SMTP_HOST', 'smtp.example.com')
os.environ.setdefault('SMTP_PORT', '465')
os.environ.setdefault('SMTP_DIAGNOSTIC_ALLOWED_HOSTS', 'smtp.example.com')
os.environ.setdefault('SMTP_DIAGNOSTIC_ALLOWED_PORTS', '465')
