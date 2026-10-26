from unittest.mock import MagicMock

import pytest

import app as application


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("postgresql://user:pass@db/app", "postgresql+psycopg2://user:pass@db/app"),
        (
            "postgresql://user:p%40ss@[2001:db8::1]:5432/app?sslmode=require",
            "postgresql+psycopg2://user:p%40ss@[2001:db8::1]:5432/app?sslmode=require",
        ),
        ("postgresql+psycopg2://user:pass@db/app", "postgresql+psycopg2://user:pass@db/app"),
        ("postgresql+psycopg://user:pass@db/app", "postgresql+psycopg://user:pass@db/app"),
        ("postgresql+asyncpg://user:pass@db/app", "postgresql+asyncpg://user:pass@db/app"),
        ("sqlite:///:memory:", "sqlite:///:memory:"),
    ],
)
def test_get_engine_preserves_existing_postgresql_driver(monkeypatch, uri, expected):
    create_engine = MagicMock()
    monkeypatch.setattr(application, "create_engine", create_engine)

    engine = application.get_engine(uri, max_retries=1, delay=0)

    create_engine.assert_called_once_with(expected, pool_pre_ping=True, pool_recycle=300)
    assert engine is create_engine.return_value
