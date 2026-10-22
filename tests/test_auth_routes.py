import pyotp
import pytest

import app as maildt


def reset_rate_limits():
    maildt.Base.metadata.create_all(maildt.engine)
    session_db = maildt.Session()
    try:
        session_db.query(maildt.RateLimitEvent).delete()
        session_db.query(maildt.GlobalCounter).filter_by(counter_name=maildt.TOTP_STEP_COUNTER).delete()
        session_db.commit()
    finally:
        session_db.close()


@pytest.fixture(autouse=True)
def reset_auth_state(monkeypatch):
    reset_rate_limits()
    monkeypatch.setitem(maildt.CONFIG, 'ADMIN_TOTP_SECRET', None)
    yield


@pytest.fixture
def client():
    maildt.app.config.update(TESTING=True)
    with maildt.app.test_client() as test_client:
        yield test_client


def csrf(client):
    client.get('/login', base_url='https://maildt.test')
    with client.session_transaction(base_url='https://maildt.test') as current:
        return current['_csrf_token']


def authenticate_session(client):
    with client.session_transaction(base_url='https://maildt.test') as current:
        current['user'] = maildt.CONFIG['ADMIN_USER']
        current['session_version'] = maildt.AUTH_SESSION_VERSION
        current['_csrf_token'] = 'test-csrf-token'


def test_legacy_boolean_session_cannot_bypass_authentication(client):
    with client.session_transaction(base_url='https://maildt.test') as current:
        current['logged_in'] = True
    response = client.get('/settings', base_url='https://maildt.test')
    assert response.status_code == 302
    assert response.headers['Location'].startswith('/login?next=')


def test_successful_login_stores_identity_and_rejects_external_next(client):
    response = client.post(
        '/login?next=https://evil.example/phish',
        base_url='https://maildt.test',
        data={
            'csrf_token': csrf(client),
            'username': maildt.CONFIG['ADMIN_USER'],
            'password': maildt.CONFIG['ADMIN_PASSWORD'],
        },
    )
    assert response.status_code == 302
    assert response.headers['Location'] == '/dashboard'
    with client.session_transaction(base_url='https://maildt.test') as current:
        assert current['user'] == maildt.CONFIG['ADMIN_USER']
        assert current['session_version'] == maildt.AUTH_SESSION_VERSION
        assert 'logged_in' not in current


def test_totp_handoff_never_echoes_or_stores_password(client, monkeypatch):
    totp_secret = pyotp.random_base32()
    monkeypatch.setitem(maildt.CONFIG, 'ADMIN_TOTP_SECRET', totp_secret)
    password = maildt.CONFIG['ADMIN_PASSWORD']
    response = client.post(
        '/login?next=/settings',
        base_url='https://maildt.test',
        data={
            'csrf_token': csrf(client),
            'username': maildt.CONFIG['ADMIN_USER'],
            'password': password,
        },
    )
    assert response.status_code == 200
    assert password.encode() not in response.data
    with client.session_transaction(base_url='https://maildt.test') as current:
        assert current['pending_totp_user'] == maildt.CONFIG['ADMIN_USER']
        assert password not in repr(dict(current))

    response = client.post(
        '/login',
        base_url='https://maildt.test',
        data={
            'csrf_token': csrf(client),
            'totp': pyotp.TOTP(totp_secret).now(),
        },
    )
    assert response.status_code == 302
    assert response.headers['Location'] == '/settings'


def test_totp_code_cannot_be_replayed(client, monkeypatch):
    totp_secret = pyotp.random_base32()
    monkeypatch.setitem(maildt.CONFIG, 'ADMIN_TOTP_SECRET', totp_secret)
    code = pyotp.TOTP(totp_secret).now()

    def login_with_code():
        client.post(
            '/login',
            base_url='https://maildt.test',
            data={
                'csrf_token': csrf(client),
                'username': maildt.CONFIG['ADMIN_USER'],
                'password': maildt.CONFIG['ADMIN_PASSWORD'],
            },
        )
        return client.post(
            '/login',
            base_url='https://maildt.test',
            data={'csrf_token': csrf(client), 'totp': code},
        )

    assert login_with_code().status_code == 302
    with client.session_transaction(base_url='https://maildt.test') as current:
        current.clear()
    response = login_with_code()
    assert response.status_code == 200
    assert b'Invalid TOTP code' in response.data


def test_login_rate_limit_is_shared_through_the_database(client):
    for _ in range(5):
        client.post(
            '/login',
            base_url='https://maildt.test',
            data={'csrf_token': csrf(client), 'username': 'nobody', 'password': 'wrong'},
        )
    session_db = maildt.Session()
    try:
        assert session_db.query(maildt.RateLimitEvent).filter_by(bucket='login').count() == 5
    finally:
        session_db.close()
    response = client.get('/login', base_url='https://maildt.test')
    assert b'Too many attempts' in response.data


def test_smtp_diagnostic_requires_authentication_and_csrf(client):
    response = client.post(
        '/api/diagnostics/smtp-test',
        base_url='https://maildt.test',
        json={'host': 'smtp.example.com', 'port': 465},
    )
    assert response.status_code == 401

    authenticate_session(client)
    response = client.post(
        '/api/diagnostics/smtp-test',
        base_url='https://maildt.test',
        json={'host': 'smtp.example.com', 'port': 465},
    )
    assert response.status_code == 403


def test_smtp_diagnostic_blocks_private_resolution_before_connect(client, monkeypatch):
    authenticate_session(client)

    def reject_target(*args, **kwargs):
        raise maildt.SMTPDestinationError(
            'SMTP host resolves to a private or reserved address'
        )

    monkeypatch.setattr(maildt, 'resolve_smtp_destination', reject_target)
    response = client.post(
        '/api/diagnostics/smtp-test',
        base_url='https://maildt.test',
        headers={'X-CSRF-Token': 'test-csrf-token'},
        json={'host': 'smtp.example.com', 'port': 465},
    )
    assert response.status_code == 400
    assert 'private or reserved' in response.get_json()['error']
