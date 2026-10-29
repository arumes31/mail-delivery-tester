import datetime
import io
import os
import subprocess

import pyotp
import pytest

import app as maildt
from security import detect_image_type, safe_widget_color, safe_widget_url, totp_matched_step

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32
BASE = 'https://maildt.test'
CSRF = 'test-csrf-token'


@pytest.fixture(autouse=True)
def reset_state():
    maildt.Base.metadata.create_all(maildt.engine)
    session_db = maildt.Session()
    try:
        for model in (maildt.RateLimitEvent, maildt.CustomWidget, maildt.ActiveTestSignal,
                      maildt.MailTest, maildt.EmailProbe):
            session_db.query(model).delete()
        session_db.commit()
    finally:
        session_db.close()
    yield


@pytest.fixture
def client():
    maildt.app.config.update(TESTING=True)
    with maildt.app.test_client() as test_client:
        yield test_client


def set_session(client, authenticated=False):
    with client.session_transaction(base_url=BASE) as current:
        current['_csrf_token'] = CSRF
        if authenticated:
            current['user'] = maildt.CONFIG['ADMIN_USER']
            current['session_version'] = maildt.AUTH_SESSION_VERSION


def test_image_type_detection_accepts_only_raster_magic_bytes():
    assert detect_image_type(PNG) == 'png'
    assert detect_image_type(b'\xff\xd8\xff\xe0rest') == 'jpg'
    assert detect_image_type(b'GIF89a...') == 'gif'
    assert detect_image_type(b'RIFF\x00\x00\x00\x00WEBPVP8 ') == 'webp'
    assert detect_image_type(b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>') is None
    assert detect_image_type(b'<html><script>alert(1)</script>') is None


@pytest.mark.parametrize('candidate', [
    'javascript:alert(1)', ' JavaScript:alert(1)', 'data:text/html,<script>', 'vbscript:x',
    '//evil.example', '/relative', 'https://', 'https://ok.example/\nx', '', None,
])
def test_widget_url_rejects_non_http_schemes(candidate):
    assert safe_widget_url(candidate) is None


def test_widget_url_and_color_accept_safe_values():
    assert safe_widget_url('https://example.com/path?q=1') == 'https://example.com/path?q=1'
    assert safe_widget_url('HTTP://example.com') == 'HTTP://example.com'
    assert safe_widget_color('#12abEF', '#000') == '#12abEF'
    assert safe_widget_color('red;background:url(x)', '#000') == '#000'


def test_totp_matched_step_returns_matching_step_only():
    totp = pyotp.TOTP(pyotp.random_base32())
    now = datetime.datetime.now(datetime.UTC)
    step = totp.timecode(now)
    assert totp_matched_step(totp, totp.generate_otp(step - 1), now) == step - 1
    assert totp_matched_step(totp, totp.generate_otp(step - 5), now) is None
    assert totp_matched_step(totp, None, now) is None


def test_csp_uses_per_request_nonce_instead_of_unsafe_inline(client):
    first = client.get('/decode-spam', base_url=BASE)
    second = client.get('/decode-spam', base_url=BASE)
    policy = first.headers['Content-Security-Policy']
    script_src = next(d for d in policy.split(';') if d.strip().startswith('script-src'))
    assert "'unsafe-inline'" not in script_src
    nonce = script_src.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"'.encode() in first.data
    assert nonce not in second.headers['Content-Security-Policy']


def test_widget_rejects_javascript_url(client):
    set_session(client, authenticated=True)
    response = client.post('/api/widgets', base_url=BASE, headers={'X-CSRF-Token': CSRF},
                           data={'title': 'x', 'url': 'javascript:alert(document.cookie)'})
    assert response.status_code == 400


def test_widget_upload_rejects_html_and_serves_png_sandboxed(client):
    set_session(client, authenticated=True)
    response = client.post(
        '/api/widgets', base_url=BASE, headers={'X-CSRF-Token': CSRF},
        data={'title': 'x', 'url': 'https://example.com',
              'icon_file': (io.BytesIO(b'<svg onload="alert(1)"/>'), 'icon.svg')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 400

    response = client.post(
        '/api/widgets', base_url=BASE, headers={'X-CSRF-Token': CSRF},
        data={'title': 'x', 'url': 'https://example.com',
              'icon_file': (io.BytesIO(PNG), 'evil.html')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 200
    session_db = maildt.Session()
    try:
        image_path = session_db.get(maildt.CustomWidget, response.get_json()['id']).image_path
    finally:
        session_db.close()
    assert image_path.endswith('.png')

    icon = client.get(image_path, base_url=BASE)
    assert icon.mimetype == 'image/png'
    assert 'sandbox' in icon.headers['Content-Security-Policy']
    assert icon.headers['X-Content-Type-Options'] == 'nosniff'
    icon.close()
    os.remove(os.path.join(maildt.UPLOAD_FOLDER, os.path.basename(image_path)))


def test_legacy_non_image_upload_is_served_as_attachment(client):
    path = os.path.join(maildt.UPLOAD_FOLDER, 'legacy_test.html')
    with open(path, 'wb') as fh:
        fh.write(b'<script>alert(1)</script>')
    try:
        response = client.get('/custom_icons/legacy_test.html', base_url=BASE)
        assert response.mimetype == 'application/octet-stream'
        assert response.headers['Content-Disposition'].startswith('attachment')
        response.close()
    finally:
        os.remove(path)


def add_probes(count, email='alice@example.com'):
    session_db = maildt.Session()
    try:
        for i in range(count):
            session_db.add(maildt.EmailProbe(guid=f'{email}-{i}', recipient_email=email, status='RECEIVED'))
        session_db.commit()
    finally:
        session_db.close()


def test_history_limit_is_clamped(client, monkeypatch):
    monkeypatch.setattr(maildt, 'MAX_HISTORY_LIMIT', 3)
    add_probes(5)
    assert len(client.get('/api/history?limit=1000000', base_url=BASE).get_json()) == 3
    assert len(client.get('/api/history?limit=-5', base_url=BASE).get_json()) == 1


def test_anonymous_history_cannot_filter_by_full_address(client):
    add_probes(2)
    add_probes(1, email='bob@example.org')
    assert client.get('/api/history?recipient=alice@example.com', base_url=BASE).get_json() == []
    masked = maildt.mask_email('alice@example.com')
    rows = client.get(f'/api/history?recipient={masked}', base_url=BASE).get_json()
    assert len(rows) == 2
    assert all(r['recipient'] == masked for r in rows)

    set_session(client, authenticated=True)
    assert len(client.get('/api/history?recipient=alice@example.com', base_url=BASE).get_json()) == 2


def test_mail_tester_ids_are_server_generated_and_session_bound(client, monkeypatch):
    monkeypatch.setattr(maildt, 'record_usage', lambda name: None)
    set_session(client)
    assert client.post('/api/mail-tester/start', base_url=BASE).status_code == 403

    response = client.post('/api/mail-tester/start', base_url=BASE, headers={'X-CSRF-Token': CSRF})
    assert response.status_code == 200
    test_id = response.get_json()['test_id']
    assert len(test_id) >= 20

    assert client.get(f'/api/mail-tester/check/{test_id}', base_url=BASE).get_json() == {'found': False}
    with maildt.app.test_client() as other:
        assert other.get(f'/api/mail-tester/check/{test_id}', base_url=BASE).status_code == 404


def test_mail_tester_start_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(maildt, 'record_usage', lambda name: None)
    set_session(client)
    statuses = [
        client.post('/api/mail-tester/start', base_url=BASE, headers={'X-CSRF-Token': CSRF}).status_code
        for _ in range(6)
    ]
    assert statuses == [200] * 5 + [429]


def test_decoder_failure_hides_stderr_and_anonymous_runs_without_resolution(client, monkeypatch):
    monkeypatch.setattr(maildt, 'record_usage', lambda name: None)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='Traceback: /srv/app/secret_path.py')

    monkeypatch.setattr(maildt, 'run_decoder', fake_run)
    response = client.post('/api/decode-spam', base_url=BASE, json={'headers': 'X-Test: 1'})
    assert response.status_code == 500
    assert b'secret_path' not in response.data
    assert b'Traceback' not in response.data
    assert '-R' in calls[0] and '-r' not in calls[0]
