import base64
import json
import ssl
import subprocess
import sys
import time
from email.mime.text import MIMEText

import dns.resolver
import pytest
from sqlalchemy.exc import OperationalError

import app as maildt
import decode_spam_headers_official as dsh
from security import REDACTED_EMAIL, log_safe, mask_email, probe_receipt_token, valid_probe_receipt

BASE = 'https://maildt.test'


@pytest.fixture(autouse=True)
def reset_state():
    maildt.Base.metadata.create_all(maildt.engine)
    session_db = maildt.Session()
    try:
        for model in (maildt.RateLimitEvent, maildt.ActiveTestSignal, maildt.MailTest,
                      maildt.EmailProbe, maildt.Recipient):
            session_db.query(model).delete()
        session_db.commit()
    finally:
        session_db.close()
    yield


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(maildt, 'record_usage', lambda name: None)
    maildt.app.config.update(TESTING=True)
    with maildt.app.test_client() as test_client:
        yield test_client


# --- Email masking ---------------------------------------------------------

@pytest.mark.parametrize('address, expected', [
    ('alice@example.com', 'a***e@e***.com'),
    ('al@example.com', 'a***@e***.com'),
    ('"a@b"@example.com', '"***"@e***.com'),
    ('nobody', REDACTED_EMAIL),
    ('@example.com', REDACTED_EMAIL),
    ('alice@', REDACTED_EMAIL),
    ('alice@example..com', REDACTED_EMAIL),
])
def test_mask_email_never_returns_unmasked_input(address, expected):
    assert mask_email(address) == expected
    assert mask_email(address) != address


def test_mask_email_passes_through_empty_values():
    assert mask_email('') == ''
    assert mask_email(None) is None


# --- Log safety and probe receipts ----------------------------------------

def test_log_safe_keeps_untrusted_text_on_one_line():
    rendered = log_safe('MAILDT-PROBE: x\r\n2026-01-01 - app - INFO - forged \x1b[31m')
    assert '\n' not in rendered and '\r' not in rendered and '\x1b' not in rendered
    assert ' ' not in rendered
    assert '\\x0d\\x0a' in rendered and '\\u2028' in rendered
    assert log_safe('a' * 500, limit=10) == 'a' * 10 + '...'


def test_probe_receipt_token_is_private_and_bound_to_guid():
    token = probe_receipt_token('k' * 32, 'guid-1')
    assert valid_probe_receipt('k' * 32, 'guid-1', token)
    assert not valid_probe_receipt('k' * 32, 'guid-2', token)
    assert not valid_probe_receipt('other' * 8, 'guid-1', token)
    assert not valid_probe_receipt('k' * 32, 'guid-1', None)
    assert not valid_probe_receipt('k' * 32, 'guid-1', '')


# --- Mail TLS -----------------------------------------------------------------

def test_mail_tls_context_requires_certificate_and_hostname():
    context = maildt.mail_tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_mail_connections_use_verifying_contexts(monkeypatch):
    seen = {}

    class FakeSMTPSSL:
        def __init__(self, host, port, timeout=None, context=None):
            seen['smtp_ssl'] = context

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def starttls(self, context=None):
            seen['starttls'] = context

    class FakeIMAP:
        def __init__(self, host, port, ssl_context=None, timeout=None):
            seen['imap'] = ssl_context

    monkeypatch.setattr(maildt.smtplib, 'SMTP_SSL', FakeSMTPSSL)
    monkeypatch.setattr(maildt.smtplib, 'SMTP', FakeSMTP)
    monkeypatch.setattr(maildt.imaplib, 'IMAP4_SSL', FakeIMAP)
    monkeypatch.setitem(maildt.CONFIG, 'IMAP_HOST', 'imap.example.com')

    monkeypatch.setitem(maildt.CONFIG, 'SMTP_PORT', 465)
    maildt.connect_smtp()
    monkeypatch.setitem(maildt.CONFIG, 'SMTP_PORT', 587)
    maildt.connect_smtp()
    maildt.connect_imap()

    for key in ('smtp_ssl', 'starttls', 'imap'):
        assert seen[key].verify_mode == ssl.CERT_REQUIRED
        assert seen[key].check_hostname is True


def test_email_alert_escapes_received_header_text(monkeypatch):
    sent = []

    class FakeServer:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            pass

        def sendmail(self, sender, recipients, message):
            sent.append(message)

    monkeypatch.setitem(maildt.CONFIG, 'ALERT_MAIL_RECIPIENT', 'ops@example.com')
    monkeypatch.setattr(maildt, 'connect_smtp', lambda: FakeServer())
    maildt.send_email_alert('Headers:\n<a href="https://evil.example">click</a>')

    body = base64.b64decode(sent[0].split('\n\n', 1)[1]).decode() if 'base64' in sent[0] else sent[0]
    assert '<a href="https://evil.example">' not in body
    assert '&lt;a href=&quot;https://evil.example&quot;&gt;' in body


# --- Inbox processing -----------------------------------------------------------

class FakeMailbox:
    def __init__(self, messages):
        self.messages = messages
        self.deleted = []

    def fetch(self, e_id, spec):
        raw = self.messages[e_id]
        if isinstance(raw, Exception):
            raise raw
        return 'OK', [(b'1 (RFC822 {1}', raw), b')']

    def store(self, e_id, op, flag):
        self.deleted.append(e_id)


def raw_message(subject, headers=None):
    msg = MIMEText('body')
    msg['Subject'] = subject
    msg['From'] = 'sender@example.com'
    for k, v in (headers or {}).items():
        msg[k] = v
    return msg.as_bytes()


def add_probe(guid='guid-1', email='alice@example.com'):
    session_db = maildt.Session()
    try:
        session_db.add(maildt.EmailProbe(guid=guid, recipient_email=email, status='PENDING'))
        session_db.commit()
    finally:
        session_db.close()


def probe_status(guid='guid-1'):
    session_db = maildt.Session()
    try:
        return session_db.query(maildt.EmailProbe).filter_by(guid=guid).one().status
    finally:
        session_db.close()


def process(mailbox, monkeypatch):
    for name in ('send_discord_alert', 'send_email_alert', 'send_webhook_alert'):
        monkeypatch.setattr(maildt, name, lambda *a, **k: None)
    session_db = maildt.Session()
    try:
        for e_id in mailbox.messages:
            maildt.process_inbox_message(mailbox, session_db, e_id, {})
    finally:
        session_db.close()


def test_probe_with_public_guid_but_no_receipt_token_is_not_accepted(monkeypatch):
    add_probe()
    mailbox = FakeMailbox({b'1': raw_message('MAILDT-PROBE: guid-1')})
    process(mailbox, monkeypatch)
    assert probe_status() == 'PENDING'
    assert mailbox.deleted == [b'1']


def test_probe_with_receipt_token_is_marked_received(monkeypatch):
    add_probe()
    token = probe_receipt_token(maildt.secret_key, 'guid-1')
    mailbox = FakeMailbox({b'1': raw_message(f'Re: MAILDT-PROBE: guid-1 {token}')})
    process(mailbox, monkeypatch)
    assert probe_status() == 'RECEIVED'
    assert mailbox.deleted == [b'1']


def test_malformed_subject_charset_does_not_stop_the_batch(monkeypatch):
    add_probe()
    token = probe_receipt_token(maildt.secret_key, 'guid-1')
    bad = MIMEText('body')
    bad['Subject'] = '=?x-no-such-charset?b?TUFJTERULVBST0JFOiDE?='
    mailbox = FakeMailbox({
        b'1': bad.as_bytes(),
        b'2': ValueError('broken fetch'),
        b'3': raw_message(f'MAILDT-PROBE: guid-1 {token}'),
    })
    process(mailbox, monkeypatch)
    assert probe_status() == 'RECEIVED'
    assert mailbox.deleted == [b'1', b'2', b'3']


def test_decode_subject_tolerates_bad_charsets():
    msg = MIMEText('body')
    msg['Subject'] = '=?x-no-such-charset?q?MAILDT-TEST:_abc?='
    assert 'MAILDT-TEST:' in maildt.decode_subject(msg)


def start_test(test_id):
    session_db = maildt.Session()
    try:
        session_db.add(maildt.ActiveTestSignal(test_id=test_id))
        session_db.commit()
    finally:
        session_db.close()


def stored_tests():
    session_db = maildt.Session()
    try:
        return [t.test_id for t in session_db.query(maildt.MailTest).all()]
    finally:
        session_db.close()


def test_mail_test_results_are_idempotent_and_require_an_active_test(monkeypatch):
    monkeypatch.setattr(maildt, 'decode_spam_headers', lambda headers: {})
    test_id = 'A' * 22
    start_test(test_id)
    add_probe()
    token = probe_receipt_token(maildt.secret_key, 'guid-1')
    mailbox = FakeMailbox({
        b'1': raw_message(f'MAILDT-TEST: {test_id}'),
        b'2': raw_message(f'MAILDT-TEST: {test_id}'),
        b'3': raw_message('MAILDT-TEST: ' + 'B' * 22),
        b'4': raw_message(f'MAILDT-PROBE: guid-1 {token}'),
    })
    process(mailbox, monkeypatch)
    assert stored_tests() == [test_id]
    assert probe_status() == 'RECEIVED'
    assert mailbox.deleted == [b'1', b'2', b'3', b'4']


def test_database_errors_roll_back_and_keep_the_message(monkeypatch):
    add_probe()
    token = probe_receipt_token(maildt.secret_key, 'guid-1')

    def failing(*args, **kwargs):
        raise OperationalError('stmt', {}, Exception('db down'))

    monkeypatch.setattr(maildt, 'process_probe_message', failing)
    mailbox = FakeMailbox({b'1': raw_message(f'MAILDT-PROBE: guid-1 {token}')})
    process(mailbox, monkeypatch)
    assert mailbox.deleted == []


# --- Decoder ----------------------------------------------------------------

def test_decoder_rejects_excessive_received_hops(client):
    headers = '\n'.join(f'Received: from h{i} by h{i + 1}' for i in range(maildt.DECODER_MAX_RECEIVED_HOPS + 1))
    response = client.post('/api/decode-spam', base_url=BASE, json={'headers': headers})
    assert response.status_code == 400


def test_decoder_rejects_oversized_headers(client):
    headers = 'X-Test: ' + 'a' * maildt.DECODER_MAX_HEADER_CHARS
    response = client.post('/api/decode-spam', base_url=BASE, json={'headers': headers})
    assert response.status_code == 413


def test_decoder_rejects_non_string_headers(client):
    response = client.post('/api/decode-spam', base_url=BASE, json={'headers': ['x']})
    assert response.status_code == 400


def test_legacy_decoder_runs_through_bounded_wrapper(client, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='ok', stderr='')

    monkeypatch.setattr(maildt, 'run_decoder', fake_run)
    response = client.post('/api/decode-spam', base_url=BASE, json={'headers': 'X-Test: 1', 'legacy': True})
    assert response.status_code == 200
    assert calls[0][1:3] == ['decode_wrapper.py', '--legacy']
    assert '-R' in calls[0]


def test_run_decoder_enforces_output_budget():
    cmd = [sys.executable, '-c', 'import sys; sys.stdout.write("x" * 200000)']
    with pytest.raises(maildt.DecoderOutputTooLarge):
        maildt.run_decoder(cmd, max_bytes=1000)
    result = maildt.run_decoder(cmd, max_bytes=300000)
    assert result.returncode == 0 and len(result.stdout) == 200000


def test_run_decoder_times_out():
    cmd = [sys.executable, '-c', 'import time; time.sleep(30)']
    with pytest.raises(subprocess.TimeoutExpired):
        maildt.run_decoder(cmd, timeout=0.5)


def test_color_markers_cannot_stall_the_parser():
    # A zero-padded color number used to rebuild a different marker and loop forever.
    hostile = 'value __COLOR_031__|x|__END_COLOR__ tail' * 2000
    start = time.monotonic()
    assert dsh.Logger.noColors(hostile) == hostile.replace('__COLOR_031__|', '').replace('|__END_COLOR__', '')
    assert time.monotonic() - start < 2


def test_color_markers_handle_nesting_and_unbalanced_input():
    nested = dsh.Logger.with_color(31, 'a ' + dsh.Logger.with_color(32, 'b') + ' c')
    assert dsh.Logger.noColors(nested) == 'a b c'
    assert dsh.Logger.ansiColors(nested) == '\x1b[31ma \x1b[32mb\x1b[0m c\x1b[0m'
    assert dsh.Logger.noColors('x |__END_COLOR__ __COLOR_31__|y') == 'x |__END_COLOR__ __COLOR_31__|y'


def test_html_report_escapes_header_and_report_text():
    out = dsh.Logger.htmlColors('<script>1</script> ' + dsh.Logger.with_color(31, '<b>'))
    assert '<script>' not in out and '&lt;script&gt;' in out
    assert '<font class="text-red">&lt;b&gt;</font>' in out
    page = dsh.formatToHtml(dsh.Logger.htmlColors('>>>>>>>>>>>>>>>>>>>>>>\nok\n<<<<<<<<<<<<<<<<<<<<<<'),
                            'Subject: <img src=x onerror=alert(1)>')
    assert '<img src=x' not in page
    assert '<div><hr/>' in page and '</div>' in page


def analysis():
    return dsh.SMTPHeadersAnalysis(dsh.Logger({'nocolor': True}))


def test_received_parsing_is_bounded_on_long_headers():
    start = time.monotonic()
    parsed = analysis().parseReceived('from a ' + 'x ' * 500000 + 'by b', 1)
    assert time.monotonic() - start < 2
    assert parsed is not None


def test_received_parsing_still_extracts_keys():
    parsed = analysis().parseReceived('from mail.example.com (1.2.3.4) by mx.example.net with ESMTPS id abc', 1)
    assert parsed['host'] == 'mail.example.com'
    assert parsed['ip'] == '1.2.3.4'
    assert parsed['parsed']['by'] == 'mx.example.net'
    assert parsed['parsed']['with'] == 'ESMTPS'


def test_domain_extraction_is_linear_on_hostile_input(monkeypatch):
    a = analysis()
    a.text = 'a.' * 30000 + '!'
    start = time.monotonic()
    a.testResolveIntoIP()
    assert time.monotonic() - start < 2


def test_msfbl_json_is_rendered_compactly_and_bounded():
    nested = json.dumps({'a': [[[[[[1, 2, 3]]]]]], 'b': 'c'}).encode()
    a = analysis()
    a.headers = [(0, 'X-MSFBL', base64.b64encode(nested).decode())]
    result = a.testMSFBL()
    assert json.dumps(json.loads(nested), ensure_ascii=False) in result['analysis']
    assert '\n    ' not in result['analysis']

    a.headers = [(0, 'X-MSFBL', 'eyJ' + 'A' * (dsh.MAX_MSFBL_PART_LENGTH + 1))]
    assert a.testMSFBL() == []


@pytest.mark.parametrize('dont_resolve, expected_lookups', [(True, 0), (False, 1)])
def test_impersonation_txt_lookup_honours_no_resolution(monkeypatch, dont_resolve, expected_lookups):
    lookups = []
    monkeypatch.setattr(dns.resolver, 'resolve', lambda *args, **kwargs: lookups.append(args) or [])
    monkeypatch.setattr(dsh.SMTPHeadersAnalysis, 'extractDomain', staticmethod(lambda value: ''))
    monkeypatch.setitem(dsh.options, 'dont_resolve', dont_resolve)
    a = analysis()
    a.headers = [(0, 'From', 'Alice <alice@sender.example>')]
    hop = {'host': 'relay.other.example', 'host2': '', 'ip': ''}
    a.received_path = [hop, hop, hop]
    a.testDomainImpersonation()
    assert len(lookups) == expected_lookups


# --- Blacklist --------------------------------------------------------------

class FakeAnswer:
    def __init__(self, exchange, preference):
        self.exchange = exchange
        self.preference = preference


def test_blacklist_bounds_mx_work_and_checks_each_address_once(client, monkeypatch):
    queries = []

    class FakeResolver:
        def __init__(self):
            self.nameservers = []
            self.timeout = self.lifetime = None

        def resolve(self, name, rtype):
            if rtype == 'MX':
                return [FakeAnswer(f'mx{i}.example.com.', i) for i in range(20)]
            queries.append(name)
            raise dns.resolver.NXDOMAIN()

    def fake_gethostbyname(host):
        if host == 'example.com':
            return '192.0.2.1'
        return f'198.51.100.{int(host[2:host.index(".")]) + 1}'

    monkeypatch.setattr(maildt.dns.resolver, 'Resolver', FakeResolver)
    monkeypatch.setattr(maildt.socket, 'gethostbyname', fake_gethostbyname)
    response = client.get('/api/diagnostics/blacklist?target=example.com', base_url=BASE)
    data = response.get_json()
    assert response.status_code == 200
    assert len(data['mx_reports']) == maildt.BLACKLIST_MAX_MX_ADDRESSES
    per_ip = len(data['results'])
    assert len(queries) == per_ip * (1 + maildt.BLACKLIST_MAX_MX_ADDRESSES)


def test_blacklist_stops_querying_after_deadline(client, monkeypatch):
    queries = []

    class FakeResolver:
        def __init__(self):
            self.nameservers = []

        def resolve(self, name, rtype):
            queries.append(name)
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(maildt.dns.resolver, 'Resolver', FakeResolver)
    monkeypatch.setattr(maildt, 'BLACKLIST_DEADLINE', -1)
    data = client.get('/api/diagnostics/blacklist?target=192.0.2.1', base_url=BASE).get_json()
    assert queries == []
    assert all(r['details'].startswith('Skipped') for r in data['results'])
