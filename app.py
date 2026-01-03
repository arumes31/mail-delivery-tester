import os
import uuid
import smtplib
import ssl
import imaplib
import email
import logging
import requests
import datetime
import pyotp
from functools import wraps
from email.mime.text import MIMEText
from email.header import decode_header
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, desc
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base
from apscheduler.schedulers.background import BackgroundScheduler

# --- Configuration ---
def get_env_var(name, default=None, var_type=str):
    val = os.environ.get(name, default)
    if val is None:
        return None
    return var_type(val)

# Ensure data directory exists for persistence
if not os.path.exists('data'):
    os.makedirs('data')

# Construct default Database URL from components
db_user = get_env_var('DB_USER', 'maildt')
db_pass = get_env_var('DB_PASS', 'securepassword')
db_host = get_env_var('DB_HOST', 'db')
db_port = get_env_var('DB_PORT', '5432')
db_name = get_env_var('DB_NAME', 'maildt')
default_db_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"

CONFIG = {
    'DATABASE_URL': get_env_var('DATABASE_URL', default_db_url), 
    'SMTP_HOST': get_env_var('SMTP_HOST'),
    'SMTP_PORT': get_env_var('SMTP_PORT', 465, int),
    'SMTP_USER': get_env_var('SMTP_USER'),
    'SMTP_PASS': get_env_var('SMTP_PASS'),
    'IMAP_HOST': get_env_var('IMAP_HOST'),
    'IMAP_PORT': get_env_var('IMAP_PORT', 993, int),
    'IMAP_USER': get_env_var('IMAP_USER'),
    'IMAP_PASS': get_env_var('IMAP_PASS'),
    'SEND_INTERVAL': get_env_var('SEND_INTERVAL', 3600, int),
    'CHECK_INTERVAL': get_env_var('CHECK_INTERVAL', 30, int),
    'ALERT_THRESHOLD': get_env_var('ALERT_THRESHOLD', 300, int),
    'DISCORD_WEBHOOK_URL': get_env_var('DISCORD_WEBHOOK_URL'),
    'ALERT_MAIL_RECIPIENT': get_env_var('ALERT_MAIL_RECIPIENT'),
    'ADMIN_USER': get_env_var('ADMIN_USER', 'admin'),
    'ADMIN_PASSWORD': get_env_var('ADMIN_PASSWORD', 'admin'),
    'ADMIN_TOTP_SECRET': get_env_var('ADMIN_TOTP_SECRET'),
    'ENABLE_PROXY': get_env_var('ENABLE_PROXY', 'false').lower() == 'true',
}

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Database Setup ---
engine = create_engine(CONFIG['DATABASE_URL'])
Session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

class EmailProbe(Base):
    __tablename__ = 'email_probes'
    id = Column(Integer, primary_key=True)
    guid = Column(String(50), unique=True, index=True)
    sent_at = Column(DateTime, default=datetime.datetime.utcnow)
    received_at = Column(DateTime, nullable=True)
    status = Column(String(20), default='PENDING') # PENDING, RECEIVED, MISSING
    alert_sent = Column(Boolean, default=False)
    recipient_email = Column(String(120))
    alert_threshold = Column(Integer, default=300)

    @property
    def latency(self):
        if self.received_at and self.sent_at:
            return (self.received_at - self.sent_at).total_seconds()
        elif self.sent_at:
            return (datetime.datetime.utcnow() - self.sent_at).total_seconds()
        return 0

class Recipient(Base):
    __tablename__ = 'recipients'
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    active = Column(Boolean, default=True)
    send_interval = Column(Integer, default=3600)
    alert_threshold = Column(Integer, default=300)
    next_send_at = Column(DateTime, default=datetime.datetime.utcnow)
    email_alerts_enabled = Column(Boolean, default=True)
    discord_alerts_enabled = Column(Boolean, default=True)
    alert_active = Column(Boolean, default=False)

class MailTest(Base):
    __tablename__ = 'mail_tests'
    id = Column(Integer, primary_key=True)
    test_id = Column(String(50), unique=True, index=True)
    received_at = Column(DateTime, default=datetime.datetime.utcnow)
    subject = Column(String(255))
    sender = Column(String(120))
    body = Column(String)
    headers = Column(String)
    spf_status = Column(String(50))
    dkim_status = Column(String(50))
    dmarc_status = Column(String(50))

Base.metadata.create_all(engine)

# --- Migration Helpers ---
def run_migrations():
    """Simple migration to add columns if they don't exist."""
    session = Session()
    try:
        from sqlalchemy import text
        # ... (previous migration checks) ...
        try:
            session.execute(text("SELECT recipient_email FROM email_probes LIMIT 1"))
        except Exception:
            session.rollback()
            logger.info("Migrating: Adding recipient_email to email_probes")
            session.execute(text("ALTER TABLE email_probes ADD COLUMN recipient_email VARCHAR(120)"))
            session.commit()
            
        try:
            session.execute(text("SELECT alert_threshold FROM email_probes LIMIT 1"))
        except Exception:
            session.rollback()
            logger.info("Migrating: Adding alert_threshold to email_probes")
            session.execute(text("ALTER TABLE email_probes ADD COLUMN alert_threshold INTEGER DEFAULT 300"))
            session.commit()

        try:
            session.execute(text("SELECT send_interval FROM recipients LIMIT 1"))
        except Exception:
            session.rollback()
            logger.info("Migrating: Adding new columns to recipients")
            session.execute(text("ALTER TABLE recipients ADD COLUMN send_interval INTEGER DEFAULT 3600"))
            session.execute(text("ALTER TABLE recipients ADD COLUMN alert_threshold INTEGER DEFAULT 300"))
            session.execute(text("ALTER TABLE recipients ADD COLUMN next_send_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            session.commit()

        try:
            session.execute(text("SELECT email_alerts_enabled FROM recipients LIMIT 1"))
        except Exception:
            session.rollback()
            logger.info("Migrating: Adding granular alert columns to recipients")
            session.execute(text("ALTER TABLE recipients ADD COLUMN email_alerts_enabled BOOLEAN DEFAULT TRUE"))
            session.execute(text("ALTER TABLE recipients ADD COLUMN discord_alerts_enabled BOOLEAN DEFAULT TRUE"))
            session.commit()

        # Alert Active state tracking
        try:
            session.execute(text("SELECT alert_active FROM recipients LIMIT 1"))
        except Exception:
            session.rollback()
            logger.info("Migrating: Adding alert_active to recipients")
            session.execute(text("ALTER TABLE recipients ADD COLUMN alert_active BOOLEAN DEFAULT FALSE"))
            session.commit()

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        session.rollback()
    finally:
        session.close()

def reset_alert_states():
    """Resets alert_active state for all recipients on startup."""
    session = Session()
    try:
        updated = session.query(Recipient).update({Recipient.alert_active: False})
        session.commit()
        if updated > 0:
            logger.info(f"Startup: Reset alert state for {updated} recipients.")
    except Exception as e:
        logger.error(f"Failed to reset alert states: {e}")
        session.rollback()
    finally:
        session.close()

run_migrations()
reset_alert_states()

# --- Mail Logic ---

def send_probe_email():
    """Generates a GUID and sends a probe email to recipients due for a check."""
    if not CONFIG['SMTP_HOST']:
        logger.warning("SMTP not configured. Skipping send.")
        return

    session = Session()
    try:
        # Get active recipients due for sending
        now = datetime.datetime.utcnow()
        recipients = session.query(Recipient).filter(
            Recipient.active == True,
            Recipient.next_send_at <= now
        ).all()
        
        if not recipients:
            return # Nothing to do

        # Choose connection type based on port
        if CONFIG['SMTP_PORT'] == 465:
            server = smtplib.SMTP_SSL(CONFIG['SMTP_HOST'], CONFIG['SMTP_PORT'])
        else:
            server = smtplib.SMTP(CONFIG['SMTP_HOST'], CONFIG['SMTP_PORT'])
            server.starttls()

        with server:
            server.login(CONFIG['SMTP_USER'], CONFIG['SMTP_PASS'])
            
            for recipient in recipients:
                probe_guid = str(uuid.uuid4())
                subject = f"MAILDT-PROBE: {probe_guid}"
                
                # HTML Body
                # Using a simple CDN for the logo or Base64 is best for emails. 
                # Since we generated it locally, let's embed a simplified version or just use a text header to avoid broken images if the app isn't public.
                # However, to be "modern", I will embed a public URL placeholder that you can replace, 
                # OR I can use a standard nice looking unicode/CSS header.
                # Let's use a nice CSS header block with the name to be safe and reliable.
                
                html_body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8f9fa; padding: 20px; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }}
                        .header {{ background: linear-gradient(135deg, #4e73df 0%, #224abe 100%); padding: 20px; text-align: center; color: white; }}
                        .header h1 {{ margin: 0; font-size: 24px; display: flex; align-items: center; justify-content: center; }}
                        .content {{ padding: 30px; }}
                        .metric {{ display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #eee; }}
                        .label {{ font-weight: 600; color: #666; }}
                        .value {{ font-family: monospace; color: #0d6efd; font-size: 14px; }}
                        .footer {{ background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #eee; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>
                                <!-- Simple SVG Icon embedded directly for email compatibility -->
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 10px; color: white;">
                                    <path d="M22 2L11 13"></path>
                                    <path d="M22 2L15 22L11 13L2 9L22 2Z"></path>
                                </svg>
                                MailDT Monitor
                            </h1>
                        </div>
                        <div class="content">
                            <p style="margin-top: 0;">This is an automated monitoring probe to verify delivery latency and reliability.</p>
                            
                            <div class="metric" style="margin-top: 20px;">
                                <span class="label">GUID</span>
                                <span class="value">{probe_guid}</span>
                            </div>
                            <div class="metric">
                                <span class="label">Sent At</span>
                                <span class="value">{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</span>
                            </div>
                        </div>
                        
                        <div class="footer">
                            Generated by MailDT System &bull; Do not reply
                        </div>
                    </div>
                </body>
                </html>
                """

                msg = MIMEText(html_body, 'html')
                msg['Subject'] = subject
                msg['From'] = CONFIG['SMTP_USER']
                msg['To'] = recipient.email

                try:
                    server.sendmail(CONFIG['SMTP_USER'], [recipient.email], msg.as_string())
                    
                    # Record successful send in DB
                    probe = EmailProbe(
                        guid=probe_guid, 
                        status='PENDING', 
                        recipient_email=recipient.email,
                        alert_threshold=recipient.alert_threshold
                    )
                    session.add(probe)
                    
                    # If we successfully sent, and we were in a SEND_ERROR alert state, we should probably reset?
                    # Actually, recovery usually happens in check_inbox. 
                    # But if the error was purely SMTP, then check_inbox might never see a recovery mail.
                    # Let's check if the previous status for this recipient was SEND_ERROR.
                    
                    # For SMTP recovery, we can reset if the send succeeded.
                    if recipient.alert_active:
                        # Optional: Send a specific SMTP recovery alert? 
                        # Or just let it reset so the next failure triggers a new alert.
                        # Since we want "send ok after", let's send a recovery if it was a SEND_ERROR.
                        
                        # Find the last probe status
                        last_probe = session.query(EmailProbe).filter_by(recipient_email=recipient.email).order_by(desc(EmailProbe.sent_at)).offset(1).first()
                        if last_probe and last_probe.status == 'SEND_ERROR':
                            msg = f"✅ **Mail Send Recovered**\nSuccessfully sent probe to `{recipient.email}` after previous failure."
                            if recipient.discord_alerts_enabled:
                                send_discord_alert(msg)
                            recipient.alert_active = False
                    
                    # Update next send time
                    recipient.next_send_at = now + datetime.timedelta(seconds=recipient.send_interval)
                    
                    logger.info(f"Sent probe {probe_guid} to {recipient.email}")
                except Exception as send_err:
                    err_msg = f"❌ **Mail Send Failure**\nFailed to send probe to `{recipient.email}`.\nError: `{str(send_err)}`"
                    logger.error(f"[DEBUG] SMTP Error for {recipient.email}: {str(send_err)}")
                    
                    # Record failure in DB
                    probe = EmailProbe(
                        guid=probe_guid,
                        status='SEND_ERROR',
                        recipient_email=recipient.email,
                        alert_threshold=recipient.alert_threshold,
                        alert_sent=True
                    )
                    session.add(probe)
                    
                    # Trigger Alert only if not already in alert state
                    if not recipient.alert_active:
                        logger.info(f"[DEBUG] Alerting: Initial failure for {recipient.email}. Sending alert now.")
                        if recipient.discord_alerts_enabled:
                            send_discord_alert(err_msg)
                        if recipient.email_alerts_enabled:
                            send_email_alert(err_msg)
                        recipient.alert_active = True
                    else:
                        logger.info(f"[DEBUG] Alerting: Failure for {recipient.email} suppressed. Recipient already in alert state.")
                    
                    # Still update next send time
                    recipient.next_send_at = now + datetime.timedelta(seconds=recipient.send_interval)
                    logger.info(f"[DEBUG] Next retry for {recipient.email} scheduled at {recipient.next_send_at}")

        session.commit()

    except Exception as e:
        logger.error(f"Error in send loop: {e}")
        session.rollback()
    finally:
        session.close()

# --- Global state for fast polling ---
ACTIVE_TESTS = {} # {test_id: timestamp}
LAST_IMAP_CHECK = datetime.datetime.min

def check_inbox():
    """Checks IMAP for returned probe emails and active tests."""
    global LAST_IMAP_CHECK
    
    if not CONFIG['IMAP_HOST']:
        logger.warning("IMAP not configured. Skipping check.")
        return

    now = datetime.datetime.utcnow()
    
    # Cleanup expired tests (older than 10 mins)
    expired = [tid for tid, ts in ACTIVE_TESTS.items() if (now - ts).total_seconds() > 600]
    for tid in expired:
        del ACTIVE_TESTS[tid]
    
    has_active_tests = len(ACTIVE_TESTS) > 0
    
    # Throttle if no active tests
    seconds_since_last = (now - LAST_IMAP_CHECK).total_seconds()
    if not has_active_tests and seconds_since_last < CONFIG['CHECK_INTERVAL']:
        return

    LAST_IMAP_CHECK = now
    session = Session()
    try:
        mail = imaplib.IMAP4_SSL(CONFIG['IMAP_HOST'], CONFIG['IMAP_PORT'])
        mail.login(CONFIG['IMAP_USER'], CONFIG['IMAP_PASS'])
        mail.select("inbox")

        # Search for emails with our subject prefix
        # We search for both PROBE and TEST
        status, messages = mail.search(None, '(OR (SUBJECT "MAILDT-PROBE:") (SUBJECT "MAILDT-TEST:"))')
        
        if status != "OK":
            logger.warning("IMAP search failed.")
            return

        email_ids = messages[0].split()
        for e_id in email_ids:
            # Fetch the email
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding if encoding else "utf-8")
                    
                    if "MAILDT-PROBE:" in subject:
                        try:
                            parts = subject.split("MAILDT-PROBE:")
                            if len(parts) > 1:
                                guid = parts[1].strip()
                                # Find in DB
                                probe = session.query(EmailProbe).filter_by(guid=guid).first()
                                if probe:
                                    if not probe.received_at:
                                        probe.received_at = datetime.datetime.utcnow()
                                        recipient = session.query(Recipient).filter_by(email=probe.recipient_email).first()
                                        if recipient and recipient.alert_active:
                                            msg_rec = f"✅ **Mail Delivery Recovered**\nProbe `{probe.guid}` to `{probe.recipient_email}` has arrived.\nLatency: {probe.latency:.2f}s"
                                            if recipient.discord_alerts_enabled: send_discord_alert(msg_rec)
                                            if recipient.email_alerts_enabled: send_email_alert(msg_rec)
                                            recipient.alert_active = False
                                        probe.status = 'RECEIVED'
                                        session.commit()
                                        logger.info(f"Received probe {guid}.")
                                mail.store(e_id, '+FLAGS', r'\Deleted')
                        except Exception as parse_err:
                            logger.error(f"Error processing probe email: {parse_err}")

                    elif "MAILDT-TEST:" in subject:
                        try:
                            parts = subject.split("MAILDT-TEST:")
                            if len(parts) > 1:
                                test_id = parts[1].strip()
                                
                                # Extract headers and body
                                headers_str = ""
                                for k, v in msg.items():
                                    headers_str += f"{k}: {v}\n"
                                
                                body = ""
                                if msg.is_multipart():
                                    for part in msg.walk():
                                        if part.get_content_type() == "text/plain":
                                            body = part.get_payload(decode=True).decode(errors='replace')
                                            break
                                else:
                                    body = msg.get_payload(decode=True).decode(errors='replace')

                                # Basic Auth Results from headers
                                auth_results = msg.get("Authentication-Results", "")
                                spf = "unknown"
                                if "spf=pass" in auth_results.lower(): spf = "pass"
                                elif "spf=fail" in auth_results.lower(): spf = "fail"
                                
                                dkim = "unknown"
                                if "dkim=pass" in auth_results.lower(): dkim = "pass"
                                elif "dkim=fail" in auth_results.lower(): dkim = "fail"

                                dmarc = "unknown"
                                if "dmarc=pass" in auth_results.lower(): dmarc = "pass"
                                elif "dmarc=fail" in auth_results.lower(): dmarc = "fail"

                                # Save test result
                                new_test = MailTest(
                                    test_id=test_id,
                                    subject=subject,
                                    sender=msg.get("From"),
                                    body=body,
                                    headers=headers_str,
                                    spf_status=spf,
                                    dkim_status=dkim,
                                    dmarc_status=dmarc
                                )
                                session.add(new_test)
                                session.commit()
                                logger.info(f"Received mail test {test_id}")
                                
                                mail.store(e_id, '+FLAGS', r'\Deleted')
                        except Exception as test_err:
                            logger.error(f"Error processing test email: {test_err}")
            
        mail.expunge()
        mail.close()
        mail.logout()

    except Exception as e:
        logger.error(f"Error checking inbox: {e}")
    finally:
        session.close()

def send_discord_alert(message):
    if not CONFIG['DISCORD_WEBHOOK_URL']:
        return
    try:
        requests.post(CONFIG['DISCORD_WEBHOOK_URL'], json={"content": message})
    except Exception as e:
        logger.error(f"Failed to send discord alert: {e}")

def send_email_alert(message):
    """Sends a formatted HTML alert email."""
    if not CONFIG['ALERT_MAIL_RECIPIENT'] or not CONFIG['SMTP_HOST']:
        logger.warning("[DEBUG] Email alert skipped: ALERT_MAIL_RECIPIENT or SMTP_HOST not set.")
        return

    try:
        # Prepare message for HTML
        html_message = message.replace('\n', '<br>')
        
        # Create HTML email for alert
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; background-color: #f4f4f4; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; border: 1px solid #ddd; }}
                .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; }}
                .header.recovery {{ background: #198754; }}
                .content {{ padding: 30px; line-height: 1.6; color: #333; }}
                .footer {{ background: #eee; padding: 10px; text-align: center; font-size: 12px; color: #777; }}
                .code-block {{ background: #f8f9fa; border: 1px solid #eee; padding: 10px; font-family: monospace; word-break: break-all; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header {'recovery' if 'Recovered' in message else ''}">
                    <h2>MailDT Alert Notification</h2>
                </div>
                <div class="content">
                    <p>An event occurred in your mail delivery monitoring system:</p>
                    <div class="code-block">
                        {html_message}
                    </div>
                    <p>Please check the <a href="http://localhost:5000">Dashboard</a> for more details.</p>
                </div>
                <div class="footer">
                    Sent by MailDT &bull; Automated Monitoring
                </div>
            </div>
        </body>
        </html>
        """

        msg = MIMEText(html_body, 'html')
        msg['Subject'] = f"MailDT Alert: {'Recovery' if 'Recovered' in message else 'Incident'} Detected"
        msg['From'] = CONFIG['SMTP_USER']
        msg['To'] = CONFIG['ALERT_MAIL_RECIPIENT']

        # Choose connection type based on port
        if CONFIG['SMTP_PORT'] == 465:
            server = smtplib.SMTP_SSL(CONFIG['SMTP_HOST'], CONFIG['SMTP_PORT'])
        else:
            server = smtplib.SMTP(CONFIG['SMTP_HOST'], CONFIG['SMTP_PORT'])
            server.starttls()

        with server:
            server.login(CONFIG['SMTP_USER'], CONFIG['SMTP_PASS'])
            server.sendmail(CONFIG['SMTP_USER'], [CONFIG['ALERT_MAIL_RECIPIENT']], msg.as_string())
        
        logger.info(f"[DEBUG] Email alert sent to {CONFIG['ALERT_MAIL_RECIPIENT']}")

    except Exception as e:
        logger.error(f"[DEBUG] Failed to send email alert: {e}")

def check_delays():
    """Checks for emails sent > their specific alert_threshold ago that haven't arrived."""
    session = Session()
    try:
        now = datetime.datetime.utcnow()
        
        # Cache recipient alert status
        recipients = session.query(Recipient).all()
        # Map email -> (email_enabled, discord_enabled)
        alerts_map = {r.email: (r.email_alerts_enabled, r.discord_alerts_enabled) for r in recipients}
        
        # Find all pending probes that haven't alerted yet
        pending_probes = session.query(EmailProbe).filter(
            EmailProbe.status == 'PENDING',
            EmailProbe.alert_sent == False
        ).all()

        for probe in pending_probes:
            # Use probe specific threshold, fallback to global default if null (for old records)
            threshold = probe.alert_threshold or CONFIG['ALERT_THRESHOLD']
            deadline = probe.sent_at + datetime.timedelta(seconds=threshold)
            
            if now > deadline:
                logger.info(f"[DEBUG] Delay Detected: Probe {probe.guid} for {probe.recipient_email} exceeded threshold ({threshold}s). Deadline was {deadline}")
                probe.status = 'MISSING'
                probe.alert_sent = True
                
                # Fetch recipient to check if we should send alert
                recipient = session.query(Recipient).filter_by(email=probe.recipient_email).first()
                if recipient:
                    if not recipient.alert_active:
                        logger.info(f"[DEBUG] Alerting: Probe {probe.guid} is the first failure. Sending notification.")
                        msg = f"⚠️ **Mail Delivery Alert**\nProbe `{probe.guid}` to `{probe.recipient_email}` sent at {probe.sent_at} is missing (> {threshold}s)."
                        
                        if recipient.discord_alerts_enabled:
                            send_discord_alert(msg)
                        
                        if recipient.email_alerts_enabled:
                            send_email_alert(msg)
                        
                        recipient.alert_active = True
                    else:
                        logger.info(f"[DEBUG] Alerting: Probe {probe.guid} missing, but {recipient.email} already in alert state. Skipping duplicate notification.")
                else:
                    logger.warning(f"Probe {probe.guid} has no matching recipient record.")
            else:
                # Optional: Log how long until expiration
                remaining = (deadline - now).total_seconds()
                if remaining < 60: # Only log if close to expiration
                    logger.info(f"[DEBUG] Monitoring: Probe {probe.guid} for {probe.recipient_email} expires in {remaining:.1f}s")

        session.commit()

    except Exception as e:
        logger.error(f"Error checking delays: {e}")
    finally:
        session.close()


# --- Flask App ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'maildt-default-secret-key-change-me')

# Apply ProxyFix middleware if enabled
if CONFIG['ENABLE_PROXY']:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session for login
        if 'logged_in' in session:
            return f(*args, **kwargs)
        
        if request.is_json or request.path.startswith('/api/'):
             return jsonify({"error": "Unauthorized"}), 401
             
        return redirect(url_for('login', next=request.url))
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp')
        
        if username == CONFIG['ADMIN_USER'] and password == CONFIG['ADMIN_PASSWORD']:
            # Check TOTP if configured
            if CONFIG['ADMIN_TOTP_SECRET']:
                totp = pyotp.TOTP(CONFIG['ADMIN_TOTP_SECRET'])
                if not totp.verify(totp_code):
                    return render_template('login.html', error="Invalid TOTP code", show_totp=True)
            
            session['logged_in'] = True
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials", show_totp=bool(CONFIG['ADMIN_TOTP_SECRET']))
    
    return render_template('login.html', show_totp=bool(CONFIG['ADMIN_TOTP_SECRET']))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/settings')
@login_required
def settings():
    # Hide passwords for display
    safe_config = CONFIG.copy()
    if safe_config['SMTP_PASS']: safe_config['SMTP_PASS'] = '********'
    if safe_config['IMAP_PASS']: safe_config['IMAP_PASS'] = '********'
    if safe_config['ADMIN_PASSWORD']: safe_config['ADMIN_PASSWORD'] = '********'
    if safe_config['ADMIN_TOTP_SECRET']: safe_config['ADMIN_TOTP_SECRET'] = '********'
    
    # Mask Database URL password
    import re
    if safe_config['DATABASE_URL']:
        safe_config['DATABASE_URL'] = re.sub(r'(://[^:]+):([^@]+)@', r'\1:********@', safe_config['DATABASE_URL'])
        
    return render_template('settings.html', config=safe_config)

@app.route('/recipients')
@login_required
def recipients_page():
    return render_template('recipients.html')

@app.route('/mail-tester')
def mail_tester_page():
    return render_template('mail_tester.html', imap_user=CONFIG['IMAP_USER'])

@app.route('/api/mail-tester/check/<test_id>')
def api_mail_tester_check(test_id):
    session = Session()
    try:
        test = session.query(MailTest).filter_by(test_id=test_id).first()
        if test:
            # Prepare data to return
            result = {
                'found': True,
                'subject': test.subject,
                'sender': test.sender,
                'received_at': test.received_at.isoformat(),
                'spf': test.spf_status,
                'dkim': test.dkim_status,
                'dmarc': test.dmarc_status,
                'headers': test.headers,
                'body': test.body
            }
            
            # If found, we can remove from active tracking
            if test_id in ACTIVE_TESTS:
                del ACTIVE_TESTS[test_id]
            
            # Remove from database so it's only "received" once
            session.delete(test)
            session.commit()
            
            return jsonify(result)
        return jsonify({'found': False})
    finally:
        session.close()

@app.route('/api/mail-tester/start/<test_id>', methods=['POST'])
def api_mail_tester_start(test_id):
    ACTIVE_TESTS[test_id] = datetime.datetime.utcnow()
    logger.info(f"Fast polling enabled for test: {test_id}")
    return jsonify({'status': 'started'})

@app.route('/api/recipients', methods=['GET', 'POST'])
@login_required
def api_recipients():
    session = Session()
    try:
        if request.method == 'GET':
            recipients = session.query(Recipient).all()
            return jsonify([{
                'id': r.id, 
                'email': r.email, 
                'active': r.active,
                'send_interval': r.send_interval,
                'alert_threshold': r.alert_threshold,
                'email_alerts_enabled': r.email_alerts_enabled,
                'discord_alerts_enabled': r.discord_alerts_enabled
            } for r in recipients])
            
        elif request.method == 'POST':
            data = request.json
            if not data or 'email' not in data:
                return jsonify({'error': 'Email required'}), 400
            
            existing = session.query(Recipient).filter_by(email=data['email']).first()
            if existing:
                return jsonify({'error': 'Recipient already exists'}), 400
                
            new_r = Recipient(
                email=data['email'], 
                active=True,
                send_interval=int(data.get('send_interval', 3600)),
                alert_threshold=int(data.get('alert_threshold', 300)),
                email_alerts_enabled=bool(data.get('email_alerts_enabled', True)),
                discord_alerts_enabled=bool(data.get('discord_alerts_enabled', True))
            )
            session.add(new_r)
            session.commit()
            return jsonify({'message': 'Added', 'id': new_r.id})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/recipients/<int:r_id>', methods=['DELETE'])
@login_required
def delete_recipient(r_id):
    session = Session()
    try:
        r = session.get(Recipient, r_id)
        if r:
            # Delete associated probe history first
            session.query(EmailProbe).filter_by(recipient_email=r.email).delete()
            # Delete the recipient
            session.delete(r)
            session.commit()
            return jsonify({'message': 'Deleted and history cleared'})
        return jsonify({'error': 'Not found'}), 404
    finally:
        session.close()

@app.route('/api/recipients/<int:r_id>', methods=['PUT'])
@login_required
def update_recipient(r_id):
    session = Session()
    try:
        r = session.get(Recipient, r_id)
        if not r:
            return jsonify({'error': 'Not found'}), 404
        
        data = request.json
        if 'send_interval' in data:
            r.send_interval = int(data['send_interval'])
            # Reset next send time to now to trigger immediate schedule update or just let it roll
            # If we shorten it, we might want it to happen sooner. 
            # If we lengthen it, the old next_send_at is still valid until it fires.
        if 'alert_threshold' in data:
            r.alert_threshold = int(data['alert_threshold'])
        if 'active' in data:
            r.active = bool(data['active'])
        if 'email_alerts_enabled' in data:
            r.email_alerts_enabled = bool(data['email_alerts_enabled'])
        if 'discord_alerts_enabled' in data:
            r.discord_alerts_enabled = bool(data['discord_alerts_enabled'])
            
        session.commit()
        return jsonify({'message': 'Updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/stats')
def api_stats():
    """Returns the latest probe for each recipient."""
    session = Session()
    try:
        # Subquery to find the latest probe ID for each recipient
        from sqlalchemy import func
        subq = session.query(
            EmailProbe.recipient_email,
            func.max(EmailProbe.sent_at).label('max_sent_at')
        ).group_by(EmailProbe.recipient_email).subquery()
        
        # Join to get full details
        latest_probes = session.query(EmailProbe).join(
            subq,
            (EmailProbe.recipient_email == subq.c.recipient_email) & 
            (EmailProbe.sent_at == subq.c.max_sent_at)
        ).all()
        
        data = []
        for p in latest_probes:
            data.append({
                'guid': p.guid,
                'sent_at': p.sent_at.isoformat() if p.sent_at else None,
                'received_at': p.received_at.isoformat() if p.received_at else None,
                'latency': round(p.latency, 2),
                'status': p.status,
                'recipient': p.recipient_email,
                'alert_threshold': p.alert_threshold
            })
        
        return jsonify(data)
    finally:
        session.close()

@app.route('/api/history')
def api_history():
    """Returns history, optionally filtered by recipient."""
    session = Session()
    try:
        limit = request.args.get('limit', 100, type=int)
        recipient = request.args.get('recipient')
        
        query = session.query(EmailProbe)
        if recipient:
            query = query.filter_by(recipient_email=recipient)
            
        recent = query.order_by(desc(EmailProbe.sent_at)).limit(limit).all()
        
        data = []
        for p in recent:
            data.append({
                'guid': p.guid,
                'sent_at': p.sent_at.isoformat() if p.sent_at else None,
                'received_at': p.received_at.isoformat() if p.received_at else None,
                'latency': round(p.latency, 2),
                'status': p.status,
                'recipient': p.recipient_email,
                'alert_threshold': p.alert_threshold
            })
        
        return jsonify(data)
    finally:
        session.close()

def cleanup_old_probes():
    """Deletes probes older than 7 days."""
    session = Session()
    try:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        deleted = session.query(EmailProbe).filter(EmailProbe.sent_at < cutoff).delete()
        session.commit()
        if deleted > 0:
            logger.info(f"Cleanup: Deleted {deleted} old probes.")
    except Exception as e:
        logger.error(f"Error in cleanup: {e}")
    finally:
        session.close()

# --- Scheduler Setup ---
scheduler = BackgroundScheduler()

# Add jobs if config is present (checking basic vars)
if CONFIG['SMTP_HOST']:
    # Check for sends every 30 seconds
    scheduler.add_job(func=send_probe_email, trigger="interval", seconds=30)
    logger.info(f"Scheduler: Added send job every 30s (checking per-recipient schedules)")

if CONFIG['IMAP_HOST']:
    # We run the job frequently, but the function itself handles throttling if no active tests are running
    scheduler.add_job(func=check_inbox, trigger="interval", seconds=5)
    logger.info(f"Scheduler: Added check job (fast-mode enabled when tests are active)")

scheduler.add_job(func=check_delays, trigger="interval", seconds=30) # Check delays every 30s
scheduler.add_job(func=cleanup_old_probes, trigger="interval", hours=24) # Cleanup daily
scheduler.start()

# --- Main Entry ---
if __name__ == '__main__':
    # Shutdown scheduler on exit? It's a daemon, but good practice.
    import atexit
    atexit.register(lambda: scheduler.shutdown())
    
    app.run(host='0.0.0.0', port=5000, debug=False)
