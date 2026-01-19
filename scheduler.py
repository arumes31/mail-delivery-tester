import os
import logging
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
from app import (
    CONFIG, logger, run_migrations, reset_alert_states,
    send_probe_email, check_inbox, check_delays, cleanup_old_probes
)

# Create a minimal Flask app for Gunicorn to run
app = Flask(__name__)

@app.route('/health')
def health():
    return {"status": "scheduler running"}, 200

# Initialize database and state once when the Gunicorn worker loads this module
logger.info("Scheduler worker initializing...")
run_migrations()
reset_alert_states()

# Setup Scheduler
# We use BackgroundScheduler here because Gunicorn will own the main process/thread
scheduler = BackgroundScheduler()

# Add jobs if config is present
if CONFIG['SMTP_HOST']:
    # Poll every 10s to see if any recipient is due for a probe
    scheduler.add_job(func=send_probe_email, trigger="interval", seconds=10)
    logger.info("Scheduler: Added send job polling every 10s")

if CONFIG['IMAP_HOST']:
    # Use the configured CHECK_INTERVAL for IMAP polling frequency
    imap_interval = CONFIG.get('CHECK_INTERVAL', 30)
    if imap_interval < 5: imap_interval = 5 # Minimum 5s
    scheduler.add_job(func=check_inbox, trigger="interval", seconds=imap_interval)
    logger.info(f"Scheduler: Added check job every {imap_interval}s")

scheduler.add_job(func=check_delays, trigger="interval", seconds=30)
scheduler.add_job(func=cleanup_old_probes, trigger="interval", hours=24)

logger.info("Scheduler starting...")
scheduler.start()

# Shutdown scheduler on process exit
import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # Fallback for manual execution
    app.run(host='0.0.0.0', port=5001)