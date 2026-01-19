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

# Global scheduler instance
scheduler = BackgroundScheduler()

def init_scheduler():
    """Initializes the scheduler, database, and jobs."""
    logger.info("Scheduler initializing...")
    try:
        run_migrations()
        reset_alert_states()
    except Exception as err:
        logger.error(f"CRITICAL: Scheduler database initialization failed: {err}")
        return

    # Add jobs if config is present
    if CONFIG['SMTP_HOST']:
        scheduler.add_job(func=send_probe_email, trigger="interval", seconds=30)
        logger.info("Scheduler: Added send job every 30s")

    if CONFIG['IMAP_HOST']:
        scheduler.add_job(func=check_inbox, trigger="interval", seconds=5)
        logger.info("Scheduler: Added check job every 5s")

    scheduler.add_job(func=check_delays, trigger="interval", seconds=30)
    scheduler.add_job(func=cleanup_old_probes, trigger="interval", hours=24)

    logger.info("Scheduler starting...")
    scheduler.start()

_scheduler_initialized = False

@app.before_request
def start_scheduler():
    global _scheduler_initialized
    if not _scheduler_initialized:
        init_scheduler()
        _scheduler_initialized = True

# Shutdown scheduler on process exit
import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # Fallback for manual execution
    init_scheduler()
    app.run(host='0.0.0.0', port=5001)