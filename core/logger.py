# core/logger.py

import os
import time
from config import LOG_FILE

# 📂 Create the log directory if it does not exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def _write_log(level, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{level}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(log_line + "\n")

def log_alert(message):
    _write_log("ALERT", message)

def log_debug(message):
    _write_log("DEBUG", message)

def log_error(message):
    _write_log("ERROR", message)
