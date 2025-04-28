# Log file path
LOG_FILE = "output/log/ids.log"

# IP address of the local machine to protect (None = auto-detect)
MY_LOCAL_IP = None

# Sliding window (in seconds) for attack detection
TIME_WINDOW = 60

# SYN scan: how many different destination ports trigger an alert
PORT_SCAN_THRESHOLD = 30

# Brute-force: how many repeated connections to a single port trigger an alert
BRUTEFORCE_THRESHOLD = 10

# Interval (seconds) for "still ongoing" incident updates
ALERT_INTERVAL = 10

# Force periodic summaries even without activity
SUMMARY_INTERVAL = 30
