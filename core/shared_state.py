# core/shared_state.py

from collections import defaultdict


# Connection history by IP and destination port
log_dic = defaultdict(lambda: {
    "port_dst": defaultdict(int)
})

# Detected bruteforce attempts (key: (ip, port), value: timestamp)
bruteforce_ips = {}

# To limit log flood (key: (ip, port), value: last alert timestamp)
last_alert_time = {}

# Global verbosity (if True, all logs are printed)
verbose = False

bruters: set[str] = set()          # IPs allowed into the fake SSH
attempts: dict[str, int] = {} 
pinned_ips: set[str] = set()


