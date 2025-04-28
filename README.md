# 🐍 AutoBait — Intelligent SSH Honeypot


AutoBait is a lightweight LLM-powered honeypot designed to dynamically wake up only when an attack is detected.

It automatically **sniffs the network** for port scans and brute-force attempts, and only then **activates** a realistic **fake SSH server** that:
- **Simulates** a real Linux filesystem,
- **Handles real commands** internally when possible,
- **Delegates unknown commands** to an **LLM** for realistic bash-style answers,
- **Profiles** the attacker behavior,
- **Logs** everything neatly for later analysis.


## ✨ Key Features

| Feature                    | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| 🧠 Smart activation         | SSH honeypot stays **silent** until a scan or attack is detected             |
| 📂 Realistic filesystem      | Common Linux directories and "juicy" files (AWS creds, database dumps)      |
| 🤖 Hybrid CLI responses      | **Known commands** handled by AutoBait • **Unknown ones** invented by LLM   |
| 🔒 Permission simulation    | Correct "Permission denied" behavior without root privileges                |
| 🛡️ Attacker profiling       | Behavioral analysis generated with a Large Language Model (LLM)             |
| 🖥️ Real bash behavior       | No AI artifacts, no code blocks, no apologies — strictly bash-like answers |
| 📜 Lightweight logging      | Neat session logs (JSONL format) and profiling reports                     |




AutoBait/ │ ├── core/ # Traffic sniffer, honeypot launcher, logger ├── detection/ # SYN scan and brute-force detection ├── honeypot/ # Filesystem simulation (filesystem.py) ├── prompt/ # Prompts for LLM (system prompt, scenario, profiling) ├── output/ │ ├── log/ # Logs (honeypot sessions, IDS alerts) │ └── sessions/ # Attacker session profiles ├── utils/ # Helpers (network info, etc.) ├── main.py # Entry point ├── honeyssh.py # SSH honeypot logic └── script.sh # Quick setup
