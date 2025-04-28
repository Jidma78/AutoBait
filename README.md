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


## 🛠️ Project Structure

```bash
AutoBait/
│
├── core/             # Traffic sniffer, honeypot launcher, logger
│   ├── honeypot_launcher.py
│   ├── logger.py
│   ├── shared_state.py
│   └── sniffer.py
│
├── detection/        # SYN scan and brute-force detection
│   ├── bruteforce.py
│   ├── syn_scan.py
│   └── tcp_flag_decoder.py         
│
├── prompt/           # Prompts for LLM (system prompt, scenario, profiling)
│   ├── profile_attacker.txt
│   ├── scenario.txt
│   └── system.txt
│
├── output/
│   ├── log/          # Logs (honeypot sessions, IDS alerts)
│   └── sessions/     # Attacker session profiles
│
├── utils/            # Helpers (network info, etc.)
│   └── netinfo.py
│
├── main.py           # Entry point (launches sniffer and honeypot)
├── honeyssh.py       # SSH honeypot core logic
└── filesystem.py
├── script.sh         # Quick setup script
└── requirements.txt  # Python dependencies




## 🚀 Quick Start

```bash
git clone https://github.com/Jidma78/AutoBait.git
cd AutoBait
bash script.sh
source .venvv/bin/activate
python3 main.py
```

- 🖥️ Starts passive network sniffing.
- 🔥 SSH honeypot auto-activates only when a scan or brute-force is detected.

## 📋 Requirements
Package | Version
Python | 3.9+
asyncssh | ≥ 2.13
scapy | ≥ 2.5
openai | ≤ 0.28
aiofiles | ≥ 23.1



## 🎯 How AutoBait Behaves
- If the attacker uses normal commands (e.g., ls, cat, cd, pwd) → AutoBait answers locally from its simulated filesystem.
- If the attacker sends an unknown or complex command (e.g., find /opt -name '*.sh') → AutoBait calls the LLM to invent a realistic bash output, keeping the deception perfect.
➡️ Mix between static simulation and dynamic generation for maximum realism.



