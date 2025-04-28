#!/bin/bash

echo "[🔥] Setting up Python virtual environment..."

# Step 1: Create the virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "[*] Virtual environment created."
fi

# Step 2: Activate the virtual environment
source .venv/bin/activate
echo "[*] Virtual environment activated."

# Step 3: Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
echo "[✅] Dependencies installed."

# Step 4: Generate SSH host key if missing
KEY_DIR=".ssh_keys"
KEY_PATH="$KEY_DIR/ssh_host_key"

if [ ! -f "$KEY_PATH" ]; then
    echo "[*] SSH host key not found. Generating..."

    mkdir -p "$KEY_DIR"
    ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N ''

    echo "[✅] SSH host key generated at $KEY_PATH."
else
    echo "[*] SSH host key already exists at $KEY_PATH."
fi
