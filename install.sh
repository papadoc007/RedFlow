#!/bin/bash

# סקריפט התקנה עבור RedFlow
# Installation script for RedFlow

echo "============================"
echo "RedFlow Installation Script"
echo "============================"

# בדיקת הרשאות מנהל
# Check if root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Please run as root"
    exit 1
fi

# התקנת חבילות מערכת דרושות
# Install required system packages
echo "[+] Installing system dependencies..."
apt-get update
apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    enum4linux \
    hydra \
    gobuster \
    whois \
    dnsutils \
    theharvester \
    whatweb \
    wafw00f \
    sublist3r \
    metasploit-framework \
    searchsploit \
    curl \
    wget

# התקנת החבילות של Python
# Install Python requirements
echo "[+] Installing Python requirements..."
pip3 install -r requirements.txt

# יצירת תיקיות דרושות
# Create required directories
echo "[+] Creating required directories..."
mkdir -p scans
mkdir -p logs

# העתקת סקריפטים למיקום הנכון
# Copy scripts to the correct location
echo "[+] Setting up files..."

# הגדרת הרשאות הרצה
# Set execution permissions
echo "[+] Setting permissions..."
chmod +x redflow.py
chmod +x redflow_gui.py

# בדיקת אם הכל הותקן בהצלחה
# Verify installation
echo "[+] Verifying installation..."
python3 -c "import requests, rich, markdown, openai; print('Python dependencies: OK')"
which nmap enum4linux hydra gobuster searchsploit > /dev/null && echo "System tools: OK"

echo ""
echo "============================"
echo "Installation completed!"
echo ""
echo "To run RedFlow:"
echo "  python3 redflow.py --target example.com"
echo ""
echo "To run RedFlow GUI:"
echo "  python3 redflow_gui.py"
echo ""
echo "To set up your OpenAI API key for GPT Exploit Advisor:"
echo "  echo 'YOUR_API_KEY' > ~/.openai_api_key"
echo "  # or add to config.yaml"
echo "============================" 