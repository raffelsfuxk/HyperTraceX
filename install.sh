#!/bin/bash
# FORENSIX - Digital Forensics Platform Installer
# Created by: raffelsfuxk

echo "========================================="
echo "  FORENSIX - Digital Forensics Platform"
echo "  Version 1.0.0"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash install.sh"
    exit 1
fi

echo "[*] Updating package list..."
apt update -y

echo "[*] Installing system dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    sqlite3 \
    testdisk \
    tesseract-ocr \
    p7zip-full \
    unrar-free

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || \
pip3 install -r requirements.txt 2>/dev/null || \
echo "[!] Python package installation failed - please install manually"

echo "[*] Installing optional forensic tools..."
apt install -y \
    python3-pypff 2>/dev/null || echo "    pypff not available"
apt install -y \
    python3-registry 2>/dev/null || echo "    python-registry not available"
apt install -y \
    lime-forensics-dkms 2>/dev/null || echo "    LiME not available"

echo "[*] Creating symlink..."
chmod +x forensix.py
ln -sf $(pwd)/forensix.py /usr/local/bin/forensix 2>/dev/null

echo ""
echo "[+] Installation complete!"
echo "    Run: sudo forensix"
echo "    Or:  sudo python3 forensix.py"
echo ""
