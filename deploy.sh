#!/bin/bash
# HyperTraceX Deployment Script
# Deploy HyperTraceX to production environment

set -e

echo "========================================="
echo "  HyperTraceX Deployment Script v1.0.0"
echo "========================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root: sudo bash deploy.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Starting HyperTraceX deployment...${NC}"

# 1. Update system
echo "[*] Step 1/8: Updating system packages..."
apt update -y && apt upgrade -y

# 2. Install core dependencies
echo "[*] Step 2/8: Installing core dependencies..."
apt install -y python3 python3-pip python3-dev git curl wget

# 3. Install forensic tools
echo "[*] Step 3/8: Installing forensic tools..."
apt install -y \
    aircrack-ng reaver hcxtools hashcat \
    tshark tcpdump testdisk photorec \
    sqlite3 p7zip-full unrar-free \
    tesseract-ocr

# 4. Install Python packages
echo "[*] Step 4/8: Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || \
pip3 install -r requirements.txt

# 5. Install optional modules
echo "[*] Step 5/8: Installing optional modules..."
pip3 install fpdf flask flask-socketio --break-system-packages 2>/dev/null || true
apt install -y python3-tk 2>/dev/null || true

# 6. Compile native modules
echo "[*] Step 6/8: Compiling native C++ modules..."
if [ -d "native" ]; then
    cd native
    make clean 2>/dev/null || true
    make all 2>/dev/null || echo "    Native compilation skipped (g++ not found)"
    make install 2>/dev/null || true
    cd ..
fi

# 7. Setup symlinks
echo "[*] Step 7/8: Setting up symlinks..."
chmod +x tracex.py
ln -sf $(pwd)/tracex.py /usr/local/bin/tracex
chmod +x deploy.sh

# 8. Create directories
echo "[*] Step 8/8: Creating working directories..."
mkdir -p /var/lib/tracex/{cases,evidence,output,logs,plugins}
chmod 755 /var/lib/tracex

echo ""
echo -e "${GREEN}[+] Deployment complete!${NC}"
echo ""
echo "  Run: sudo tracex"
echo "  Web: sudo tracex dashboard"
echo "  API: sudo tracex api"
echo ""
echo "  Configuration: /var/lib/tracex/"
echo "  Logs: /var/lib/tracex/logs/"
echo ""
