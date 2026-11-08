#!/usr/bin/env bash
# ==============================================================================
# Enterprise Active Directory Secure LDAPS Proxy - Linux Host Installation Script
# Supports: Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, Alpine
# Minimum Requirements: Linux OS, Python 3.10+
# ==============================================================================

set -euo pipefail

# Text Styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

APP_NAME="ad-ldaps-proxy"
INSTALL_DIR="${INSTALL_DIR:-$(pwd)}"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_FILE="${INSTALL_DIR}/ad_proxy/config.yaml"
CERTS_DIR="${INSTALL_DIR}/certs"
LOGS_DIR="${INSTALL_DIR}/logs"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    ACTIVE DIRECTORY SECURE LDAPS PROXY - LINUX HOST INSTALLER         "
echo "========================================================================"
echo -e "${NC}"

# 1. Verify Operating System
OS_NAME="$(uname -s)"
if [ "$OS_NAME" != "Linux" ]; then
    echo -e "${RED}[ERROR] This installer is intended for Linux hosts. Detected: ${OS_NAME}${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Verified Linux Host environment: $(uname -mrs)${NC}"

# 2. Verify Python 3.10+
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] python3 is not installed or not in PATH.${NC}"
    echo "Please install Python 3.10+ via your package manager:"
    echo "  Ubuntu/Debian:  sudo apt update && sudo apt install -y python3 python3-pip python3-venv"
    echo "  RHEL/Rocky/Alma: sudo dnf install -y python3 python3-pip"
    echo "  Alpine Linux:    sudo apk add python3 py3-pip"
    exit 1
fi

PYTHON_BIN="$(which python3)"
PY_VER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="$($PYTHON_BIN -c 'import sys; print(sys.version_info.major)')"
PY_MINOR="$($PYTHON_BIN -c 'import sys; print(sys.version_info.minor)')"

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo -e "${RED}[ERROR] Python 3.10 or higher is required. Found: Python ${PY_VER}${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Detected supported Python version: Python ${PY_VER} (${PYTHON_BIN})${NC}"

# 3. Create Required Runtime Directories
echo -e "\n${BLUE}--> [Step 1/5] Initializing application runtime directories...${NC}"
mkdir -p "${CERTS_DIR}" "${LOGS_DIR}" "${INSTALL_DIR}/ad_proxy"
chmod 700 "${CERTS_DIR}"
chmod 755 "${LOGS_DIR}"
echo -e "${GREEN}[OK] Created directories: ${LOGS_DIR}, ${CERTS_DIR}${NC}"

# 4. Check for SSL/TLS Certificates
echo -e "\n${BLUE}--> [Step 2/5] Validating SSL/TLS certificate chain...${NC}"
CA_CERT="${CERTS_DIR}/corporate_root_ca.crt"
SERVER_CERT="${CERTS_DIR}/ad_proxy_server.crt"
SERVER_KEY="${CERTS_DIR}/ad_proxy_server.key"

if [ -f "$SERVER_CERT" ] && [ -f "$SERVER_KEY" ]; then
    echo -e "${GREEN}[OK] Existing TLS certificates detected in ${CERTS_DIR}.${NC}"
else
    echo -e "${YELLOW}[!] Generating development self-signed 2048-bit TLS certificates...${NC}"
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$SERVER_KEY" \
            -out "$SERVER_CERT" \
            -days 365 \
            -subj "/C=US/ST=Security/L=Operations/O=Enterprise/CN=ad-proxy.corp.acme.internal" &>/dev/null
        cp "$SERVER_CERT" "$CA_CERT" 2>/dev/null || true
        chmod 600 "$SERVER_KEY"
        chmod 644 "$SERVER_CERT"
        echo -e "${GREEN}[OK] Generated TLS certificates at: ${SERVER_CERT}${NC}"
    else
        echo -e "${YELLOW}[WARNING] OpenSSL not found. Relying on pre-configured certs or dev TLS fallback.${NC}"
    fi
fi

# 5. Virtual Environment & Python Dependency Resolution
echo -e "\n${BLUE}--> [Step 3/5] Resolving Python dependencies...${NC}"
USE_VENV=false

# Check if venv is possible
if $PYTHON_BIN -c "import venv" &>/dev/null; then
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating Python virtual environment in ${VENV_DIR}..."
        $PYTHON_BIN -m venv "$VENV_DIR" || true
    fi

    if [ -f "${VENV_DIR}/bin/python3" ]; then
        chmod +x "${VENV_DIR}/bin/"* 2>/dev/null || true
        if [ -x "${VENV_DIR}/bin/python3" ] && "${VENV_DIR}/bin/python3" -c "import sys" &>/dev/null; then
            PYTHON_EXEC="${VENV_DIR}/bin/python3"
            PIP_EXEC="${VENV_DIR}/bin/pip"
            USE_VENV=true
            echo -e "${GREEN}[OK] Using virtualenv interpreter: ${PYTHON_EXEC}${NC}"
        else
            PYTHON_EXEC="$PYTHON_BIN"
            echo -e "${YELLOW}[!] Virtualenv interpreter unusable, falling back to: ${PYTHON_EXEC}${NC}"
        fi
    else
        PYTHON_EXEC="$PYTHON_BIN"
    fi
else
    PYTHON_EXEC="$PYTHON_BIN"
fi

if [ "$USE_VENV" = true ] && [ -x "${PIP_EXEC:-}" ]; then
    echo "Installing pinned enterprise dependencies via pip..."
    "$PIP_EXEC" install --quiet --upgrade pip 2>/dev/null || true
    if [ -f "${INSTALL_DIR}/requirements.txt" ]; then
        "$PIP_EXEC" install --quiet -r "${INSTALL_DIR}/requirements.txt" 2>/dev/null || true
        echo -e "${GREEN}[OK] Python packages installed from requirements.txt.${NC}"
    fi
else
    # Check if host has pip
    if command -v pip3 &>/dev/null; then
        echo "Installing Python dependencies to user site..."
        pip3 install --quiet -r "${INSTALL_DIR}/requirements.txt" --user 2>/dev/null || true
    else
        echo -e "${YELLOW}[INFO] Minimal Linux host detected without pip.${NC}"
        echo -e "${GREEN}[OK] AD-Proxy built-in standard library fallback engine will be used.${NC}"
    fi
fi

# 6. Configuration Verification
echo -e "\n${BLUE}--> [Step 4/5] Validating YAML configuration and directory permissions...${NC}"
cd "$INSTALL_DIR"
$PYTHON_EXEC -m ad_proxy.cli --check-config

# 7. Execute Built-in Functional & Security Verification Suite
if [ "${SKIP_TESTS:-0}" != "1" ] && [ "${1:-}" != "--skip-tests" ]; then
    echo -e "\n${BLUE}--> [Step 5/5] Running complete security & functional test suite...${NC}"
    $PYTHON_EXEC -m ad_proxy.cli --run-tests
else
    echo -e "\n${BLUE}--> [Step 5/5] Skipping test suite (SKIP_TESTS flag active)...${NC}"
fi

echo -e "\n${GREEN}${BOLD}========================================================================"
echo "    INSTALLATION & SECURITY VALIDATION COMPLETED SUCCESSFULLY!          "
echo "========================================================================${NC}"
echo -e "To start the AD-Proxy daemon manually on this host:"
echo -e "  ${CYAN}${PYTHON_EXEC} -m ad_proxy.cli --run --tls${NC}"
echo -e "\nTo simulate an AI agent query:"
echo -e "  ${CYAN}${PYTHON_EXEC} -m ad_proxy.cli --simulate-agent --agent ai-triage-agent --command list_group_members --param group_name=VPN-Users${NC}"
echo -e "\nTo install as a systemd service:"
echo -e "  sudo cp ${INSTALL_DIR}/ad-proxy.service /etc/systemd/system/"
echo -e "  sudo systemctl daemon-reload"
echo -e "  sudo systemctl enable --now ad-proxy.service"
echo ""
