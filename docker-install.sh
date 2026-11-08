#!/usr/bin/env bash
# ==============================================================================
# Active Directory Secure LDAPS Proxy - Automated Docker Installer & Runner
# Compliant with official Docker Compose Specification (v2+) & CIS Benchmark
# Modes:
#   --headless   : Deploy headless zero-trust LDAPS Proxy engine (Port 10636) [Default]
#   --fullstack  : Deploy full-stack Web Console (Port 3000) + LDAPS Engine (Port 10636)
#   --status     : Inspect running containers and TLS healthcheck status
#   --down       : Gracefully stop and clean up containers
# ==============================================================================

set -euo pipefail

# Text Styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${INSTALL_DIR}/certs"
LOGS_DIR="${INSTALL_DIR}/logs"
MODE="headless"

# Parse CLI options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fullstack|-f)
            MODE="fullstack"
            shift
            ;;
        --headless|-h)
            MODE="headless"
            shift
            ;;
        --status|-s)
            MODE="status"
            shift
            ;;
        --down|-d)
            MODE="down"
            shift
            ;;
        --help)
            echo "Usage: ./docker-install.sh [--headless | --fullstack | --status | --down]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: ./docker-install.sh [--headless | --fullstack | --status | --down]"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    ACTIVE DIRECTORY SECURE LDAPS PROXY - DOCKER INSTALLATION WIZARD    "
echo "========================================================================"
echo -e "${NC}"

# 1. Verify Docker CLI is installed
if ! command -v docker &>/dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed or not in system PATH.${NC}"
    echo "Please install Docker from the official Docker documentation:"
    echo "  https://docs.docker.com/engine/install/"
    exit 1
fi
echo -e "${GREEN}[OK] Docker engine CLI detected: $(docker --version)${NC}"

# 2. Detect Compose v2 CLI
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
    echo -e "${GREEN}[OK] Modern Docker Compose v2 plugin detected: $(${COMPOSE_CMD} version)${NC}"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    echo -e "${YELLOW}[!] Using legacy docker-compose standalone binary: $(${COMPOSE_CMD} --version)${NC}"
else
    echo -e "${RED}[ERROR] Neither 'docker compose' (v2 plugin) nor 'docker-compose' found.${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

cd "$INSTALL_DIR"

# Handle --down
if [ "$MODE" = "down" ]; then
    echo -e "\n${BLUE}Stopping and tearing down AD-Proxy Docker containers...${NC}"
    $COMPOSE_CMD -f docker-compose.yml down 2>/dev/null || true
    $COMPOSE_CMD -f docker-compose.fullstack.yml down 2>/dev/null || true
    echo -e "${GREEN}[OK] All AD-Proxy containers stopped.${NC}"
    exit 0
fi

# Handle --status
if [ "$MODE" = "status" ]; then
    echo -e "\n${BLUE}Inspecting AD-Proxy Docker containers status...${NC}"
    $COMPOSE_CMD -f docker-compose.yml ps 2>/dev/null || true
    $COMPOSE_CMD -f docker-compose.fullstack.yml ps 2>/dev/null || true
    exit 0
fi

# 3. Create Required Persistent Host Directories
echo -e "\n${BLUE}--> [Step 1/4] Preparing host storage and volume mounts...${NC}"
mkdir -p "${CERTS_DIR}" "${LOGS_DIR}" "${INSTALL_DIR}/ad_proxy"
chmod 700 "${CERTS_DIR}"
chmod 755 "${LOGS_DIR}"
echo -e "${GREEN}[OK] Host persistent directories initialized (logs/ and certs/)${NC}"

# 4. Generate TLS Certificates if needed
echo -e "\n${BLUE}--> [Step 2/4] Validating TLS certificates for LDAPS...${NC}"
SERVER_CERT="${CERTS_DIR}/ad_proxy_server.crt"
SERVER_KEY="${CERTS_DIR}/ad_proxy_server.key"
CA_CERT="${CERTS_DIR}/corporate_root_ca.crt"

if [ -f "$SERVER_CERT" ] && [ -f "$SERVER_KEY" ]; then
    echo -e "${GREEN}[OK] Existing TLS certificates detected in ${CERTS_DIR}.${NC}"
else
    echo -e "${YELLOW}[!] Generating development 2048-bit RSA TLS certificates...${NC}"
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
        echo -e "${YELLOW}[WARNING] OpenSSL not found. Ensure certificates exist in ${CERTS_DIR}.${NC}"
    fi
fi

# 5. Build and Launch Containers
if [ "$MODE" = "fullstack" ]; then
    COMPOSE_FILE="docker-compose.fullstack.yml"
    echo -e "\n${BLUE}--> [Step 3/4] Building and launching Full-Stack Container (Web Console + Proxy Engine)...${NC}"
else
    COMPOSE_FILE="docker-compose.yml"
    echo -e "\n${BLUE}--> [Step 3/4] Building and launching Hardened Headless LDAPS Proxy Engine...${NC}"
fi

echo -e "Executing: ${CYAN}${COMPOSE_CMD} -f ${COMPOSE_FILE} up -d --build${NC}"
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d --build

# 6. Verify Health
echo -e "\n${BLUE}--> [Step 4/4] Verifying container status and healthchecks...${NC}"
sleep 3
$COMPOSE_CMD -f "$COMPOSE_FILE" ps

echo -e "\n${GREEN}${BOLD}========================================================================"
echo "    DOCKER INSTALLATION & INITIALIZATION COMPLETED SUCCESSFULLY!        "
echo "========================================================================${NC}"

if [ "$MODE" = "fullstack" ]; then
    echo -e "Web Management Console:   ${CYAN}http://localhost:3000${NC}"
    echo -e "Secure LDAPS REST Port:   ${CYAN}https://localhost:10636${NC}"
else
    echo -e "Secure LDAPS REST Port:   ${CYAN}https://localhost:10636${NC}"
fi

echo -e "\nUseful Docker Operations:"
echo -e "  View real-time logs:     ${CYAN}${COMPOSE_CMD} -f ${COMPOSE_FILE} logs -f${NC}"
echo -e "  Check container health:  ${CYAN}${COMPOSE_CMD} -f ${COMPOSE_FILE} ps${NC}"
echo -e "  Stop container:          ${CYAN}${COMPOSE_CMD} -f ${COMPOSE_FILE} down${NC}"
echo -e "  Test health endpoint:    ${CYAN}curl -k https://localhost:10636/health${NC}"
echo ""
