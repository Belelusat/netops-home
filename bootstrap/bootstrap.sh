#!/usr/bin/env bash
# =============================================================================
# NetOps Bootstrap Script
# =============================================================================
# PURPOSE:
#   Converts a fresh Ubuntu 24.04 LTS install into an automation-ready host.
#   Handles everything up to and including the first CIS IG1 compliance scan.
#   Ansible (running in Docker) takes over after this script completes.
#
# WHAT THIS SCRIPT DOES:
#   Phase 1 — Preflight:     Validates environment, loads variables, prompts user
#   Phase 2 — Network:       Configures interface via Netplan (DHCP or static)
#   Phase 3 — OS Baseline:   Updates, timezone, NTP, hostname, logging
#   Phase 4 — Admin User:    Creates admin user and group with sudo access
#   Phase 5 — SSH Hardening: Applies CIS-aligned SSH configuration
#   Phase 6 — Firewall:      Configures UFW baseline rules
#   Phase 7 — Docker:        Installs Docker using official method
#   Phase 8 — Git:           Configures git and clones repositories
#   Phase 9 — GOSS:          Installs GOSS and runs first compliance scan
#
# VARIABLE OVERRIDE PATTERN:
#   Every variable loaded from the vars file can be overridden at runtime.
#   The script shows the current value and asks to keep or change it.
#   Variables left blank in the vars file are always prompted.
#
# WHAT THIS SCRIPT DOES NOT DO:
#   - Configure network devices
#   - Populate NetBox
#   - Run Ansible playbooks (that happens from inside Docker)
#   - Manage SSH keys (future project)
#
# REQUIREMENTS:
#   - Ubuntu 24.04 LTS, fresh install
#   - Run as root or with sudo
#   - Internet access (or local mirror configured)
#
# USAGE:
#   sudo bash bootstrap.sh                          # uses bootstrap.vars in same directory
#   sudo bash bootstrap.sh --vars bootstrap.work.vars   # specify a vars file
#
# EXCEPTIONS REGISTER (controls intentionally deviated from CIS IG1 default):
#   EX-001: SSH password authentication enabled
#           Justification: No SSH key management infrastructure in place.
#           TACACS+ via Cisco ISE is planned as the production auth replacement.
#           Compensating controls: Strong password policy, MaxAuthTries=3,
#           root login disabled, AllowGroups restricts access to admin group only.
#   EX-002: Docker networking kernel parameters
#           Justification: Required for Docker bridge networking functionality.
#           Specific parameters documented in Phase 6 comments below.
#
# AUTHOR NOTES FOR FUTURE ADMINS:
#   - Variable descriptions are in bootstrap.vars — read it before editing
#   - Each phase logs to NETOPS_LOG_FILE defined in your vars file
#   - If a phase fails, the script stops — fix the error and re-run
#   - Re-running is safe; most steps check before acting (idempotent where possible)
# =============================================================================

set -euo pipefail
# set -e  : exit immediately if any command fails
# set -u  : treat unset variables as errors
# set -o pipefail : catch failures in piped commands, not just the last one

# =============================================================================
# INTERNAL CONSTANTS — do not edit these
# =============================================================================
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_VARS_FILE="${SCRIPT_DIR}/bootstrap.vars"
REQUIRED_OS="Ubuntu"
REQUIRED_VERSION="24.04"
MIN_DISK_GB=20
MIN_RAM_MB=1024

# Terminal colors for readable output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log() {
    # Writes timestamped message to both console and log file
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="[${timestamp}] [${level}] ${message}"

    # Console output with color
    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${NC}  ${message}" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC}  ${message}" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} ${message}" ;;
        PHASE) echo -e "\n${BOLD}${BLUE}>>> ${message}${NC}" ;;
        OK)    echo -e "${GREEN}  ✓${NC} ${message}" ;;
    esac

    # Write to log file if it exists yet (it won't during very early preflight)
    if [[ -n "${NETOPS_LOG_FILE:-}" ]] && [[ -d "$(dirname "$NETOPS_LOG_FILE")" ]]; then
        echo "$log_line" >> "$NETOPS_LOG_FILE"
    fi
}

die() {
    # Fatal error — log and exit
    log ERROR "$1"
    log ERROR "Bootstrap failed at $(date). Review log for details."
    exit 1
}

confirm() {
    # Prompt user for yes/no confirmation
    # Usage: confirm "Are you sure?" && do_something
    local prompt="$1"
    local response
    echo -e "${YELLOW}${prompt} [y/N]:${NC} " >/dev/tty
    read -r response </dev/tty
    [[ "$response" =~ ^[Yy]$ ]]
}

prompt_required() {
    # Prompts for a required value, re-asking until non-empty input is given
    # Usage: VALUE=$(prompt_required "Prompt text" "description for error")
    local prompt="$1"
    local description="$2"
    local value=""
    while [[ -z "$value" ]]; do
        echo -e "${BOLD}${prompt}${NC}" >/dev/tty
        read -r value </dev/tty
        if [[ -z "$value" ]]; then
            echo -e "${RED}  ${description} cannot be empty. Please try again.${NC}" >/dev/tty
        fi
    done
    echo "$value"
}

prompt_password() {
    # Prompts for a password with confirmation, enforces basic complexity
    # Password is never written to log file
    local prompt="$1"
    local password=""
    local confirm_password=""

    while true; do
        echo -e "${BOLD}${prompt}${NC}" >/dev/tty
        echo -e "${YELLOW}  Requirements: minimum 12 characters, mix of upper, lower, number, symbol${NC}" >/dev/tty
        read -rs password </dev/tty
        echo >/dev/tty

        # Basic complexity check
        local length=${#password}
        if [[ $length -lt 12 ]]; then
            echo -e "${RED}  Password must be at least 12 characters.${NC}" >/dev/tty
            continue
        fi
        if ! echo "$password" | grep -qP '(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9])'; then
            echo -e "${RED}  Password must contain uppercase, lowercase, a number, and a symbol.${NC}" >/dev/tty
            continue
        fi

        echo -e "${BOLD}  Confirm password:${NC}" >/dev/tty
        read -rs confirm_password </dev/tty
        echo >/dev/tty

        if [[ "$password" != "$confirm_password" ]]; then
            echo -e "${RED}  Passwords do not match. Please try again.${NC}" >/dev/tty
            continue
        fi

        break
    done
    echo "$password"
}

check_command() {
    # Verifies a command exists, dies if not
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."
}

prompt_with_default() {
    # Shows current value from vars file and offers to keep or override it.
    # If vars value is blank, always prompts (no default to show).
    # Usage: VALUE=$(prompt_with_default "Label" "current_value" "description")
    # Returns the final value — either kept from vars or entered at runtime.
    local label="$1"
    local current="$2"
    local description="$3"
    local value=""

    if [[ -n "$current" ]]; then
        echo -e "${BOLD}${label}${NC}" >/dev/tty
        echo -e "${YELLOW}  Current value from vars file: ${GREEN}${current}${NC}" >/dev/tty
        echo -e "${YELLOW}  Press Enter to keep, or type a new value to override:${NC}" >/dev/tty
        read -r value </dev/tty
        if [[ -z "$value" ]]; then
            value="$current"
        fi
    else
        # Blank in vars file — always prompt
        value=$(prompt_required "${label}: " "$description")
    fi
    echo "$value"
}

validate_ip() {
    # Returns 0 (true) if argument is a valid IPv4 address, 1 (false) otherwise
    local ip="$1"
    if echo "$ip" | grep -qP \
        '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'; then
        return 0
    fi
    return 1
}

validate_prefix() {
    # Returns 0 if argument is a valid CIDR prefix length (1-32)
    local prefix="$1"
    if echo "$prefix" | grep -qP '^([1-9]|[1-2][0-9]|3[0-2])$'; then
        return 0
    fi
    return 1
}

phase_banner() {
    # Prints a clear visual separator between phases
    local phase_num="$1"
    local phase_name="$2"
    echo ""
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    echo -e "${BOLD}${BLUE}  PHASE ${phase_num}: ${phase_name}${NC}"
    echo -e "${BOLD}${BLUE}============================================================${NC}"
    log PHASE "Starting Phase ${phase_num}: ${phase_name}"
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

VARS_FILE="$DEFAULT_VARS_FILE"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vars)
            VARS_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: sudo bash bootstrap.sh [--vars /path/to/vars/file]"
            echo ""
            echo "Options:"
            echo "  --vars FILE    Path to variable file (default: bootstrap.vars in script directory)"
            echo "  --help         Show this help"
            exit 0
            ;;
        *)
            die "Unknown argument: $1. Run with --help for usage."
            ;;
    esac
done

# =============================================================================
# PHASE 1 — PREFLIGHT
# =============================================================================

phase_banner "1" "PREFLIGHT CHECKS"

# --- Must run as root ---
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Use: sudo bash bootstrap.sh"
fi

# --- Load variable file ---
if [[ ! -f "$VARS_FILE" ]]; then
    die "Variable file not found: ${VARS_FILE}
  Create one by copying bootstrap.vars and editing for your environment.
  Example: cp bootstrap.vars bootstrap.work.vars"
fi

log INFO "Loading variables from: ${VARS_FILE}"
# shellcheck source=/dev/null
source "$VARS_FILE"
log OK "Variables loaded"

# --- Validate OS ---
if [[ ! -f /etc/os-release ]]; then
    die "Cannot determine OS. /etc/os-release not found."
fi
source /etc/os-release
if [[ "$NAME" != "$REQUIRED_OS" ]]; then
    die "This script requires ${REQUIRED_OS}. Found: ${NAME}"
fi
if [[ "$VERSION_ID" != "$REQUIRED_VERSION" ]]; then
    die "This script requires Ubuntu ${REQUIRED_VERSION}. Found: ${VERSION_ID}"
fi
log OK "OS verified: Ubuntu ${VERSION_ID}"

# --- Validate environment variable is set correctly ---
if [[ "$NETOPS_ENV" != "home" && "$NETOPS_ENV" != "work" ]]; then
    die "NETOPS_ENV in your vars file must be 'home' or 'work'. Found: ${NETOPS_ENV}"
fi
log OK "Environment type: ${NETOPS_ENV} (${NETOPS_ENV_LABEL})"

# --- Check disk space ---
AVAILABLE_GB=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
if [[ $AVAILABLE_GB -lt $MIN_DISK_GB ]]; then
    die "Insufficient disk space. Need ${MIN_DISK_GB}GB free, found ${AVAILABLE_GB}GB."
fi
log OK "Disk space: ${AVAILABLE_GB}GB available"

# --- Check RAM ---
AVAILABLE_RAM_MB=$(free -m | awk 'NR==2 {print $2}')
if [[ $AVAILABLE_RAM_MB -lt $MIN_RAM_MB ]]; then
    log WARN "Low RAM detected: ${AVAILABLE_RAM_MB}MB. Minimum recommended: ${MIN_RAM_MB}MB."
    log WARN "Raspberry Pi 3 with 1GB RAM will be tight. Consider limiting running containers."
fi

# --- Check internet connectivity ---
log INFO "Checking internet connectivity..."
if ! curl -s --max-time 10 https://archive.ubuntu.com > /dev/null 2>&1; then
    die "Cannot reach Ubuntu package servers. Check network connectivity before proceeding."
fi
log OK "Internet connectivity confirmed"

# --- Create log directory early so subsequent phases can write to it ---
mkdir -p "$(dirname "$NETOPS_LOG_FILE")"
touch "$NETOPS_LOG_FILE"
chmod 640 "$NETOPS_LOG_FILE"
log OK "Log file initialized: ${NETOPS_LOG_FILE}"

# =============================================================================
# RUNTIME PROMPTS
# =============================================================================
# All input is collected here, upfront, so the rest of the script runs
# unattended. Values pre-filled in the vars file are shown as defaults —
# press Enter to accept or type a new value to override.
# Fields left blank in the vars file are always prompted.

echo ""
echo -e "${BOLD}${BLUE}============================================================${NC}"
echo -e "${BOLD}${BLUE}  RUNTIME CONFIGURATION${NC}"
echo -e "${BOLD}${BLUE}  Environment: ${NETOPS_ENV_LABEL}${NC}"
echo -e "${BOLD}${BLUE}============================================================${NC}"
echo ""
echo -e "${YELLOW}Values pre-filled from ${VARS_FILE} are shown as defaults."
echo -e "Press Enter to accept a default, or type a new value to override.${NC}"
echo ""

# --- Hostname (always prompted — unique per host, no useful default) ---
echo -e "${BOLD}Enter the hostname for this machine.${NC}"
echo -e "${YELLOW}  Convention: use lowercase with hyphens. Examples: netops-home-01, netops-prod-01${NC}"
RUNTIME_HOSTNAME=$(prompt_required "Hostname: " "Hostname")
if ! echo "$RUNTIME_HOSTNAME" | grep -qP '^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$'; then
    die "Invalid hostname '${RUNTIME_HOSTNAME}'. Use lowercase letters, numbers, and hyphens only. Cannot start or end with a hyphen."
fi

# --- Admin username (always prompted — unique per deployment) ---
echo ""
echo -e "${BOLD}Enter the admin username to create on this host.${NC}"
echo -e "${YELLOW}  This user will be added to '${NETOPS_ADMIN_GROUP}' and granted sudo access.${NC}"
RUNTIME_ADMIN_USER=$(prompt_required "Admin username: " "Admin username")
if ! echo "$RUNTIME_ADMIN_USER" | grep -qP '^[a-z_][a-z0-9_\-]{0,31}$'; then
    die "Invalid username '${RUNTIME_ADMIN_USER}'. Use lowercase letters, numbers, underscores, hyphens."
fi

# --- Admin password (always prompted — never stored in vars file) ---
echo ""
echo -e "${BOLD}Set the password for ${RUNTIME_ADMIN_USER}.${NC}"
echo -e "${YELLOW}  IMPORTANT: Store this in your password manager immediately."
echo -e "  This is your SSH login credential until TACACS+ integration is complete.${NC}"
RUNTIME_ADMIN_PASSWORD=$(prompt_password "Admin password: ")

# --- Network mode ---
echo ""
echo -e "${BOLD}${BLUE}--- Network Configuration ---${NC}"
echo ""

# Detect available network interfaces for reference
AVAILABLE_IFACES=$(ip link show | awk -F': ' '/^[0-9]+: / && !/lo/ {print "  " $2}')
echo -e "${YELLOW}Available network interfaces on this system:${NC}"
echo -e "$AVAILABLE_IFACES"
echo ""

# Mode: DHCP or static
while true; do
    echo -e "${BOLD}Network mode [dhcp/static]:${NC}" >/dev/tty
    if [[ -n "${NETOPS_NET_MODE:-}" ]]; then
        echo -e "${YELLOW}  Current value from vars file: ${GREEN}${NETOPS_NET_MODE}${NC}" >/dev/tty
        echo -e "${YELLOW}  Press Enter to keep, or type dhcp or static to override:${NC}" >/dev/tty
    fi
    read -r _net_mode_input </dev/tty
    RUNTIME_NET_MODE="${_net_mode_input:-${NETOPS_NET_MODE:-}}"
    if [[ "$RUNTIME_NET_MODE" == "dhcp" || "$RUNTIME_NET_MODE" == "static" ]]; then
        break
    fi
    echo -e "${RED}  Must be 'dhcp' or 'static'. Please try again.${NC}" >/dev/tty
done

# Interface name — auto-detect or override
echo ""
_detected_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
_iface_default="${NETOPS_NET_INTERFACE:-${_detected_iface}}"
echo -e "${BOLD}Network interface name:${NC}" >/dev/tty
echo -e "${YELLOW}  Auto-detected primary interface: ${GREEN}${_detected_iface}${NC}" >/dev/tty
if [[ -n "${NETOPS_NET_INTERFACE:-}" ]]; then
    echo -e "${YELLOW}  Vars file value: ${GREEN}${NETOPS_NET_INTERFACE}${NC}" >/dev/tty
fi
echo -e "${YELLOW}  Press Enter to use '${_iface_default}', or type a different interface name:${NC}" >/dev/tty
read -r _iface_input </dev/tty
RUNTIME_NET_INTERFACE="${_iface_input:-${_iface_default}}"
if [[ -z "$RUNTIME_NET_INTERFACE" ]]; then
    die "Could not determine network interface. Specify NETOPS_NET_INTERFACE in your vars file."
fi

# Validate the interface actually exists
if ! ip link show "$RUNTIME_NET_INTERFACE" > /dev/null 2>&1; then
    die "Interface '${RUNTIME_NET_INTERFACE}' not found on this system. Check 'ip link show' output."
fi

# Static IP fields — only collected if mode is static
RUNTIME_NET_IP=""
RUNTIME_NET_PREFIX=""
RUNTIME_NET_GATEWAY=""
RUNTIME_NET_DNS_PRIMARY=""
RUNTIME_NET_DNS_SECONDARY=""
RUNTIME_NET_DNS_SEARCH=""

if [[ "$RUNTIME_NET_MODE" == "static" ]]; then
    echo ""
    echo -e "${YELLOW}Static IP configuration — enter values for ${RUNTIME_NET_INTERFACE}${NC}"
    echo ""

    # IP address
    while true; do
        RUNTIME_NET_IP=$(prompt_with_default "IP address (e.g. 192.168.1.50)" "${NETOPS_NET_IP:-}" "IP address")
        if validate_ip "$RUNTIME_NET_IP"; then break; fi
        echo -e "${RED}  '${RUNTIME_NET_IP}' is not a valid IPv4 address. Please try again.${NC}" >/dev/tty
        NETOPS_NET_IP=""  # Force re-prompt on retry
    done

    # Subnet prefix
    while true; do
        RUNTIME_NET_PREFIX=$(prompt_with_default \
            "Subnet prefix length (e.g. 24 for /24 = 255.255.255.0)" \
            "${NETOPS_NET_PREFIX:-}" "Subnet prefix length")
        if validate_prefix "$RUNTIME_NET_PREFIX"; then break; fi
        echo -e "${RED}  '${RUNTIME_NET_PREFIX}' is not valid. Enter a number between 1 and 32.${NC}" >/dev/tty
        NETOPS_NET_PREFIX=""
    done

    # Gateway
    while true; do
        RUNTIME_NET_GATEWAY=$(prompt_with_default \
            "Default gateway (e.g. 192.168.1.1)" \
            "${NETOPS_NET_GATEWAY:-}" "Default gateway")
        if validate_ip "$RUNTIME_NET_GATEWAY"; then break; fi
        echo -e "${RED}  '${RUNTIME_NET_GATEWAY}' is not a valid IPv4 address.${NC}" >/dev/tty
        NETOPS_NET_GATEWAY=""
    done
fi

# DNS — collected for both DHCP and static
# (DHCP still benefits from explicit DNS to override what the DHCP server provides)
echo ""
echo -e "${YELLOW}DNS configuration — applies regardless of DHCP or static mode.${NC}"
echo -e "${YELLOW}For DHCP: these override whatever the DHCP server assigns.${NC}"
echo ""

while true; do
    RUNTIME_NET_DNS_PRIMARY=$(prompt_with_default \
        "Primary DNS server (e.g. 192.168.1.1 or 1.1.1.1)" \
        "${NETOPS_NET_DNS_PRIMARY:-}" "Primary DNS server")
    if validate_ip "$RUNTIME_NET_DNS_PRIMARY"; then break; fi
    echo -e "${RED}  '${RUNTIME_NET_DNS_PRIMARY}' is not a valid IPv4 address.${NC}" >/dev/tty
    NETOPS_NET_DNS_PRIMARY=""
done

while true; do
    RUNTIME_NET_DNS_SECONDARY=$(prompt_with_default \
        "Secondary DNS server (e.g. 8.8.8.8, or same as primary if only one exists)" \
        "${NETOPS_NET_DNS_SECONDARY:-}" "Secondary DNS server")
    if validate_ip "$RUNTIME_NET_DNS_SECONDARY"; then break; fi
    echo -e "${RED}  '${RUNTIME_NET_DNS_SECONDARY}' is not a valid IPv4 address.${NC}" >/dev/tty
    NETOPS_NET_DNS_SECONDARY=""
done

echo ""
echo -e "${BOLD}DNS search domain (optional — press Enter to skip)${NC}" >/dev/tty
echo -e "${YELLOW}  Appended to short hostnames. Example: corp.example.com${NC}" >/dev/tty
echo -e "${YELLOW}  Multiple domains space-separated. Leave blank if not used.${NC}" >/dev/tty
if [[ -n "${NETOPS_NET_DNS_SEARCH:-}" ]]; then
    echo -e "${YELLOW}  Current value from vars file: ${GREEN}${NETOPS_NET_DNS_SEARCH}${NC}" >/dev/tty
    echo -e "${YELLOW}  Press Enter to keep, or type a new value:${NC}" >/dev/tty
fi
read -r _dns_search_input </dev/tty
RUNTIME_NET_DNS_SEARCH="${_dns_search_input:-${NETOPS_NET_DNS_SEARCH:-}}"

# --- Confirmation summary ---
echo ""
echo -e "${BOLD}${BLUE}============================================================${NC}"
echo -e "${BOLD}  CONFIGURATION SUMMARY — Review before proceeding${NC}"
echo -e "${BOLD}${BLUE}============================================================${NC}"
echo -e "  Environment:    ${NETOPS_ENV_LABEL}"
echo -e "  Hostname:       ${RUNTIME_HOSTNAME}"
echo -e "  Admin user:     ${RUNTIME_ADMIN_USER} (group: ${NETOPS_ADMIN_GROUP})"
echo -e "  Timezone:       ${NETOPS_TIMEZONE}"
echo -e "  NTP:            ${NETOPS_NTP_PRIMARY}"
echo ""
echo -e "  Network mode:   ${RUNTIME_NET_MODE}"
echo -e "  Interface:      ${RUNTIME_NET_INTERFACE}"
if [[ "$RUNTIME_NET_MODE" == "static" ]]; then
echo -e "  IP address:     ${RUNTIME_NET_IP}/${RUNTIME_NET_PREFIX}"
echo -e "  Gateway:        ${RUNTIME_NET_GATEWAY}"
fi
echo -e "  DNS primary:    ${RUNTIME_NET_DNS_PRIMARY}"
echo -e "  DNS secondary:  ${RUNTIME_NET_DNS_SECONDARY}"
echo -e "  DNS search:     ${RUNTIME_NET_DNS_SEARCH:-"(none)"}"
echo ""
echo -e "  SSH port:       ${NETOPS_SSH_PORT}"
echo -e "  Firewall ports: ${NETOPS_FIREWALL_ADDITIONAL_PORTS}"
echo -e "  Git user:       ${NETOPS_GIT_USERNAME} <${NETOPS_GIT_EMAIL}>"
echo -e "  Log file:       ${NETOPS_LOG_FILE}"
echo ""

if ! confirm "Does this look correct? Proceeding will modify this system."; then
    echo "Bootstrap cancelled. No changes were made."
    exit 0
fi

log INFO "Configuration confirmed by operator. Beginning bootstrap."
log INFO "Bootstrap v${SCRIPT_VERSION} | Env: ${NETOPS_ENV_LABEL} | Host: ${RUNTIME_HOSTNAME} | Net: ${RUNTIME_NET_MODE}"

# =============================================================================
# PHASE 2 — NETWORK CONFIGURATION
# =============================================================================

phase_banner "2" "NETWORK CONFIGURATION (NETPLAN)"

# Install netplan if not already present (it is default on Ubuntu 24.04 server)
apt-get install -y -qq netplan.io >> "$NETOPS_LOG_FILE" 2>&1

NETPLAN_FILE="/etc/netplan/99-netops-bootstrap.cfg"

# Back up any existing netplan configs
if ls /etc/netplan/*.yaml /etc/netplan/*.cfg 2>/dev/null | grep -v "99-netops-bootstrap.cfg" > /dev/null 2>&1; then
    log INFO "Backing up existing netplan configuration files..."
    mkdir -p /etc/netplan/backup-pre-bootstrap
    for f in /etc/netplan/*.yaml /etc/netplan/*.cfg; do
        [[ -f "$f" ]] && cp "$f" "/etc/netplan/backup-pre-bootstrap/" && log OK "Backed up: $f"
    done
fi

# Build DNS nameservers line for netplan YAML
_dns_servers="[${RUNTIME_NET_DNS_PRIMARY}, ${RUNTIME_NET_DNS_SECONDARY}]"

# Build DNS search line — optional
if [[ -n "$RUNTIME_NET_DNS_SEARCH" ]]; then
    # Convert space-separated domains to YAML list format
    _dns_search_yaml=$(echo "$RUNTIME_NET_DNS_SEARCH" | \
        tr ' ' '\n' | \
        awk '{print "          - " $0}' | \
        tr '\n' '\n')
    _dns_search_block="        search:
${_dns_search_yaml}"
else
    _dns_search_block=""
fi

if [[ "$RUNTIME_NET_MODE" == "dhcp" ]]; then
    log INFO "Writing Netplan config: DHCP on ${RUNTIME_NET_INTERFACE}"
    cat > "$NETPLAN_FILE" << EOF
# =============================================================================
# Netplan Network Configuration — Generated by NetOps Bootstrap
# Mode: DHCP
# Interface: ${RUNTIME_NET_INTERFACE}
# Generated: $(date)
# To modify: edit this file and run 'sudo netplan apply'
# =============================================================================
network:
  version: 2
  renderer: networkd
  ethernets:
    ${RUNTIME_NET_INTERFACE}:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
      nameservers:
        addresses: ${_dns_servers}
EOF
    # Append search domains if provided
    if [[ -n "$RUNTIME_NET_DNS_SEARCH" ]]; then
        cat >> "$NETPLAN_FILE" << EOF
${_dns_search_block}
EOF
    fi

else
    log INFO "Writing Netplan config: Static ${RUNTIME_NET_IP}/${RUNTIME_NET_PREFIX} on ${RUNTIME_NET_INTERFACE}"
    cat > "$NETPLAN_FILE" << EOF
# =============================================================================
# Netplan Network Configuration — Generated by NetOps Bootstrap
# Mode: Static
# Interface: ${RUNTIME_NET_INTERFACE}
# Generated: $(date)
# To modify: edit this file and run 'sudo netplan apply'
# =============================================================================
network:
  version: 2
  renderer: networkd
  ethernets:
    ${RUNTIME_NET_INTERFACE}:
      dhcp4: false
      addresses:
        - ${RUNTIME_NET_IP}/${RUNTIME_NET_PREFIX}
      routes:
        - to: default
          via: ${RUNTIME_NET_GATEWAY}
      nameservers:
        addresses: ${_dns_servers}
EOF
    if [[ -n "$RUNTIME_NET_DNS_SEARCH" ]]; then
        cat >> "$NETPLAN_FILE" << EOF
${_dns_search_block}
EOF
    fi
fi

# Secure the netplan file — world-readable netplan files are a CIS finding
chmod 600 "$NETPLAN_FILE"
log OK "Netplan config written: ${NETPLAN_FILE}"

# Validate config before applying
log INFO "Validating Netplan configuration..."
if ! netplan generate >> "$NETOPS_LOG_FILE" 2>&1; then
    die "Netplan configuration validation failed. Check log file and ${NETPLAN_FILE}."
fi
log OK "Netplan configuration validated"

# Apply — this will briefly drop and reconnect the network interface
log INFO "Applying network configuration (brief connectivity interruption expected)..."
netplan apply >> "$NETOPS_LOG_FILE" 2>&1
sleep 3  # Allow interface to come back up

# Verify connectivity after apply
log INFO "Verifying network connectivity post-apply..."
if ! curl -s --max-time 15 https://archive.ubuntu.com > /dev/null 2>&1; then
    log WARN "Cannot reach archive.ubuntu.com after netplan apply."
    log WARN "This may be a brief delay. Waiting 10 seconds and retrying..."
    sleep 10
    if ! curl -s --max-time 15 https://archive.ubuntu.com > /dev/null 2>&1; then
        die "Network connectivity lost after applying Netplan config.
  Review ${NETPLAN_FILE} and check your network settings.
  To restore: cp /etc/netplan/backup-pre-bootstrap/*.yaml /etc/netplan/ && netplan apply"
    fi
fi
log OK "Network connectivity confirmed after configuration applied"

# Log final interface state for the record
log INFO "Final interface state:"
ip addr show "$RUNTIME_NET_INTERFACE" >> "$NETOPS_LOG_FILE" 2>&1
ip route show >> "$NETOPS_LOG_FILE" 2>&1

# =============================================================================
# PHASE 3 — OS BASELINE
# =============================================================================

phase_banner "3" "OS BASELINE"

# --- Hostname ---
log INFO "Setting hostname to: ${RUNTIME_HOSTNAME}"
hostnamectl set-hostname "$RUNTIME_HOSTNAME"
# Update /etc/hosts to reflect new hostname (prevents sudo warnings)
if ! grep -q "$RUNTIME_HOSTNAME" /etc/hosts; then
    echo "127.0.1.1  ${RUNTIME_HOSTNAME}" >> /etc/hosts
fi
log OK "Hostname set: ${RUNTIME_HOSTNAME}"

# --- Timezone ---
log INFO "Setting timezone to: ${NETOPS_TIMEZONE}"
timedatectl set-timezone "$NETOPS_TIMEZONE" || die "Invalid timezone: ${NETOPS_TIMEZONE}. Check tz database name."
log OK "Timezone set: ${NETOPS_TIMEZONE}"

# --- NTP ---
log INFO "Configuring NTP: ${NETOPS_NTP_PRIMARY}"
# Ubuntu 24.04 uses systemd-timesyncd by default — CIS IG1 compliant choice
cat > /etc/systemd/timesyncd.conf << EOF
[Time]
NTP=${NETOPS_NTP_PRIMARY} ${NETOPS_NTP_SECONDARY}
FallbackNTP=pool.ntp.org
EOF
systemctl restart systemd-timesyncd
systemctl enable systemd-timesyncd
log OK "NTP configured and enabled"

# --- System update ---
log INFO "Running system updates (this may take several minutes)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >> "$NETOPS_LOG_FILE" 2>&1 || die "apt-get update failed. Check network and log file."
apt-get upgrade -y -qq >> "$NETOPS_LOG_FILE" 2>&1 || die "apt-get upgrade failed. Check log file."
log OK "System packages updated"

# --- Install required base packages ---
log INFO "Installing required base packages..."
apt-get install -y -qq \
    curl \
    wget \
    git \
    unzip \
    vim \
    htop \
    net-tools \
    tcpdump \
    auditd \
    audispd-plugins \
    rsyslog \
    logrotate \
    aide \
    fail2ban \
    >> "$NETOPS_LOG_FILE" 2>&1 || die "Base package installation failed. Check log file."
log OK "Base packages installed"

# --- Configure audit logging (CIS IG1 requirement) ---
log INFO "Configuring auditd..."
systemctl enable auditd >> "$NETOPS_LOG_FILE" 2>&1
systemctl start auditd >> "$NETOPS_LOG_FILE" 2>&1
log OK "auditd enabled and started"

# --- Configure log rotation ---
cat > /etc/logrotate.d/netops << EOF
${NETOPS_LOG_FILE} {
    daily
    rotate ${NETOPS_LOG_RETENTION_DAYS}
    compress
    missingok
    notifempty
    create 640 root adm
}
EOF
log OK "Log rotation configured (${NETOPS_LOG_RETENTION_DAYS} day retention)"

# --- Disable unused filesystems (CIS IG1) ---
log INFO "Disabling unused filesystem types per CIS IG1..."
cat > /etc/modprobe.d/netops-cis.conf << EOF
# CIS IG1 — Disable uncommon filesystem types
# These are not needed on a server and represent unnecessary attack surface.
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF
log OK "Unused filesystems disabled"

# =============================================================================
# PHASE 4 — ADMIN USER AND GROUP
# =============================================================================

phase_banner "4" "ADMIN USER AND GROUP"

# --- Create admin group ---
if ! getent group "$NETOPS_ADMIN_GROUP" > /dev/null 2>&1; then
    groupadd "$NETOPS_ADMIN_GROUP"
    log OK "Created group: ${NETOPS_ADMIN_GROUP}"
else
    log INFO "Group already exists: ${NETOPS_ADMIN_GROUP}"
fi

# --- Create admin user ---
if ! id "$RUNTIME_ADMIN_USER" > /dev/null 2>&1; then
    useradd \
        --create-home \
        --shell /bin/bash \
        --groups "$NETOPS_ADMIN_GROUP" \
        --comment "NetOps Admin" \
        "$RUNTIME_ADMIN_USER"
    log OK "Created user: ${RUNTIME_ADMIN_USER}"
else
    log INFO "User already exists: ${RUNTIME_ADMIN_USER} — updating group membership"
    usermod -aG "$NETOPS_ADMIN_GROUP" "$RUNTIME_ADMIN_USER"
fi

# --- Set password ---
echo "${RUNTIME_ADMIN_USER}:${RUNTIME_ADMIN_PASSWORD}" | chpasswd
# Clear password variable from memory immediately after use
RUNTIME_ADMIN_PASSWORD=""
unset RUNTIME_ADMIN_PASSWORD
log OK "Password set for: ${RUNTIME_ADMIN_USER} (cleared from memory)"

# --- Configure sudo access for admin group ---
cat > /etc/sudoers.d/netops-admin << EOF
# NetOps admin group — full sudo with password required
# CIS IG1: sudo requires authentication (no NOPASSWD)
%${NETOPS_ADMIN_GROUP} ALL=(ALL:ALL) ALL
EOF
chmod 440 /etc/sudoers.d/netops-admin
# Validate sudoers file before continuing — a bad sudoers file can lock you out
visudo -c -f /etc/sudoers.d/netops-admin >> "$NETOPS_LOG_FILE" 2>&1 || \
    die "sudoers file validation failed. This is a critical error — do not proceed."
log OK "sudo configured for group: ${NETOPS_ADMIN_GROUP}"

# --- Password policy (CIS IG1) ---
log INFO "Configuring password policy..."
# Install libpam-pwquality for password complexity enforcement
apt-get install -y -qq libpam-pwquality >> "$NETOPS_LOG_FILE" 2>&1

# Set password aging in /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Set password complexity via pwquality
cat > /etc/security/pwquality.conf << EOF
# CIS IG1 password complexity requirements
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
EOF
log OK "Password policy configured"

# =============================================================================
# PHASE 5 — SSH HARDENING
# =============================================================================

phase_banner "5" "SSH HARDENING"
# NOTE: Exception EX-001 applies here — see script header for justification.
# Password authentication is intentionally left enabled.

log INFO "Backing up original SSH config..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-bootstrap

log INFO "Applying CIS-aligned SSH configuration..."
cat > /etc/ssh/sshd_config << EOF
# =============================================================================
# SSH Server Configuration — NetOps Bootstrap
# CIS Ubuntu 24.04 Level 1 aligned
# Exception EX-001: PasswordAuthentication enabled (see bootstrap exception register)
# =============================================================================

# Network
Port ${NETOPS_SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes

# Exception EX-001: PasswordAuthentication yes
# Justification: No SSH key management infrastructure. TACACS+ planned.
# Compensating controls applied below.

# Access restriction — only members of admin group may SSH in
AllowGroups ${NETOPS_ADMIN_GROUP}

# Brute force protection
MaxAuthTries ${NETOPS_SSH_MAX_AUTH_TRIES}
MaxSessions 4
LoginGraceTime ${NETOPS_SSH_LOGIN_GRACE_TIME}

# Session hardening
ClientAliveInterval 300
ClientAliveCountMax 1
TCPKeepAlive no

# Idle timeout (CIS IG1)
# ClientAliveInterval * ClientAliveCountMax = ${NETOPS_SSH_IDLE_TIMEOUT}s max idle

# Disable insecure features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no

# Use strong ciphers and MACs only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256

# Logging (CIS IG1)
LogLevel VERBOSE
SyslogFacility AUTH

# Banner
Banner /etc/issue.net
EOF

# --- Legal banner (CIS IG1 requirement) ---
cat > /etc/issue.net << EOF
*******************************************************************************
  AUTHORIZED ACCESS ONLY

  This system is for authorized personnel only. All activity is monitored
  and logged. Unauthorized access is prohibited and may result in
  disciplinary action and/or criminal prosecution.

  By continuing, you consent to monitoring and acknowledge that you have
  no expectation of privacy on this system.
*******************************************************************************
EOF

# Validate SSH config before restarting
sshd -t >> "$NETOPS_LOG_FILE" 2>&1 || die "SSH configuration validation failed. Check log file."
systemctl restart sshd
log OK "SSH hardened and restarted"

# --- Configure fail2ban for SSH brute force protection ---
log INFO "Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/netops-ssh.conf << EOF
[sshd]
enabled = true
port = ${NETOPS_SSH_PORT}
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl enable fail2ban >> "$NETOPS_LOG_FILE" 2>&1
systemctl restart fail2ban >> "$NETOPS_LOG_FILE" 2>&1
log OK "fail2ban configured for SSH protection"

# =============================================================================
# PHASE 6 — FIREWALL (UFW)
# =============================================================================

phase_banner "6" "FIREWALL (UFW)"

log INFO "Configuring UFW firewall..."
apt-get install -y -qq ufw >> "$NETOPS_LOG_FILE" 2>&1

# Reset to clean state
ufw --force reset >> "$NETOPS_LOG_FILE" 2>&1

# Default policy — deny all inbound, allow all outbound
ufw default deny incoming >> "$NETOPS_LOG_FILE" 2>&1
ufw default allow outgoing >> "$NETOPS_LOG_FILE" 2>&1

# Allow SSH (critical — must be done before enabling UFW)
ufw allow "${NETOPS_SSH_PORT}/tcp" comment "SSH" >> "$NETOPS_LOG_FILE" 2>&1
log OK "SSH port ${NETOPS_SSH_PORT} allowed through firewall"

# Allow additional ports from vars file
for port in $NETOPS_FIREWALL_ADDITIONAL_PORTS; do
    ufw allow "$port" comment "NetOps service" >> "$NETOPS_LOG_FILE" 2>&1
    log OK "Port ${port} allowed through firewall"
done

# Enable UFW
ufw --force enable >> "$NETOPS_LOG_FILE" 2>&1
systemctl enable ufw >> "$NETOPS_LOG_FILE" 2>&1
log OK "UFW enabled with default-deny policy"

# =============================================================================
# PHASE 7 — DOCKER INSTALLATION
# =============================================================================

phase_banner "7" "DOCKER INSTALLATION"
# NOTE: Exception EX-002 — Docker networking requires the following kernel
# parameters that CIS IG1 may flag:
#   net.ipv4.ip_forward = 1  (required for container networking)
#   net.bridge.bridge-nf-call-iptables = 1  (required for UFW/iptables integration)
# These are documented exceptions, not oversights.

log INFO "Installing Docker using official method..."

# Remove any old/unofficial Docker packages
apt-get remove -y -qq docker docker-engine docker.io containerd runc >> "$NETOPS_LOG_FILE" 2>&1 || true

# Install prerequisites
apt-get install -y -qq \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    >> "$NETOPS_LOG_FILE" 2>&1

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -qq >> "$NETOPS_LOG_FILE" 2>&1
apt-get install -y -qq \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin \
    >> "$NETOPS_LOG_FILE" 2>&1 || die "Docker installation failed. Check log file."

# --- Docker daemon security configuration ---
log INFO "Configuring Docker daemon..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << EOF
{
  "log-driver": "${NETOPS_DOCKER_LOG_DRIVER}",
  "log-opts": {
    "max-size": "${NETOPS_DOCKER_LOG_MAX_SIZE}",
    "max-file": "${NETOPS_DOCKER_LOG_MAX_FILE}"
  },
  "data-root": "${NETOPS_DOCKER_DATA_DIR}",
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false
}
EOF
# icc: false          — disable inter-container communication by default (CIS Docker)
# no-new-privileges   — prevent containers gaining additional privileges
# live-restore        — keep containers running if Docker daemon restarts
# userland-proxy      — disable for slight security improvement

# Add admin user to docker group so they can run docker without sudo
usermod -aG docker "$RUNTIME_ADMIN_USER"
log OK "Admin user ${RUNTIME_ADMIN_USER} added to docker group"

# Enable and start Docker
systemctl enable docker >> "$NETOPS_LOG_FILE" 2>&1
systemctl start docker >> "$NETOPS_LOG_FILE" 2>&1

# Verify Docker is working
if docker run --rm hello-world >> "$NETOPS_LOG_FILE" 2>&1; then
    log OK "Docker installed and verified working"
else
    die "Docker installed but test container failed. Check log file."
fi

# =============================================================================
# PHASE 8 — GIT CONFIGURATION AND REPO CLONE
# =============================================================================

phase_banner "8" "GIT CONFIGURATION"

ADMIN_HOME="/home/${RUNTIME_ADMIN_USER}"
NETOPS_REPO_DIR="${ADMIN_HOME}/netops"

# Configure git for the admin user
sudo -u "$RUNTIME_ADMIN_USER" git config --global user.name "$NETOPS_GIT_USERNAME"
sudo -u "$RUNTIME_ADMIN_USER" git config --global user.email "$NETOPS_GIT_EMAIL"
sudo -u "$RUNTIME_ADMIN_USER" git config --global init.defaultBranch "main"
sudo -u "$RUNTIME_ADMIN_USER" git config --global pull.rebase false
log OK "Git configured for user: ${RUNTIME_ADMIN_USER}"

# Create repo directory
mkdir -p "$NETOPS_REPO_DIR"
chown "${RUNTIME_ADMIN_USER}:${NETOPS_ADMIN_GROUP}" "$NETOPS_REPO_DIR"

# Clone repositories
log INFO "Cloning repositories from: ${NETOPS_GIT_REMOTE_BASE}"
for repo in $NETOPS_GIT_REPOS; do
    REPO_URL="${NETOPS_GIT_REMOTE_BASE}/${repo}.git"
    REPO_PATH="${NETOPS_REPO_DIR}/${repo}"

    if [[ -d "$REPO_PATH" ]]; then
        log INFO "Repository already exists, skipping clone: ${repo}"
        continue
    fi

    log INFO "Cloning: ${repo}"
    if sudo -u "$RUNTIME_ADMIN_USER" git clone "$REPO_URL" "$REPO_PATH" >> "$NETOPS_LOG_FILE" 2>&1; then
        log OK "Cloned: ${repo}"
    else
        log WARN "Could not clone ${repo} from ${REPO_URL} — repository may not exist yet. Skipping."
    fi
done

# =============================================================================
# PHASE 9 — GOSS INSTALLATION AND FIRST COMPLIANCE SCAN
# =============================================================================

phase_banner "9" "GOSS AND COMPLIANCE SCAN"

# --- Install GOSS ---
log INFO "Installing GOSS v${NETOPS_GOSS_VERSION}..."
GOSS_URL="https://github.com/goss-org/goss/releases/download/v${NETOPS_GOSS_VERSION}/goss-linux-amd64"

# Raspberry Pi uses ARM — detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "armv7l" ]]; then
    GOSS_URL="https://github.com/goss-org/goss/releases/download/v${NETOPS_GOSS_VERSION}/goss-linux-arm"
    log INFO "ARM architecture detected (Raspberry Pi) — using ARM GOSS binary"
fi

curl -fsSL "$GOSS_URL" -o /usr/local/bin/goss >> "$NETOPS_LOG_FILE" 2>&1 || \
    die "GOSS download failed. Check network and GOSS version in vars file."
chmod +x /usr/local/bin/goss
log OK "GOSS installed: $(goss --version)"

# --- Create GOSS test directory ---
mkdir -p "$NETOPS_GOSS_TEST_DIR"
mkdir -p "$NETOPS_GOSS_REPORT_DIR"

# --- Write baseline GOSS test file ---
log INFO "Writing GOSS baseline tests..."
cat > "${NETOPS_GOSS_TEST_DIR}/cis-ig1-baseline.yaml" << 'GOSSEOF'
# =============================================================================
# GOSS CIS IG1 Baseline Tests — Ubuntu 24.04 LTS
# =============================================================================
# This file validates that bootstrap hardening was applied correctly.
# Add tests here as your compliance requirements grow.
# Run manually: sudo goss -g /opt/goss/cis-ig1-baseline.yaml validate
# =============================================================================

# --- Services that must be running ---
service:
  sshd:
    enabled: true
    running: true
  ufw:
    enabled: true
    running: true
  auditd:
    enabled: true
    running: true
  fail2ban:
    enabled: true
    running: true
  docker:
    enabled: true
    running: true
  systemd-timesyncd:
    enabled: true
    running: true

# --- Services that must NOT be running (CIS IG1) ---
  telnet:
    enabled: false
    running: false
  rsh:
    enabled: false
    running: false
  vsftpd:
    enabled: false
    running: false
  avahi-daemon:
    enabled: false
    running: false

# --- SSH configuration checks ---
file:
  /etc/ssh/sshd_config:
    exists: true
    mode: "0600"
    contains:
      - "PermitRootLogin no"
      - "PermitEmptyPasswords no"
      - "X11Forwarding no"
      - "MaxAuthTries"
      - "AllowGroups"
      - "LoginGraceTime"

  /etc/issue.net:
    exists: true
    contains:
      - "AUTHORIZED ACCESS ONLY"

  /etc/sudoers.d/netops-admin:
    exists: true
    mode: "0440"

  /etc/docker/daemon.json:
    exists: true
    contains:
      - "no-new-privileges"

  # Netplan config — permissions are a CIS finding if world-readable
  /etc/netplan/99-netops-bootstrap.cfg:
    exists: true
    mode: "0600"

# --- Password policy ---
  /etc/security/pwquality.conf:
    exists: true
    contains:
      - "minlen = 12"

# --- Unused filesystem modules disabled ---
  /etc/modprobe.d/netops-cis.conf:
    exists: true
    contains:
      - "install cramfs /bin/true"
      - "install usb-storage /bin/true"

# --- Kernel parameters (CIS IG1) ---
kernel-param:
  net.ipv4.tcp_syncookies:
    value: "1"
  net.ipv4.conf.all.accept_redirects:
    value: "0"
  net.ipv4.conf.default.accept_redirects:
    value: "0"
  net.ipv4.conf.all.send_redirects:
    value: "0"
  net.ipv4.conf.all.accept_source_route:
    value: "0"
  net.ipv6.conf.all.accept_redirects:
    value: "0"
  kernel.randomize_va_space:
    value: "2"
GOSSEOF

log OK "GOSS test file written: ${NETOPS_GOSS_TEST_DIR}/cis-ig1-baseline.yaml"

# --- Set secure kernel parameters ---
log INFO "Applying CIS IG1 kernel parameters..."
cat > /etc/sysctl.d/99-netops-cis.conf << EOF
# CIS IG1 kernel parameters — NetOps Bootstrap
# Exception EX-002: net.ipv4.ip_forward=1 required for Docker networking

# Network hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# Docker networking requirement (EX-002)
net.ipv4.ip_forward = 1

# Memory protection
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl -p /etc/sysctl.d/99-netops-cis.conf >> "$NETOPS_LOG_FILE" 2>&1
log OK "Kernel parameters applied"

# --- Run GOSS compliance scan ---
log INFO "Running initial compliance scan..."
REPORT_TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
REPORT_FILENAME="goss-report-${NETOPS_ENV}-${REPORT_TIMESTAMP}.json"
REPORT_PATH="${NETOPS_GOSS_REPORT_DIR}/${REPORT_FILENAME}"

# Run GOSS and capture output — failure here does NOT stop the script
# This is a report, not a gate. Review results and remediate manually or via Ansible.
set +e
goss -g "${NETOPS_GOSS_TEST_DIR}/cis-ig1-baseline.yaml" validate --format json > "$REPORT_PATH" 2>&1
GOSS_EXIT_CODE=$?
set -e

# Also run human-readable output to console and log
goss -g "${NETOPS_GOSS_TEST_DIR}/cis-ig1-baseline.yaml" validate --format documentation 2>&1 | \
    tee -a "$NETOPS_LOG_FILE"

if [[ $GOSS_EXIT_CODE -eq 0 ]]; then
    log OK "Compliance scan PASSED — all tests passed"
else
    log WARN "Compliance scan completed with failures — review report: ${REPORT_PATH}"
    log WARN "This does not mean bootstrap failed. Failures may need Ansible remediation."
fi

log OK "Compliance report saved: ${REPORT_PATH}"

# =============================================================================
# BOOTSTRAP COMPLETE
# =============================================================================

echo ""
echo -e "${BOLD}${GREEN}============================================================${NC}"
echo -e "${BOLD}${GREEN}  BOOTSTRAP COMPLETE${NC}"
echo -e "${BOLD}${GREEN}============================================================${NC}"
echo ""
echo -e "  Host:            ${RUNTIME_HOSTNAME}"
echo -e "  Environment:     ${NETOPS_ENV_LABEL}"
echo -e "  Admin user:      ${RUNTIME_ADMIN_USER} (member of ${NETOPS_ADMIN_GROUP})"
echo -e "  Network:         ${RUNTIME_NET_MODE} on ${RUNTIME_NET_INTERFACE}"
if [[ "$RUNTIME_NET_MODE" == "static" ]]; then
echo -e "  IP address:      ${RUNTIME_NET_IP}/${RUNTIME_NET_PREFIX}"
fi
echo -e "  Bootstrap log:   ${NETOPS_LOG_FILE}"
echo -e "  Compliance scan: ${REPORT_PATH}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo -e "  1. Log out and log back in as ${RUNTIME_ADMIN_USER} to verify SSH access"
echo -e "  2. Review the compliance report for any failed checks"
echo -e "  3. Navigate to ~/netops/ and review your cloned repositories"
echo -e "  4. Bring up Docker services: cd ~/netops/docker-stacks && docker compose up -d"
echo -e "  5. Run Ansible hardening playbook from within the Ansible container"
echo ""
echo -e "${RED}IMPORTANT:${NC}"
echo -e "  - Verify you can SSH in as ${RUNTIME_ADMIN_USER} BEFORE closing this session"
echo -e "  - Store the admin password in your password manager if not already done"
echo -e "  - Root login is now disabled — ${RUNTIME_ADMIN_USER} with sudo is your access path"
echo ""

log INFO "Bootstrap completed successfully: ${RUNTIME_HOSTNAME} (${NETOPS_ENV_LABEL})"
