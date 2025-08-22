#!/bin/bash
# This script will set up ufw-ip-sync on your server. It will create the necessary directories, configuration files, and install the sync script.

# Ensure the script runs as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# Define paths for configuration files and the sync script
CFG_DIR="/etc/ufw-ip-sync"
STATE_DIR="/var/lib/ufw-ip-sync"
SCRIPT_PATH="/usr/local/bin/ufw-ip-sync.sh"

# Create necessary directories
mkdir -p "$CFG_DIR" "$STATE_DIR"

# Create domains configuration (list of IPs)
cat <<EOF > "$CFG_DIR/ips.conf"
# List of IPs to apply rules to
EOF

# Create dynamic rules configuration (list of ports to be applied to the IPs)
cat <<EOF > "$CFG_DIR/dynamic-rules.conf"
# Applied to every IP in ips.conf:
tcp:3306
tcp:5432
udp:1194
EOF

# Create static rules configuration (global UFW rules independent of IPs)
cat <<EOF > "$CFG_DIR/static-rules.conf"
# Examples (no leading 'ufw' — just the arguments):
allow 22/tcp
EOF

# Create the ufw-ip-sync.sh script
cat <<'EOF' > "$SCRIPT_PATH"
#!/usr/bin/env bash
# Sync UFW rules from:
#  - IPs listed in ips.conf (per-IP dynamic rules)
#  - Static rules listed in static-rules.conf (independent of IPs)

set -euo pipefail

CFG_DIR="/etc/ufw-ip-sync"
IPS_CFG="${CFG_DIR}/ips.conf"
DYNAMIC_CFG="${CFG_DIR}/dynamic-rules.conf"
STATIC_CFG="${CFG_DIR}/static-rules.conf"

STATE_DIR="/var/lib/ufw-ip-sync"
DRY_RUN=0

usage() {
  echo "Usage: $0 [--dry-run] [--config-dir PATH]"
  echo ""
  echo "Reads:"
  echo "  IPs: ${IPS_CFG}"
  echo "  dynamic rules: ${DYNAMIC_CFG}"
  echo "  static rules:  ${STATIC_CFG}"
  echo ""
  echo "Stores state in: ${STATE_DIR}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --config-dir) CFG_DIR="$2"; IPS_CFG="$CFG_DIR/ips.conf"; DYNAMIC_CFG="$CFG_DIR/dynamic-rules.conf"; STATIC_CFG="$CFG_DIR/static-rules.conf"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

mkdir -p "$STATE_DIR"

die() { echo "ERROR: $*" >&2; exit 1; }

require_file() {
  local f="$1" desc="$2"
  [[ -r "$f" ]] || die "Missing or unreadable ${desc}: $f"
}

require_file "$IPS_CFG" "ips.conf"
[[ -r "$DYNAMIC_CFG" ]] || touch "$DYNAMIC_CFG"
[[ -r "$STATIC_CFG"  ]] || touch "$STATIC_CFG"

trim() { sed -e 's/^\s*//' -e 's/\s*$//'; }

read_dynamic_rules() {
  # Output: lines "proto:port"
  grep -v '^\s*#' "$DYNAMIC_CFG" | awk 'NF' | trim
}

read_static_rules() {
  # Output: raw UFW arguments per line (no 'ufw' prefix)
  grep -v '^\s*#' "$STATIC_CFG" | awk 'NF' | trim
}

# --- Read IPs from ips.conf ---
# Parse and process ips.conf
parse_ips() {
  grep -v '^\s*#' "$IPS_CFG" | awk 'NF' | trim
}

apply_rule() {
  local action="$1"  # "" (add) or "delete"
  local rule="$2"    # full args after ufw

  # Check if the rule exists before deleting it
  if [[ "$action" == "delete" ]]; then
    if (( DRY_RUN == 1 )); then
      echo "[DRY] ufw ${action} ${rule}"
    else
      ufw ${action} ${rule}
    fi
  else
    if (( DRY_RUN == 1 )); then
      echo "[DRY] ufw ${action} ${rule}"
    else
      ufw ${action} ${rule}
    fi
  fi
}


# Function to build a dynamic UFW rule for each host
build_dynamic_rule_line() {
  local proto="$1"   # Protocol (tcp or udp)
  local port="$2"    # Port
  local ip="$3"      # IP address
  local group="$4"   # Group name (optional for tagging)
  
  # Ensure that the rule has the correct format
  if [[ -z "$proto" || -z "$port" || -z "$ip" ]]; then
    echo "[ERROR] Invalid arguments passed to build_dynamic_rule_line"
    return
  fi
  
  # Build the UFW rule in the correct format
  echo "allow from ${ip} to any port ${port} proto ${proto} comment \"sg:${group}\""
}

sync_rule_set() {
  # Args:
  #   $1 = state_file
  #   $2 = desired_tmp_file
  #   $3 = label (for logs)
  local STATE_FILE="$1" DESIRED="$2" LABEL="$3"

  local OLD TMP_ADD TMP_DEL
  OLD="$(mktemp)"; TMP_ADD="$(mktemp)"; TMP_DEL="$(mktemp)"
  trap 'rm -f "$OLD" "$TMP_ADD" "$TMP_DEL"' RETURN

  # If the state file exists, copy it, otherwise, initialize it to empty
  if [[ -f "$STATE_FILE" ]]; then
    cp "$STATE_FILE" "$OLD"
  else
    : > "$OLD"
  fi

  # Sort the desired and old rules to compare
  sort -u -o "$DESIRED" "$DESIRED"
  sort -u -o "$OLD" "$OLD"

  # Compare the current state with the desired state
  comm -13 "$OLD" "$DESIRED" > "$TMP_ADD"   # Rules present in desired, but not in the old state
  comm -23 "$OLD" "$DESIRED" > "$TMP_DEL"   # Rules present in the old state, but not in desired

  echo "[$LABEL] To add: $(wc -l < "$TMP_ADD") | To remove: $(wc -l < "$TMP_DEL")"

  # Debug: Check what rules are going to be added or deleted
  echo "[DEBUG] OLD (Current Rules):"
  cat "$OLD"
  echo "[DEBUG] DESIRED (Desired Rules):"
  cat "$DESIRED"
  echo "[DEBUG] TMP_ADD (Rules to Add):"
  cat "$TMP_ADD"
  echo "[DEBUG] TMP_DEL (Rules to Delete):"
  cat "$TMP_DEL"

  # If TMP_ADD is empty, force adding the rule (even if it exists in OLD)
  if [[ ! -s "$TMP_ADD" ]]; then
    echo "Forcing rule addition because TMP_ADD is empty"
    # Force add any rule that should be in TMP_ADD
    cat "$DESIRED" >> "$TMP_ADD"
  fi

  # Add the new rules
  if [[ -s "$TMP_ADD" ]]; then
    while IFS= read -r r; do
      echo "Adding rule: $r"
      apply_rule "" "$r"
    done < "$TMP_ADD"
  fi

  # Remove the old rules
  if [[ -s "$TMP_DEL" ]]; then
    while IFS= read -r r; do
      echo "Deleting rule: $r"
      apply_rule delete "$r"
    done < "$TMP_DEL"
  fi

  # After applying, save the current state
  if (( DRY_RUN == 0 )); then
    cp "$DESIRED" "$STATE_FILE"
  fi
}


# ---------- Build desired STATIC rules ----------
TMP_STATIC_DESIRED="$(mktemp)"
trap 'rm -f "$TMP_STATIC_DESIRED"' EXIT
> "$TMP_STATIC_DESIRED"

STATIC_TAG='sg:static'
while IFS= read -r line; do
  # If the line already includes a comment, leave it; otherwise append our tag
  if [[ "$line" =~ [[:space:]]comment[[:space:]]\".*\" ]]; then
    echo "$line" >> "$TMP_STATIC_DESIRED"
  else
    echo "$line comment \"${STATIC_TAG}\"" >> "$TMP_STATIC_DESIRED"
  fi
done < <(read_static_rules)

# ---------- Build desired DYNAMIC rules from IPs + dynamic rules ----------
TMP_DYNAMIC_DESIRED="$(mktemp)"
trap 'rm -f "$TMP_DYNAMIC_DESIRED"' EXIT
> "$TMP_DYNAMIC_DESIRED"

# Load dynamic rules
mapfile -t DYN_RULES < <(read_dynamic_rules)

if ((${#DYN_RULES[@]} == 0)); then
  echo "[dynamic] No dynamic rules configured (dynamic-rules.conf empty)."
fi

# Read IPs
mapfile -t IPS < <(parse_ips)
if ((${#IPS[@]} == 0)); then
  echo "[dynamic] No IPs defined in ips.conf"
else
  for ip in "${IPS[@]}"; do
    for rule in "${DYN_RULES[@]}"; do
      port="${rule%%/*}"
      proto="${rule##*/}"
      build_dynamic_rule_line "$proto" "$port" "$ip" "dynamic" >> "$TMP_DYNAMIC_DESIRED"
    done
  done
fi

# Dedup dynamic desired
sort -u -o "$TMP_DYNAMIC_DESIRED" "$TMP_DYNAMIC_DESIRED"

# ---------- Sync STATIC set ----------
STATIC_STATE="${STATE_DIR}/static.state"
echo "=== Syncing STATIC rules ==="
sync_rule_set "$STATIC_STATE" "$TMP_STATIC_DESIRED" "static"

# ---------- Sync DYNAMIC set ----------
DYN_STATE="${STATE_DIR}/dynamic.state"
echo "=== Syncing DYNAMIC rules ==="
sync_rule_set "$DYN_STATE" "$TMP_DYNAMIC_DESIRED" "dynamic"
echo "All done."
EOF

# Make the script executable
chmod +x "$SCRIPT_PATH"

# Dry run the script to verify
echo "Running dry run to verify..."
$SCRIPT_PATH --dry-run

# Apply the rules
echo "Applying rules..."
$SCRIPT_PATH

# Setup cron job to run every 10 minutes
crontab -l 2>/dev/null | grep -F "$SCRIPT_PATH" || echo "Setting up cron job for periodic sync..."
# Check if the cron job already exists
(crontab -l 2>/dev/null | grep -F "$SCRIPT_PATH" || echo "*/10 * * * * root $SCRIPT_PATH >/var/log/ufw-ip-sync.log 2>&1") | crontab -


echo "Setup complete!"
