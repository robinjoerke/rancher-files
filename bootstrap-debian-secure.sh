#!/usr/bin/env bash
# =============================================================================
# Debian/Ubuntu Kubernetes Node Bootstrap (worker, etcd-cp, or rancher)
# =============================================================================
# This script:
#   - Updates system packages
#   - Sets hostname and /etc/hosts
#   - Creates a 'solutiance' sudo user with authorized_keys
#   - Hardens SSH and sets sane defaults
#   - Installs vim, htop, ufw, fail2ban
#   - Configures firewall based on node ROLE (worker, etcd-cp, rancher)
#   - Installs Docker CE (official repo)
#   - (Optional) Installs open-iscsi for Longhorn on workers
#   - (Optional) Override DHCP DNS with systemd-networkd snippet (removed here)
#
# Run as root:  sudo bash ./bootstrap.sh
# Idempotent where practical. Safe to re-run.
# =============================================================================

set -euo pipefail

# ----------------------------- USER VARIABLES -------------------------------
if [[ -z "${ROLE:-}" ]]; then
  read -p "Enter the node role (worker, etcd-cp, rancher): " ROLE
fi

# Hostname to set for this node (use a unique value per machine)
if [[ -z "${NEW_HOSTNAME:-}" ]]; then
  read -p "Enter the new hostname: " NEW_HOSTNAME
fi

# Node role: "worker", "etcd-cp", or "rancher"
if [[ -z "${ROLE:-}" ]]; then
  read -p "Enter the node role (worker, etcd-cp, rancher): " ROLE
fi

# Hostname to set for this node (use a unique value per machine)
if [[ -z "${NEW_HOSTNAME:-}" ]]; then
  read -p "Enter the new hostname: " NEW_HOSTNAME
fi

# Username for the admin user
if [[ -z "${USERNAME:-}" ]]; then
  read -p "Enter the username for the new user: " USERNAME
fi

# User password for the admin user
if [[ -z "${USER_PASSWORD:-}" ]]; then
  read -s -p "Enter the password for the new user: " USER_PASSWORD
  echo
fi

# Public SSH key for the new user
if [[ -z "${USER_AUTHORIZED_KEY:-}" ]]; then
  read -p "Enter the SSH public key for the new user: " USER_AUTHORIZED_KEY
fi

FORCE_PASSWORD_CHANGE="true"        # <-- Re-added: Forces password reset after setup

# Public SSH key to seed for the user (authorized_keys)
USER_AUTHORIZED_KEY='ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAC1W7jVagEmip4iCNa0G0TdBeYUNrHeJYgXWgSqORxnDHhAAnwGO0OlrRhKlXsifDJX7nBI1oWtBzAvLe6JoiQM9wFWK+dARPWN93Yeng6z8LDSASMVXhtFGL7m2RvZa5pex9IfSb7TUn8HQQad92FKFjjPvHT5i5UZ34mwq4H6rZsRgQ== robinjoerke-ecdsa-key-20250819'

# Install open-iscsi (Longhorn requirement) automatically on workers
INSTALL_ISCSI_ON_WORKER="true"

# --------------------------- END USER VARIABLES -----------------------------

# Non-interactive apt
export DEBIAN_FRONTEND=noninteractive

# Basic sanity checks
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (e.g., sudo bash $0)"; exit 1
fi

if [[ ! "worker etcd-cp rancher" =~ "${ROLE}" ]]; then
  echo "ROLE must be 'worker', 'etcd-cp', or 'rancher'"; exit 1
fi

log() { echo -e "\n\033[1;32m==> $*\033[0m"; }

# -----------------------------------------------------------------------------
# 1) Update system packages
# -----------------------------------------------------------------------------
log "Updating packages…"
apt-get update -y
apt-get upgrade -y

# -----------------------------------------------------------------------------
# 2) Hostname & /etc/hosts   (Debian uses 127.0.1.1 for hostname by default)
# -----------------------------------------------------------------------------
log "Configuring hostname to '${NEW_HOSTNAME}'…"
hostnamectl set-hostname "${NEW_HOSTNAME}"

# Ensure 127.0.1.1 NEW_HOSTNAME in /etc/hosts (idempotent)
if grep -qE '^127\.0\.1\.1\s' /etc/hosts; then
  sed -i "s/^127\.0\.1\.1.*/127.0.1.1 ${NEW_HOSTNAME}/" /etc/hosts
else
  echo "127.0.1.1 ${NEW_HOSTNAME}" >> /etc/hosts
fi
# Keep loopback too (don’t clobber existing entries)
if ! grep -qE '^127\.0\.0\.1\s' /etc/hosts; then
  echo "127.0.0.1 localhost" >> /etc/hosts
fi

# -----------------------------------------------------------------------------
# 3) Create sudo user and SSH authorized_keys (non-interactive)
# -----------------------------------------------------------------------------
log "Ensuring user '${USERNAME}' exists and has sudo…"
if ! id -u "${USERNAME}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${USERNAME}"
fi

# Disable history for the password change (to prevent it from appearing in history)
HISTFILE=/dev/null
echo "${USERNAME}:${USER_PASSWORD}" | chpasswd
usermod -aG sudo "${USERNAME}"
if [ "$FORCE_PASSWORD_CHANGE" == "true" ]; then
    chage -d 0 "${USERNAME}"
fi

# Authorized key
install -d -m 700 "/home/${USERNAME}/.ssh"
AUTH_FILE="/home/${USERNAME}/.ssh/authorized_keys"
touch "${AUTH_FILE}"
grep -qxF "${USER_AUTHORIZED_KEY}" "${AUTH_FILE}" || echo "${USER_AUTHORIZED_KEY}" >> "${AUTH_FILE}"
chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}/.ssh"
chmod 600 "${AUTH_FILE}"

# -----------------------------------------------------------------------------
# 4) SSH hardening (idempotent edits)
# -----------------------------------------------------------------------------
log "Hardening SSH config…"
SSHD="/etc/ssh/sshd_config"

# helper to ensure 'Key value' exists or is updated
ensure_sshd_opt () {
  local key="$1" value="$2"
  if grep -qE "^[#\s]*${key}\s+" "${SSHD}"; then
    sed -ri "s|^[#\s]*(${key})\s+.*|\1 ${value}|" "${SSHD}"
  else
    echo "${key} ${value}" >> "${SSHD}"
  fi
}

ensure_sshd_opt "PermitRootLogin" "no"
ensure_sshd_opt "Protocol" "2"
# Restrict SSH to the admin user
if ! grep -q "^AllowUsers " "${SSHD}"; then
  echo "AllowUsers ${USERNAME}" >> "${SSHD}"
else
  sed -ri "s/^AllowUsers .*/AllowUsers ${USERNAME}/" "${SSHD}"
fi
ensure_sshd_opt "ClientAliveInterval" "180"
ensure_sshd_opt "PermitEmptyPasswords" "no"

systemctl reload ssh || systemctl reload sshd || true

# -----------------------------------------------------------------------------
# 5) Editor / Monitoring basics
# -----------------------------------------------------------------------------
log "Installing vim and htop…"
apt-get install -y vim htop

# -----------------------------------------------------------------------------
# 6) UFW firewall rules based on ROLE
# -----------------------------------------------------------------------------
log "Installing and configuring UFW…"
apt-get install -y ufw
ufw --force reset
ufw default allow outgoing
ufw default deny incoming
ufw allow from 10.0.0.0/8 # 
ufw allow 22/tcp            # SSH

sudo ufw allow 6443/tcp    # Kubernetes API server
sudo ufw allow 9345/tcp    # RKE2 supervisor API
sudo ufw allow 10250/tcp   # kubelet metrics
#sudo ufw allow from 10.0.0.0/8 to any port 8472 proto udp    # Canal CNI with VXLAN
sudo ufw allow 9099/tcp    # Canal CNI health checks   
  
if [[ "${ROLE}" == "etcd-cp" || "${ROLE}" == "rancher" ]]; then
  # Ports for etcd + control-plane nodes
  ufw allow 2379:2381/tcp     # etcd client port / etcd peer port / etcd metrics port
fi  
if [[ "${ROLE}" == "worker" || "${ROLE}" == "rancher" ]]; then
  # Ports for worker nodes
  ufw allow 80/tcp            # HTTP (for services running on worker nodes)
  ufw allow 443/tcp           # HTTPS (for secure Kubernetes communication)
  ufw allow 30000:32767/tcp   # NodePort services (for accessing Kubernetes services externally)
fi
# sudo ufw allow from 10.0.0.0/8 to any port 6443 proto tcp    # Kubernetes API server
# sudo ufw allow from 10.0.0.0/8 to any port 9345 proto tcp    # RKE2 supervisor API
# sudo ufw allow from 10.0.0.0/8 to any port 10250 proto tcp   # kubelet metrics
# sudo ufw allow from 10.0.0.0/8 to any port 8472 proto udp    # Canal CNI with VXLAN
# sudo ufw allow from 10.0.0.0/8 to any port 9099 proto tcp    # Canal CNI health checks   
  
# if [[ "${ROLE}" == "etcd-cp" || "${ROLE}" == "rancher" ]]; then
#   # Ports for etcd + control-plane nodes
#   sudo ufw allow from 10.0.0.0/8 to any port 2379:2381 proto tcp     # etcd client port / etcd peer port / etcd metrics port
# fi  
# if [[ "${ROLE}" == "worker" || "${ROLE}" == "rancher" ]]; then
#   # Ports for worker nodes
#   ufw allow 80/tcp            # HTTP (for services running on worker nodes)
#   ufw allow 443/tcp           # HTTPS (for secure Kubernetes communication)
#   ufw allow from 10.0.0.0/8 to any port 30000:32767 proto tcp   # NodePort services (for accessing Kubernetes services externally)

# fi


ufw --force enable
ufw status verbose

# -----------------------------------------------------------------------------
# 7) Fail2Ban minimal hardening
# -----------------------------------------------------------------------------
log "Installing and configuring Fail2Ban…"
apt-get install -y fail2ban
cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 600
ignoreip = 127.0.0.1/8
ignoreself = true

[sshd]
enabled  = true
port     = 22
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
EOF
systemctl enable --now fail2ban

# -----------------------------------------------------------------------------
# 8) Longhorn support (open-iscsi) — typically workers
# -----------------------------------------------------------------------------
if [[ "${ROLE}" == "worker" && "${INSTALL_ISCSI_ON_WORKER}" == "true" ]]; then
  log "Installing open-iscsi for Longhorn (worker)…"
  apt-get install -y open-iscsi
  systemctl enable --now iscsid || true
fi

# =============================================================================
# Additional Hardening Steps
# =============================================================================

# ----------------------------------------------------------------------------- 
# 1) Install and enable unattended-upgrades
# ----------------------------------------------------------------------------- 
log "Installing and enabling unattended-upgrades..."
apt-get install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# ----------------------------------------------------------------------------- 
# 2) Install Lynis & Tiger
# ----------------------------------------------------------------------------- 
log "Installing Lynis & Tiger..."
apt-get install -y lynis tiger

# ----------------------------------------------------------------------------- 
# 3) Disable tmpfs
# ----------------------------------------------------------------------------- 
log "Disabling tmpfs..."
echo "tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
systemctl daemon-reload

# ----------------------------------------------------------------------------- 
# 4) Install and enable ClamAV (Antivirus)
# ----------------------------------------------------------------------------- 
log "Installing and enabling ClamAV (Antivirus)..."
apt-get install -y clamav clamav-daemon
systemctl enable --now clamav-freshclam
systemctl enable --now clamav-daemon

# ----------------------------------------------------------------------------- 
# 5) Install and enable logrotate
# ----------------------------------------------------------------------------- 
log "Installing and enabling logrotate..."
apt-get install -y logrotate
systemctl enable --now logrotate

# ----------------------------------------------------------------------------- 
# 6) Install and enable AppArmor
# ----------------------------------------------------------------------------- 
log "Installing and enabling AppArmor..."
apt-get install -y apparmor apparmor-utils
systemctl enable --now apparmor

# =============================================================================
# End of Additional Hardening Steps
# =============================================================================

# ----------------------------------------------------------------------------- 
# Summary
# -----------------------------------------------------------------------------
log "All done! Reboot is recommended."
echo "Summary:"
echo "  ROLE                : ${ROLE}"
echo "  HOSTNAME            : ${NEW_HOSTNAME}"
echo "  USER                : ${USERNAME} (sudo)"
echo "  SSH key installed   : $( [[ -n "${USER_AUTHORIZED_KEY}" ]] && echo yes || echo no )"
echo "  UFW                 : $(ufw status | head -n1)"
echo "  Unattended Upgrades : Installed and enabled"
echo "  Lynis               : Installed"
echo "  Tiger               : Installed"
echo "  tmpfs               : Disabled"
echo "  ClamAV (Antivirus)  : Installed and enabled"
echo "  logrotate           : Installed and enabled"
echo "  AppArmor            : Installed and enabled"
# echo "  2FA (Google Authenticator) : Enabled and enforced for ${USERNAME} on first login"
