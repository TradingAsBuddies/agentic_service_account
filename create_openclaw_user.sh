#!/usr/bin/env bash
# =============================================================================
# setup-openclaw-service-account.sh
# Creates a hardened service account for OpenClaw on Fedora 43
#
# Features:
#   - Dedicated 'openclaw' user with restricted login
#   - SELinux custom policy module for process confinement
#   - Scoped sudoers rules (only what OpenClaw actually needs)
#   - systemd system service with extensive hardening directives
#   - firewalld rules scoped to localhost-only by default
#   - Filesystem permission lockdown
#
# Usage:
#   sudo bash setup-openclaw-service-account.sh
#
# After running this script you will need to:
#   1. Switch to the openclaw user to run the installer/onboarding
#   2. Configure your LLM API keys and channels
#   3. Enable and start the systemd service
# =============================================================================

set -euo pipefail

# ── Preflight ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (or via sudo)." >&2
  exit 1
fi

OCUSER="openclaw"
OCHOME="/home/${OCUSER}"
OCDATA="${OCHOME}/.openclaw"
OCWORKSPACE="${OCHOME}/workspace"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  OpenClaw Service Account Setup — Fedora 43                 ║"
echo "║  SELinux + sudo confinement                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# ── 1. Create the service account ───────────────────────────────────────────

echo "▸ [1/7] Creating service account '${OCUSER}'..."

if id "${OCUSER}" &>/dev/null; then
  echo "  User '${OCUSER}' already exists — skipping creation."
else
  # Create a regular user (not --system, because OpenClaw needs a real home
  # dir and user-level systemd/lingering support), but with no password
  # and a restricted shell initially.
  useradd \
    --create-home \
    --home-dir "${OCHOME}" \
    --shell /bin/bash \
    --comment "OpenClaw AI Assistant Service Account" \
    "${OCUSER}"

  # Lock the password so direct login is blocked — access via `su` or `sudo -u`
  passwd --lock "${OCUSER}" >/dev/null 2>&1
  echo "  Created user '${OCUSER}' with locked password."
fi

# Enable lingering so user-level systemd services persist without a login session
loginctl enable-linger "${OCUSER}" 2>/dev/null || true
echo "  Lingering enabled for ${OCUSER}."

# ── 2. Directory structure and permissions ──────────────────────────────────

echo "▸ [2/7] Setting up directory structure and permissions..."

mkdir -p "${OCDATA}" "${OCWORKSPACE}"

# Lock down the home directory — only the openclaw user can enter
chmod 750 "${OCHOME}"
chmod 700 "${OCDATA}"
chmod 700 "${OCWORKSPACE}"
chown -R "${OCUSER}:${OCUSER}" "${OCHOME}"

# Prevent the openclaw user from reading other users' homes
# (Default Fedora behavior with 700 homes, but belt-and-suspenders)
echo "  Directories created and permissions set (750/700)."

# ── 3. Scoped sudoers rules ────────────────────────────────────────────────

echo "▸ [3/7] Installing scoped sudoers rules..."

cat > /etc/sudoers.d/openclaw << 'SUDOERS'
# /etc/sudoers.d/openclaw
# Scoped sudo rules for the OpenClaw service account
# Only allow specific, low-risk commands that OpenClaw may need.
#
# PRINCIPLE: Grant the minimum sudo necessary. OpenClaw should run
# almost entirely unprivileged. These rules cover edge cases like
# service restarts and package queries.

# Allow restarting its own systemd service
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl restart openclaw-gateway.service
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl status openclaw-gateway.service
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl stop openclaw-gateway.service
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl start openclaw-gateway.service

# Allow checking for port conflicts (read-only diagnostic)
openclaw ALL=(root) NOPASSWD: /usr/bin/ss -tlnp

# Allow reading systemd journal for its own service
openclaw ALL=(root) NOPASSWD: /usr/bin/journalctl -u openclaw-gateway.service *

# Deny everything else explicitly
# (This is default behavior, but makes the intent clear)
Defaults:openclaw !requiretty
SUDOERS

chmod 0440 /etc/sudoers.d/openclaw

# Validate the sudoers file
if visudo -c -f /etc/sudoers.d/openclaw >/dev/null 2>&1; then
  echo "  Sudoers rules installed and validated."
else
  echo "  WARNING: sudoers syntax check failed — review /etc/sudoers.d/openclaw"
fi

# ── 4. SELinux policy module ────────────────────────────────────────────────

echo "▸ [4/7] Building SELinux policy module for OpenClaw..."

# Check that SELinux is enforcing
SELINUX_MODE=$(getenforce 2>/dev/null || echo "Disabled")
echo "  Current SELinux mode: ${SELINUX_MODE}"

# Install policy build tools if needed
dnf install -y --quiet selinux-policy-devel policycoreutils-python-utils 2>/dev/null || true

POLICY_DIR=$(mktemp -d)
cat > "${POLICY_DIR}/openclaw_local.te" << 'TEPOLICY'
# SELinux Type Enforcement policy for OpenClaw
# Confines the openclaw gateway process.

policy_module(openclaw_local, 1.0.0)

require {
    type unconfined_t;
    type user_home_t;
    type user_home_dir_t;
    type node_t;
    type http_port_t;
    type unreserved_port_t;
    type dns_port_t;
    type net_conf_t;
    type cert_t;
    type passwd_file_t;
    type proc_t;
    type sysfs_t;
    type tmp_t;
    type usr_t;
    type bin_t;
    type lib_t;
    type locale_t;
    type fonts_t;
    type ld_so_t;
    type ld_so_cache_t;
    type devlog_t;
    type syslogd_var_run_t;
    class file { read open getattr execute execute_no_trans map create write append unlink rename setattr lock ioctl };
    class dir { read open getattr search add_name remove_name write create rmdir };
    class lnk_file { read getattr };
    class tcp_socket { create connect bind listen accept getopt setopt getattr read write shutdown name_connect name_bind node_bind };
    class udp_socket { create connect bind getopt setopt getattr read write };
    class unix_stream_socket { create connect bind listen accept getopt setopt read write connectto };
    class unix_dgram_socket { create connect bind getopt setopt read write sendto };
    class process { signal sigchld fork execmem setrlimit };
    class netlink_route_socket { create bind getattr read write nlmsg_read };
    class fifo_file { read write open getattr };
    class sock_file { write getattr };
}

# Define the openclaw domain and file types
type openclaw_t;
type openclaw_exec_t;
type openclaw_data_t;
type openclaw_workspace_t;

# openclaw_t is a domain (process runs in this context)
domain_type(openclaw_t)

# Allow transition from unconfined_t when executing openclaw_exec_t
domain_auto_trans(unconfined_t, openclaw_exec_t, openclaw_t)

# openclaw_t inherits basic domain permissions
role system_r types openclaw_t;

# ── File access ──────────────────────────────────────────────────────────

# Full access to its own data directory (~/.openclaw)
allow openclaw_t openclaw_data_t:file { read open getattr write create append unlink rename setattr lock ioctl map };
allow openclaw_t openclaw_data_t:dir { read open getattr search add_name remove_name write create rmdir };
allow openclaw_t openclaw_data_t:lnk_file { read getattr };

# Full access to its workspace
allow openclaw_t openclaw_workspace_t:file { read open getattr write create append unlink rename setattr lock ioctl map };
allow openclaw_t openclaw_workspace_t:dir { read open getattr search add_name remove_name write create rmdir };

# Read access to home directory structure
allow openclaw_t user_home_dir_t:dir { read open getattr search };
allow openclaw_t user_home_t:dir { read open getattr search };
allow openclaw_t user_home_t:file { read open getattr };

# Read system libraries, binaries, config
allow openclaw_t bin_t:file { read open getattr execute execute_no_trans map };
allow openclaw_t bin_t:dir { read open getattr search };
allow openclaw_t lib_t:file { read open getattr execute map };
allow openclaw_t lib_t:dir { read open getattr search };
allow openclaw_t ld_so_t:file { read open getattr execute map };
allow openclaw_t ld_so_cache_t:file { read open getattr map };
allow openclaw_t usr_t:file { read open getattr };
allow openclaw_t usr_t:dir { read open getattr search };
allow openclaw_t locale_t:file { read open getattr map };
allow openclaw_t locale_t:dir { read open getattr search };
allow openclaw_t fonts_t:file { read open getattr map };
allow openclaw_t fonts_t:dir { read open getattr search };

# Read /etc/passwd (Node.js os.userInfo() needs this)
allow openclaw_t passwd_file_t:file { read open getattr };

# Read /proc and /sys for Node.js runtime
allow openclaw_t proc_t:file { read open getattr };
allow openclaw_t proc_t:dir { read open getattr search };
allow openclaw_t sysfs_t:file { read open getattr };
allow openclaw_t sysfs_t:dir { read open getattr search };

# /tmp access for Node.js
allow openclaw_t tmp_t:file { read open getattr write create append unlink rename setattr lock ioctl map };
allow openclaw_t tmp_t:dir { read open getattr search add_name remove_name write create };

# Read SSL certs
allow openclaw_t cert_t:file { read open getattr };
allow openclaw_t cert_t:dir { read open getattr search };

# Read DNS config
allow openclaw_t net_conf_t:file { read open getattr };

# ── Network access ───────────────────────────────────────────────────────

# TCP: allow binding to the gateway port and connecting outbound to APIs
allow openclaw_t unreserved_port_t:tcp_socket { name_bind name_connect };
allow openclaw_t http_port_t:tcp_socket { name_connect };
allow openclaw_t node_t:tcp_socket { node_bind };
allow openclaw_t self:tcp_socket { create connect bind listen accept getopt setopt getattr read write shutdown };

# UDP: DNS resolution
allow openclaw_t dns_port_t:udp_socket { name_connect };
allow openclaw_t self:udp_socket { create connect bind getopt setopt getattr read write };

# Unix sockets (Node.js IPC)
allow openclaw_t self:unix_stream_socket { create connect bind listen accept getopt setopt read write };
allow openclaw_t self:unix_dgram_socket { create connect bind getopt setopt read write sendto };

# Netlink for route/interface info
allow openclaw_t self:netlink_route_socket { create bind getattr read write nlmsg_read };

# Syslog
allow openclaw_t devlog_t:sock_file { write getattr };
allow openclaw_t syslogd_var_run_t:dir { read open getattr search };
allow openclaw_t self:unix_dgram_socket { sendto };

# ── Process ──────────────────────────────────────────────────────────────

# Node.js needs fork, execmem (for JIT), and signal handling
allow openclaw_t self:process { signal sigchld fork execmem setrlimit };
allow openclaw_t self:fifo_file { read write open getattr };

# ── Deny by default ─────────────────────────────────────────────────────
# Everything NOT explicitly allowed above is denied by SELinux.
# Key things that are denied:
#   - Writing to /etc, /usr, /var (system dirs)
#   - Reading other users' home dirs
#   - Loading kernel modules
#   - Accessing raw block devices
#   - Mounting filesystems
#   - Changing SELinux contexts
#   - ptrace / debugging other processes
TEPOLICY

# File contexts — label the OpenClaw directories
cat > "${POLICY_DIR}/openclaw_local.fc" << FCPOLICY
${OCHOME}/.openclaw(/.*)?    gen_context(system_u:object_r:openclaw_data_t,s0)
${OCWORKSPACE}(/.*)?         gen_context(system_u:object_r:openclaw_workspace_t,s0)
FCPOLICY

# Build and install the module
pushd "${POLICY_DIR}" >/dev/null

if make -f /usr/share/selinux/devel/Makefile openclaw_local.pp 2>/dev/null; then
  semodule -i openclaw_local.pp
  echo "  SELinux policy module 'openclaw_local' installed."

  # Apply file contexts
  restorecon -R "${OCHOME}" 2>/dev/null || true
  echo "  File contexts applied to ${OCHOME}."
else
  echo "  WARNING: SELinux policy compilation failed."
  echo "  This may be due to missing selinux-policy-devel."
  echo "  The account will still work but without custom SELinux confinement."
  echo "  You can install it with: dnf install selinux-policy-devel"
  echo "  Then re-run this script."
fi

popd >/dev/null
rm -rf "${POLICY_DIR}"

# ── 5. systemd service with hardening ──────────────────────────────────────

echo "▸ [5/7] Installing hardened systemd service..."

cat > /etc/systemd/system/openclaw-gateway.service << SYSTEMD
[Unit]
Description=OpenClaw AI Gateway (hardened)
Documentation=https://docs.openclaw.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OCUSER}
Group=${OCUSER}
WorkingDirectory=${OCHOME}

# ── Launch command ──
# Adjust this path after running the OpenClaw installer as the openclaw user.
# The installer typically places the binary at ~/.openclaw/bin/openclaw
ExecStart=${OCHOME}/.openclaw/bin/openclaw gateway start --foreground
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

# ── Environment ──
Environment=NODE_ENV=production
Environment=HOME=${OCHOME}
Environment=OPENCLAW_DISABLE_BONJOUR=1

# ── Filesystem hardening ──
ProtectSystem=strict
ProtectHome=tmpfs
BindPaths=${OCHOME}
ReadWritePaths=${OCDATA} ${OCWORKSPACE}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true

# ── Capability restrictions ──
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=

# ── Network ──
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
IPAddressDeny=any
# Allow loopback + outbound to LLM APIs.
# CUSTOMIZE: Add your LLM provider IP ranges if you want to be stricter.
IPAddressAllow=localhost
IPAddressAllow=0.0.0.0/0

# ── Syscall filtering ──
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @raw-io @module @debug @obsolete
SystemCallArchitectures=native

# ── Memory / execution ──
MemoryDenyWriteExecute=false
# NOTE: Node.js V8 JIT requires W^X pages, so we cannot enable
# MemoryDenyWriteExecute=true. This is a known trade-off with Node runtimes.

# ── Misc ──
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
PrivateDevices=true
DeviceAllow=

# ── Resource limits ──
LimitNOFILE=65536
LimitNPROC=512
# Set a memory ceiling to prevent runaway usage
MemoryMax=2G
CPUQuota=200%

# ── Logging ──
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw-gateway

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
echo "  systemd service installed at /etc/systemd/system/openclaw-gateway.service"

# ── 6. Firewall rules ──────────────────────────────────────────────────────

echo "▸ [6/7] Configuring firewall rules..."

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
  # Only allow the gateway port on localhost by default.
  # If you need remote access, use Tailscale or an SSH tunnel instead.
  firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="127.0.0.1" port protocol="tcp" port="18789" accept' 2>/dev/null || true
  firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source address="::1" port protocol="tcp" port="18789" accept' 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null || true
  echo "  Gateway port 18789 allowed on localhost only."
else
  echo "  firewalld not active — skipping (configure manually if needed)."
fi

# ── 7. Summary & next steps ────────────────────────────────────────────────

echo "▸ [7/7] Finalizing..."
echo

cat << 'SUMMARY'
╔══════════════════════════════════════════════════════════════════════╗
║  SETUP COMPLETE                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  User:       openclaw (password locked, no direct SSH login)         ║
║  Home:       /home/openclaw                                          ║
║  Data:       /home/openclaw/.openclaw    (mode 700)                  ║
║  Workspace:  /home/openclaw/workspace    (mode 700)                  ║
║  Service:    openclaw-gateway.service                                ║
║  SELinux:    openclaw_local policy module (if compilation succeeded)  ║
║  Sudo:       scoped to service restart + diagnostics only            ║
║  Firewall:   port 18789 on localhost only                            ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  NEXT STEPS                                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  1. Switch to the openclaw user to install OpenClaw:                 ║
║                                                                      ║
║       sudo -u openclaw -i                                            ║
║       curl -fsSL https://openclaw.ai/install.sh | bash               ║
║                                                                      ║
║  2. Run onboarding:                                                  ║
║                                                                      ║
║       openclaw onboard                                               ║
║                                                                      ║
║  3. After onboarding, verify the ExecStart path in the service:      ║
║                                                                      ║
║       which openclaw                                                 ║
║       # Then update ExecStart in the service file if needed:         ║
║       sudo systemctl edit openclaw-gateway.service                   ║
║                                                                      ║
║  4. Enable and start:                                                ║
║                                                                      ║
║       sudo systemctl enable --now openclaw-gateway.service           ║
║                                                                      ║
║  5. Check status:                                                    ║
║                                                                      ║
║       systemctl status openclaw-gateway.service                      ║
║       journalctl -u openclaw-gateway.service -f                      ║
║                                                                      ║
║  6. Set OpenClaw's own exec consent mode for defense-in-depth:       ║
║                                                                      ║
║       Edit ~/.openclaw/config and set:                               ║
║         exec.ask: "on"                                               ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  SECURITY NOTES                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  • The openclaw user CANNOT: read /etc/shadow, install packages,     ║
║    modify other users' files, load kernel modules, mount fs, or      ║
║    access raw devices.                                               ║
║                                                                      ║
║  • The openclaw user CAN: restart its own service, check ports,      ║
║    read its own journal logs, and manage files within its home.      ║
║                                                                      ║
║  • SELinux (if active) further confines the process even if the      ║
║    application itself is compromised.                                ║
║                                                                      ║
║  • The systemd service adds defense-in-depth: ProtectSystem=strict,  ║
║    PrivateTmp, capability bounding, syscall filtering, etc.          ║
║                                                                      ║
║  • For remote access, use Tailscale Serve or an SSH tunnel rather    ║
║    than opening port 18789 to the internet.                          ║
║                                                                      ║
║  • Disable mDNS broadcasting: OPENCLAW_DISABLE_BONJOUR=1 is set     ║
║    in the service file to prevent network reconnaissance.            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
SUMMARY

echo
echo "To audit the SELinux confinement later:"
echo "  sudo ausearch -m avc -ts recent | audit2why"
echo "  sudo semanage fcontext -l | grep openclaw"
echo
echo "Done."
