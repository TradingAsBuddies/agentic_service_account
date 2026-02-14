#!/usr/bin/env bash
# =============================================================================
# setup-claude-code-for-openclaw.sh
# Installs Claude Code for the 'openclaw' service account on Fedora 43
#
# Run AFTER setup-openclaw-service-account.sh
#
# This script:
#   1. Installs Claude Code native binary as the openclaw user
#   2. Configures headless/API-key authentication
#   3. Sets up the environment for non-interactive and interactive use
#   4. Updates the systemd service to include Claude Code in PATH
#   5. Updates SELinux file contexts for the Claude Code binary
#   6. Adds scoped sudoers rules for Claude Code operations
#   7. Creates a wrapper script for your admin account to invoke claude as openclaw
#
# Usage:
#   sudo bash setup-claude-code-for-openclaw.sh
#
# You will be prompted for your Anthropic API key (or you can set it later).
# =============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (or via sudo)." >&2
  exit 1
fi

OCUSER="openclaw"
OCHOME="/home/${OCUSER}"
OCDATA="${OCHOME}/.openclaw"
CLAUDE_HOME="${OCHOME}/.claude"
CLAUDE_BIN_DIR="${OCHOME}/.local/bin"
CLAUDE_DATA_DIR="${OCHOME}/.claude"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Claude Code Setup for OpenClaw Service Account             ║"
echo "║  Fedora 43 — headless / API-key auth                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# ── Preflight checks ───────────────────────────────────────────────────────

if ! id "${OCUSER}" &>/dev/null; then
  echo "ERROR: User '${OCUSER}' does not exist." >&2
  echo "Run setup-openclaw-service-account.sh first." >&2
  exit 1
fi

# ── 1. Install Claude Code native binary ───────────────────────────────────

echo "▸ [1/7] Installing Claude Code native binary as '${OCUSER}'..."

# Create the directories Claude Code expects
sudo -u "${OCUSER}" mkdir -p "${CLAUDE_BIN_DIR}"
sudo -u "${OCUSER}" mkdir -p "${CLAUDE_DATA_DIR}"

# Install using the native installer (recommended by Anthropic, no Node.js needed)
# We run this as the openclaw user so it installs into their home directory.
sudo -u "${OCUSER}" bash -c 'curl -fsSL https://claude.ai/install.sh | bash' || {
  echo "  Native installer failed. Falling back to npm method..."
  echo "  Checking for Node.js..."

  if ! command -v node &>/dev/null; then
    echo "  Installing Node.js 20..."
    dnf install -y nodejs20 npm 2>/dev/null || dnf install -y nodejs npm 2>/dev/null || {
      echo "ERROR: Could not install Node.js. Install it manually and re-run." >&2
      exit 1
    }
  fi

  NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
  if [[ "${NODE_VERSION}" -lt 18 ]]; then
    echo "ERROR: Node.js 18+ required, found v${NODE_VERSION}." >&2
    exit 1
  fi

  # Set up npm global directory for the openclaw user (never use sudo npm)
  sudo -u "${OCUSER}" bash -c '
    mkdir -p ~/.npm-global
    npm config set prefix "~/.npm-global"
    npm install -g @anthropic-ai/claude-code
  '
  CLAUDE_BIN_DIR="${OCHOME}/.npm-global/bin"
  echo "  Installed via npm to ${CLAUDE_BIN_DIR}"
}

# Determine where claude actually ended up
CLAUDE_BIN=""
for candidate in \
  "${OCHOME}/.claude/bin/claude" \
  "${OCHOME}/.local/bin/claude" \
  "${OCHOME}/.npm-global/bin/claude"; do
  if [[ -x "${candidate}" ]]; then
    CLAUDE_BIN="${candidate}"
    break
  fi
done

if [[ -z "${CLAUDE_BIN}" ]]; then
  echo "  WARNING: Could not locate claude binary automatically."
  echo "  You may need to find it with: sudo -u ${OCUSER} find ${OCHOME} -name claude -type f"
  CLAUDE_BIN="${OCHOME}/.claude/bin/claude"
  echo "  Assuming: ${CLAUDE_BIN}"
else
  echo "  Claude Code binary found at: ${CLAUDE_BIN}"
fi

CLAUDE_BIN_PARENT=$(dirname "${CLAUDE_BIN}")

# ── 2. Configure authentication ───────────────────────────────────────────

echo "▸ [2/7] Configuring authentication..."
echo

# Prompt for API key
read -r -p "  Enter your Anthropic API key (or press Enter to skip and configure later): " API_KEY

ENV_FILE="${OCHOME}/.claude-env"

if [[ -n "${API_KEY}" ]]; then
  # Write the key to a protected environment file
  cat > "${ENV_FILE}" << EOF
# Anthropic API key for Claude Code
# This file is sourced by the systemd service and the shell profile.
# Permissions: 600, owned by ${OCUSER}
ANTHROPIC_API_KEY=${API_KEY}
EOF
  echo "  API key saved to ${ENV_FILE}"
else
  # Create a placeholder
  cat > "${ENV_FILE}" << 'EOF'
# Anthropic API key for Claude Code
# Set your key here:
# ANTHROPIC_API_KEY=sk-ant-...
#
# Or authenticate interactively:
#   sudo -u openclaw -i
#   claude /login
EOF
  echo "  Placeholder created at ${ENV_FILE}"
  echo "  You'll need to either:"
  echo "    a) Edit ${ENV_FILE} and add your ANTHROPIC_API_KEY, or"
  echo "    b) Run 'sudo -u ${OCUSER} -i' then 'claude /login' (requires SSH port forwarding)"
fi

chown "${OCUSER}:${OCUSER}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

# ── 3. Configure the shell environment ────────────────────────────────────

echo "▸ [3/7] Configuring shell environment for '${OCUSER}'..."

BASHRC="${OCHOME}/.bashrc"

# Add Claude Code PATH and env to the openclaw user's .bashrc
# Use a marker so we can detect if this has already been added
MARKER="# === Claude Code configuration (managed) ==="
if ! grep -qF "${MARKER}" "${BASHRC}" 2>/dev/null; then
  cat >> "${BASHRC}" << EOF

${MARKER}
# Claude Code binary
export PATH="${CLAUDE_BIN_PARENT}:\${HOME}/.local/bin:\${HOME}/.npm-global/bin:\${PATH}"

# Load API key from protected env file
if [[ -f "\${HOME}/.claude-env" ]]; then
  set -a
  source "\${HOME}/.claude-env"
  set +a
fi

# Disable Claude Code auto-updater in production service environments
# Uncomment the next line if you want to pin versions and update manually:
# export DISABLE_AUTOUPDATER=1
EOF
  chown "${OCUSER}:${OCUSER}" "${BASHRC}"
  echo "  Updated ${BASHRC} with Claude Code environment."
else
  echo "  Claude Code environment already configured in ${BASHRC}."
fi

# ── 4. Update systemd service ─────────────────────────────────────────────

echo "▸ [4/7] Creating systemd drop-in for Claude Code PATH..."

# Create a drop-in that adds Claude Code to the openclaw-gateway service environment
# and also creates a dedicated claude-code service for running Claude Code tasks.
mkdir -p /etc/systemd/system/openclaw-gateway.service.d

cat > /etc/systemd/system/openclaw-gateway.service.d/claude-code.conf << EOF
[Service]
# Add Claude Code to PATH so OpenClaw skills/exec can invoke it
Environment=PATH=${CLAUDE_BIN_PARENT}:${OCHOME}/.local/bin:${OCHOME}/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=-${ENV_FILE}
EOF

echo "  Drop-in created: openclaw-gateway.service.d/claude-code.conf"

# Also create a dedicated oneshot service for running Claude Code tasks
cat > /etc/systemd/system/claude-code@.service << EOF
[Unit]
Description=Claude Code Task (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${OCUSER}
Group=${OCUSER}
WorkingDirectory=${OCHOME}/workspace

# Claude Code binary
ExecStart=${CLAUDE_BIN} -p "%i"

# Environment
Environment=HOME=${OCHOME}
Environment=PATH=${CLAUDE_BIN_PARENT}:${OCHOME}/.local/bin:${OCHOME}/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=-${ENV_FILE}

# ── Hardening (same as gateway service) ──
ProtectSystem=strict
ProtectHome=tmpfs
BindPaths=${OCHOME}
ReadWritePaths=${OCDATA} ${OCHOME}/workspace ${OCHOME}/.claude
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @raw-io @module @debug @obsolete
SystemCallArchitectures=native
MemoryDenyWriteExecute=false
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
PrivateDevices=true
DeviceAllow=

# Resource limits
LimitNOFILE=65536
MemoryMax=2G
CPUQuota=200%
TimeoutStartSec=300

StandardOutput=journal
StandardError=journal
SyslogIdentifier=claude-code

[Install]
WantedBy=multi-user.target
EOF

echo "  Oneshot service template: claude-code@.service"

systemctl daemon-reload

# ── 5. Update SELinux contexts ────────────────────────────────────────────

echo "▸ [5/7] Updating SELinux file contexts..."

if command -v semanage &>/dev/null; then
  # Label the Claude Code directories so the openclaw_t domain can access them
  semanage fcontext -a -t openclaw_data_t "${OCHOME}/.claude(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t openclaw_data_t "${OCHOME}/.claude(/.*)?" 2>/dev/null || true

  semanage fcontext -a -t bin_t "${OCHOME}/.claude/bin(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t bin_t "${OCHOME}/.claude/bin(/.*)?" 2>/dev/null || true

  semanage fcontext -a -t bin_t "${OCHOME}/.local/bin(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t bin_t "${OCHOME}/.local/bin(/.*)?" 2>/dev/null || true

  semanage fcontext -a -t bin_t "${OCHOME}/.npm-global/bin(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t bin_t "${OCHOME}/.npm-global/bin(/.*)?" 2>/dev/null || true

  # Apply the contexts
  restorecon -R "${OCHOME}/.claude" 2>/dev/null || true
  restorecon -R "${OCHOME}/.local" 2>/dev/null || true
  restorecon -R "${OCHOME}/.npm-global" 2>/dev/null || true

  echo "  SELinux file contexts updated and applied."
else
  echo "  semanage not found — skipping SELinux context updates."
  echo "  Install with: dnf install policycoreutils-python-utils"
fi

# ── 6. Update sudoers for Claude Code operations ─────────────────────────

echo "▸ [6/7] Updating sudoers rules for Claude Code..."

SUDOERS_FILE="/etc/sudoers.d/openclaw"

# Append Claude Code-specific rules if not already present
if ! grep -q "claude-code" "${SUDOERS_FILE}" 2>/dev/null; then
  cat >> "${SUDOERS_FILE}" << EOF

# ── Claude Code operations ──
# Allow running Claude Code tasks via the oneshot service template
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl start claude-code@*
openclaw ALL=(root) NOPASSWD: /usr/bin/systemctl status claude-code@*
openclaw ALL=(root) NOPASSWD: /usr/bin/journalctl -u claude-code@*

# Allow the openclaw user to update Claude Code
openclaw ALL=(root) NOPASSWD: ${CLAUDE_BIN} update
openclaw ALL=(root) NOPASSWD: ${CLAUDE_BIN} doctor
EOF

  chmod 0440 "${SUDOERS_FILE}"

  if visudo -c -f "${SUDOERS_FILE}" >/dev/null 2>&1; then
    echo "  Sudoers rules updated and validated."
  else
    echo "  WARNING: sudoers validation failed — review ${SUDOERS_FILE}"
  fi
else
  echo "  Claude Code sudoers rules already present."
fi

# ── 7. Create convenience wrapper ─────────────────────────────────────────

echo "▸ [7/7] Creating convenience wrapper..."

# Create a wrapper script so your admin account can easily run Claude Code
# in the context of the openclaw user
cat > /usr/local/bin/oc-claude << 'WRAPPER'
#!/usr/bin/env bash
# oc-claude — Run Claude Code as the openclaw service account
#
# Usage:
#   oc-claude                     # interactive session
#   oc-claude -p "prompt here"    # non-interactive / headless
#   oc-claude doctor              # health check
#   oc-claude update              # update Claude Code
#   oc-claude /login              # interactive OAuth login (needs SSH port forwarding)
#
# This wrapper switches to the 'openclaw' user, loads its environment,
# and runs Claude Code within the openclaw workspace.

set -euo pipefail

OCUSER="openclaw"
OCHOME="/home/${OCUSER}"

if [[ $EUID -eq 0 ]] || sudo -n true 2>/dev/null; then
  exec sudo -u "${OCUSER}" -i bash -lc "cd ~/workspace && claude $*"
else
  echo "ERROR: You need sudo access to run Claude Code as '${OCUSER}'." >&2
  exit 1
fi
WRAPPER

chmod 755 /usr/local/bin/oc-claude
echo "  Wrapper installed at /usr/local/bin/oc-claude"

# ── Final permissions sweep ───────────────────────────────────────────────

chown -R "${OCUSER}:${OCUSER}" "${OCHOME}/.claude" 2>/dev/null || true
chown -R "${OCUSER}:${OCUSER}" "${OCHOME}/.local" 2>/dev/null || true
chmod 700 "${OCHOME}/.claude" 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────

echo
cat << SUMMARY
╔══════════════════════════════════════════════════════════════════════╗
║  CLAUDE CODE SETUP COMPLETE                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Binary:     ${CLAUDE_BIN}
║  Config:     ${OCHOME}/.claude/
║  Env file:   ${OCHOME}/.claude-env  (API key — mode 600)
║  Wrapper:    /usr/local/bin/oc-claude
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  AUTHENTICATION                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Option A — API Key (headless, recommended for service accounts):    ║
║                                                                      ║
║    Edit /home/openclaw/.claude-env and set:                          ║
║      ANTHROPIC_API_KEY=sk-ant-your-key-here                         ║
║                                                                      ║
║    Then test:                                                        ║
║      oc-claude -p "Hello, confirm you can see me"                    ║
║                                                                      ║
║  Option B — OAuth login (interactive, needs port forwarding):        ║
║                                                                      ║
║    From your local machine:                                          ║
║      ssh -L 8080:localhost:8080 you@server                           ║
║                                                                      ║
║    On the server:                                                    ║
║      sudo -u openclaw -i                                             ║
║      claude /login                                                   ║
║                                                                      ║
║    Then open the URL it prints in your local browser.                ║
║                                                                      ║
║  Option C — Claude Pro/Max subscription:                             ║
║                                                                      ║
║    Same as Option B, but choose "Claude.ai account" during login.    ║
║    Do NOT set ANTHROPIC_API_KEY (it overrides subscription auth).    ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  USAGE                                                               ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  From your admin account (wrapper):                                  ║
║    oc-claude                      # interactive session              ║
║    oc-claude -p "fix the bug"     # headless one-shot                ║
║    oc-claude doctor               # health check                     ║
║    oc-claude update               # update Claude Code               ║
║                                                                      ║
║  As the openclaw user directly:                                      ║
║    sudo -u openclaw -i                                               ║
║    cd ~/workspace                                                    ║
║    claude                                                            ║
║                                                                      ║
║  Via systemd (for automated tasks):                                  ║
║    systemctl start 'claude-code@fix the bug in main.py'              ║
║    journalctl -u 'claude-code@fix the bug in main.py'               ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  SECURITY NOTES                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  • The API key is stored in ~/.claude-env (mode 600) — only the     ║
║    openclaw user can read it.                                        ║
║                                                                      ║
║  • The systemd EnvironmentFile directive loads the key at service    ║
║    start without exposing it in process listings.                    ║
║                                                                      ║
║  • Claude Code runs under the same SELinux confinement and systemd  ║
║    hardening as the OpenClaw gateway.                                ║
║                                                                      ║
║  • The oneshot service template (claude-code@.service) lets you      ║
║    dispatch tasks with full sandboxing without an interactive shell. ║
║                                                                      ║
║  • The oc-claude wrapper requires sudo — your admin account gates   ║
║    all access to the openclaw user's environment.                    ║
║                                                                      ║
║  • For CI/CD or cron usage, use:                                     ║
║      claude -p "prompt" --allowedTools Read,Grep,Glob               ║
║    to restrict which tools Claude Code can use.                      ║
║                                                                      ║
║  • NEVER use --dangerously-skip-permissions except in fully          ║
║    isolated disposable containers.                                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
SUMMARY

echo
echo "Quick smoke test (after setting your API key):"
echo "  oc-claude -p 'What OS am I running on?'"
echo
echo "Done."
