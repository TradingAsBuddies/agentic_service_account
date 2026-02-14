# OpenClaw Service Account — Design Rationale

## Why This Approach

OpenClaw is a high-privilege AI agent: it can execute shell commands, read/write
files, and control browsers. Running it as your main user account means a prompt
injection or malicious skill gets access to everything *you* can access. This
setup creates a three-layer defense:

1. **OS-level isolation** — dedicated user with minimal permissions
2. **SELinux confinement** — mandatory access control even if the app is compromised
3. **systemd hardening** — capability bounding, syscall filtering, filesystem restrictions

## Layer 1: The Service Account

The `openclaw` user is created as a regular (non-system) user because OpenClaw
needs a real home directory and `loginctl enable-linger` for persistent services.
However:

- **Password is locked** — no one can SSH in or `login` as this user directly
- **Access is via `sudo -u openclaw -i`** — your admin account gates all access
- **Home is 750** — other non-root users can't read into it
- **Data dirs are 700** — only the openclaw user touches config and workspace

## Layer 2: Scoped Sudo

The sudoers rules follow least-privilege strictly. OpenClaw may need to:

| Allowed Command | Why |
|---|---|
| `systemctl restart/start/stop/status openclaw-gateway.service` | Self-healing restarts |
| `ss -tlnp` | Port conflict diagnostics (`openclaw doctor` uses this) |
| `journalctl -u openclaw-gateway.service` | Reading its own service logs |

Everything else is denied. The `openclaw` user cannot `dnf install`, `useradd`,
read `/etc/shadow`, or do anything outside its lane.

## Layer 3: SELinux Policy

The custom `openclaw_local` policy module defines:

- **`openclaw_t`** — the domain (process context) for the running gateway
- **`openclaw_data_t`** — the label for `~/.openclaw/` (config, sessions, keys)
- **`openclaw_workspace_t`** — the label for `~/workspace/` (agent working dir)

### What the policy ALLOWS:
- Read/write its own data and workspace directories
- Read system libraries, `/etc/passwd`, SSL certs, DNS config (Node.js needs these)
- Bind to unreserved TCP ports (18789) and connect outbound to HTTPS (API calls)
- Fork processes, use JIT memory (V8 requirement)
- Use `/tmp` for Node.js temporary files

### What the policy DENIES (by omission):
- Writing to `/etc/`, `/usr/`, `/var/` (system directories)
- Reading other users' home directories
- Loading kernel modules
- Accessing raw block devices
- Mounting filesystems
- Changing SELinux contexts
- Debugging/ptracing other processes
- Accessing the Docker/Podman socket

### SELinux Troubleshooting

After starting the service, if things break, check for AVC denials:

```bash
sudo ausearch -m avc -ts recent | audit2why
```

If you see legitimate denials (Node.js needing something unexpected), you can
generate a supplemental policy:

```bash
sudo ausearch -m avc -ts recent | audit2allow -M openclaw_supplement
sudo semodule -i openclaw_supplement.pp
```

But **review what you're allowing** before installing — that's the whole point.

## Layer 4: systemd Hardening

The service file stacks additional protections:

| Directive | Effect |
|---|---|
| `ProtectSystem=strict` | Entire filesystem is read-only except explicitly allowed paths |
| `ProtectHome=tmpfs` | All home dirs hidden; only `/home/openclaw` bind-mounted back |
| `PrivateTmp=true` | Isolated `/tmp` namespace |
| `NoNewPrivileges=true` | Cannot gain privileges via setuid/setgid binaries |
| `CapabilityBoundingSet=` | All Linux capabilities dropped |
| `SystemCallFilter=@system-service` | Only "normal" syscalls allowed; mount/reboot/raw-io blocked |
| `RestrictNamespaces=true` | Cannot create new namespaces (prevents container escape patterns) |
| `PrivateDevices=true` | No access to physical devices |
| `MemoryMax=2G` | Hard memory ceiling |
| `CPUQuota=200%` | CPU limit (200% = 2 cores max) |

### The V8 JIT Trade-off

`MemoryDenyWriteExecute=false` is intentional. Node.js V8 uses JIT compilation
which requires memory pages that are both writable and executable. Enabling this
would crash the gateway. This is a known limitation with all Node.js workloads
under systemd hardening.

## Network Isolation

- **OPENCLAW_DISABLE_BONJOUR=1** prevents mDNS broadcasting of the gateway's
  presence on your LAN (filesystem paths, SSH availability, etc.)
- **firewalld rules** restrict port 18789 to localhost only
- For remote access, use **Tailscale Serve** or an **SSH tunnel** — never expose
  the gateway port directly to the internet

## Extending This Setup

### If you want to run OpenClaw in a Podman container instead:

Podman rootless + this user account is an excellent combination. The user already
has lingering enabled. You'd skip the SELinux policy module and rely on container
isolation instead, but the sudoers and systemd hardening still apply.

### If you want tighter exec control:

Set `exec.ask: "on"` in OpenClaw's own config (`~/.openclaw/config`). This makes
the agent ask for your approval before running shell commands — defense-in-depth
on top of the OS-level restrictions.

### Fedora Cloud / Bootable Containers note:

If you're running this on a Fedora CoreOS or Fedora IoT immutable image, the
`/etc/sudoers.d/` and `/etc/systemd/system/` paths may need to go through
`rpm-ostree` or be layered via Butane/Ignition config instead. The SELinux policy
module installs the same way via `semodule`. The user creation would go into your
Ignition config's `passwd.users` section.
