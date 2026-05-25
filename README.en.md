# smooth-ssh-mcp

[中文](README.zh-CN.md) | [Back to README](README.md)

## What It Is

`smooth-ssh-mcp` is an SSH connection management MCP server for AI assistants. It wraps system OpenSSH as a tool layer designed for model use: assistants can probe connections, inspect servers, run remote commands, transfer files, and manage port forwards without seeing real passwords or private key contents.

It is an accidental-damage prevention and audit layer for SSH operations. It is not a remote shell sandbox or a full terminal emulator.

## Use Cases

- Let Codex, Claude, OpenCode, or another MCP client operate saved SSH hosts.
- List hosts, choose a default host, and inspect recent host usage.
- Diagnose SSH failures such as TCP errors, timeouts, authentication failure, host key problems, or missing config.
- Run argv-style remote commands instead of ad-hoc shell strings.
- Run read-only host health checks for system info, load, memory, disk, services, ports, Docker, and key logs.
- Open bounded interactive sessions for short commands, simple menus, REPLs, or temporary remote context.
- Upload and download files with SCP.
- Manage local `ssh -N -L` port forwards.
- Require confirmation for sudo, writes, deletes, restarts, firewall changes, sensitive paths, and other risky operations.

It is not meant to replace tmux, full-screen TUI programs, long-running unattended sessions, a strong isolation sandbox, or a CI/CD orchestration platform.

## Design Goals

- **Reuse OpenSSH**: use system `ssh` and `scp`, including `~/.ssh/config`, ssh-agent, ProxyJump, known_hosts, hardware keys, and certificates.
- **Prefer structured operations**: expose clear MCP tools and argv-style command execution; keep `ssh_exec` as a shell fallback.
- **Do not store secrets**: inventory files store connection metadata and key paths, not passwords, private key contents, or sudo passwords.
- **Auditable confirmation**: risky operations return `confirmationRequired`; confirmation tokens are bound to host, operation, command/path/ports, expire quickly, and are single-use.
- **Protect returned output**: stdout/stderr are redacted and truncated before being returned.
- **Reuse connections**: use OpenSSH `ControlMaster`, `ControlPath`, and `ControlPersist` automatically.

## Feature Overview

- YAML/JSON host inventory using either `hostname` or `sshConfigHost`.
- Password authentication through `passwordEnv` and `sshpass -e`.
- SSH probes with classified failure reasons.
- Fixed read-only host health checks.
- `ssh_command` for argv-style remote program execution.
- `task_batch` for per-task review, confirmation, and resumable execution.
- `cleanup_paths` for confirming an exact remote path set once.
- Bounded interactive sessions through `session_start`, `session_send`, `session_read`, and `session_stop`.
- SCP transfer through `file_upload` and `file_download`.
- Managed local forwards through `forward_start`, `forward_stop`, and `forward_list`.
- Persistent local state through `host_select`, `host_recent`, and `host_permission_set`.

## Installation

Requirements:

- Node.js `>=20`
- System OpenSSH clients: `ssh`, `scp`
- `sshpass` if password authentication is used

```bash
git clone https://github.com/Da-bai-da/smooth-ssh-mcp.git
cd smooth-ssh-mcp
npm install
npm run build
```

## Host Configuration

Copy the example inventory:

```bash
mkdir -p ~/.config/smooth-ssh-mcp
cp examples/hosts.example.yaml ~/.config/smooth-ssh-mcp/hosts.yaml
chmod 600 ~/.config/smooth-ssh-mcp/hosts.yaml
```

Minimal host:

```yaml
hosts:
  - id: lab-linux
    hostname: 192.0.2.10
    user: ubuntu
    port: 22
    identityFile: ~/.ssh/lab.pem
    environment: dev
    policy:
      permissionLevel: 2
      allowExec: true
      allowPty: true
      allowUpload: true
      allowDownload: true
      allowForward: true
```

Reference a Host from `~/.ssh/config`:

```yaml
hosts:
  - id: gateway
    sshConfigHost: openwrt-gw
    environment: staging
    tags: [openwrt, gateway]
```

Password authentication stores only the environment variable name:

```yaml
hosts:
  - id: password-vps
    hostname: 203.0.113.20
    user: root
    port: 22
    passwordEnv: SMOOTH_SSH_PASSWORD_PASSWORD_VPS
```

Do not put real passwords in `hosts.yaml`. Put them in your MCP client's secret env, or load them through the local wrapper.

## MCP Client Configuration

stdio example:

```json
{
  "mcpServers": {
    "smooth-ssh": {
      "command": "node",
      "args": [
        "/path/to/smooth-ssh-mcp/dist/server.js",
        "--config",
        "/home/you/.config/smooth-ssh-mcp/hosts.yaml"
      ],
      "env": {
        "SMOOTH_SSH_PASSWORD_PASSWORD_VPS": "set-this-in-your-client-secret-env"
      }
    }
  }
}
```

Codex wrapper example:

```toml
[mcp_servers.smooth-ssh]
command = "/path/to/smooth-ssh-mcp/bin/smooth-ssh-mcp-codex"
```

The wrapper reads:

- `SMOOTH_SSH_MCP_CONFIG`, defaulting to `~/.config/smooth-ssh-mcp/hosts.yaml`
- `SMOOTH_SSH_MCP_SECRETS`, defaulting to `~/.config/smooth-ssh-mcp/secrets.env`

`secrets.env` must be owned by the current user and have mode `600` or `400`. The wrapper treats it as `KEY=value` data and does not execute shell code from it.

## Tools

| Tool | Description |
| --- | --- |
| `capability_list` | Lists structured capabilities and the shell fallback policy. |
| `host_list` | Lists host aliases and non-secret metadata. |
| `host_get` | Shows one host without returning passwords or private key contents. |
| `host_select` | Stores the current default host. |
| `host_recent` | Shows the selected host and recently used hosts. |
| `host_permission_set` | Stores a per-host permission level. Setting `1` requires confirmation. |
| `host_connect` | Probes a host and can optionally start an interactive session. |
| `ssh_probe` | Runs a read-only SSH probe and classifies failure reasons. |
| `host_health` | Runs fixed read-only host, load, memory, disk, service, port, Docker, and log checks. |
| `ssh_command` | Executes one remote program using argv-style input. |
| `task_batch` | Runs argv tasks one by one; risky items stop with a resume index. |
| `ssh_exec` | Bounded shell fallback; prefer structured tools. |
| `cleanup_paths` | Deletes exact remote paths or empties exact directories after one confirmation. |
| `session_start` | Starts a bounded interactive SSH session. |
| `session_send` | Sends input to an open session; risky input triggers confirmation. |
| `session_read` | Reads and clears session output. |
| `session_stop` | Stops a managed session. |
| `session_list` | Lists managed sessions. |
| `file_upload` | Uploads a local file through SCP. |
| `file_download` | Downloads a remote file through SCP. |
| `forward_start` | Starts a managed local port forward. |
| `forward_stop` | Stops a managed port forward. |
| `forward_list` | Lists managed port forwards. |

## Permission Levels

Each host can use a numeric permission level:

- `1`: highest privilege. Risky operations are treated as authorized and skip the usual smooth-ssh confirmation layer; hard host switches and disaster command blocks still apply.
- `2`: recommended default. Read-only operations run directly; writes, sudo, restarts, uploads, downloads, and port forwards require confirmation.
- `3`: restricted read-only. Only clearly recognized read-only `exec` operations are allowed; writes, sudo, restarts, uploads, downloads, port forwards, and interactive PTY are rejected.

Set this in `hosts.yaml` as `policy.permissionLevel`, or persist an override with `host_permission_set`.

## Confirmation Flow

Risky operations first return:

```json
{
  "confirmationRequired": true,
  "token": "4f2d...",
  "risk": "high",
  "operation": "exec",
  "preview": {
    "command": "hostname"
  }
}
```

After confirmation, retry the same tool call with `confirmationToken`:

```json
{
  "hostId": "prod-api",
  "command": "hostname",
  "confirmationToken": "4f2d..."
}
```

When `task_batch` is blocked by a risky task, it returns `blocked.resumeFrom`. Retry with the same task list plus `startAt: blocked.resumeFrom` to resume without rerunning completed tasks.

## Bounded Interactive Sessions

`session_start` uses the system `ssh -tt` command over stdin/stdout pipes. It does not use `node-pty`.

Good fits:

- Simple REPLs
- One-off menus
- Commands that need a short-lived working directory or remote context

Poor fits:

- Full-screen TUI programs such as `vim`, `top`, `htop`, or `tmux`
- Programs that require real terminal dimensions, cursor control, or complex ANSI refreshes
- Long-running unattended sessions

Sessions have TTL, idle timeout, maximum session count, and a ring buffer. `session_read` clears the buffer after reading.

## Security Model

`smooth-ssh-mcp` is an accidental-damage prevention and audit layer. It is not a remote shell sandbox.

Default policies include:

- Commands on prod/high-risk hosts require confirmation when they cannot be confidently classified as read-only.
- sudo, writes, complex shell, uploads, downloads, and port forwards require confirmation.
- Commands touching sensitive remote paths such as `.env`, `.ssh`, private keys, `.pem`, `.key`, or `/etc/shadow` are never confirmation-free.
- Downloads from sensitive paths are denied by default.
- SCP remote paths disallow whitespace and shell metacharacters so file transfer cannot become command execution.
- Disaster commands such as `rm -rf /`, `mkfs`, `dd of=...`, reboots, and shutdowns are denied by default.
- sudo passwords are never entered automatically.
- `known_hosts` is not modified automatically.
- `acceptNewHostKey: true` only lets OpenSSH save first-seen host keys; changed host keys are still rejected by OpenSSH.
- Password authentication reads from environment variables only and passes the value to `sshpass -e` through `SSHPASS`.

## State File

`host_select`, `host_recent`, and `host_permission_set` write to:

```text
~/.config/smooth-ssh-mcp/state.json
```

The state file stores only host IDs, timestamps, use counts, use reasons, and permission levels. It does not store passwords, private key paths, session IDs, or shell state.

## Development

```bash
npm test
npm run typecheck
npm run build
```
