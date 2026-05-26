# smooth-ssh-mcp

[English](README.en.md) | [返回主页](README.md)

## 这是什么

`smooth-ssh-mcp` 是一个面向 AI 助手的 SSH 连接管理 MCP server。它把系统 OpenSSH 封装成更适合模型调用的工具层：模型不需要临时拼接复杂 shell，也不需要知道真实密码或私钥内容，就可以通过受控工具完成连接探测、服务器巡检、远端命令、文件传输和端口转发。

它的定位是“防误操作、可审计、适合 AI 调用的 SSH 操作层”，不是远端 shell 沙箱，也不是完整终端模拟器。

## 适合的场景

- 让 Codex、Claude、OpenCode 或其他 MCP client 管理保存好的 SSH 主机。
- 快速查看主机列表、当前默认主机和最近使用记录。
- 探测 SSH 连接失败原因，例如 TCP 不通、超时、认证失败、host key 问题或配置缺失。
- 执行明确的 argv 风格远端命令，减少模型拼接 shell 带来的风险。
- 做只读服务器巡检：系统信息、负载、内存、磁盘、服务、端口、Docker 和关键日志。
- 打开有限交互 SSH 会话，用于短命令、简单菜单、REPL 或需要保留 cwd 的临时上下文。
- 通过 SCP 上传和下载文件。
- 管理本地 `ssh -N -L` 端口转发。
- 对 sudo、写入、删除、重启、防火墙、敏感路径等风险操作做确认。

不适合的场景：替代 tmux、运行全屏 TUI、长期无人值守会话、强隔离安全沙箱，或复杂 CI/CD 编排。

## 核心设计

- **复用 OpenSSH**：使用系统 `ssh` / `scp`，兼容 `~/.ssh/config`、ssh-agent、ProxyJump、known_hosts、硬件密钥和证书。
- **结构化优先**：优先使用 MCP tools 和 argv 风格命令；`ssh_exec` 只是 shell 兜底。
- **不保存秘密**：inventory 保存连接元数据和私钥路径，不保存密码、私钥内容或 sudo 密码。
- **确认可审计**：高风险操作先返回 `confirmationRequired`；确认 token 绑定 host、operation、command/path/ports，短期有效且一次性消费。
- **输出保护**：stdout/stderr 返回前默认脱敏和截断。
- **连接复用**：自动使用 OpenSSH `ControlMaster` / `ControlPath` / `ControlPersist`。

## 功能概览

- YAML/JSON host inventory，支持 `hostname` 或 `sshConfigHost`。
- 密码登录通过 `passwordEnv` 引用环境变量，并使用 `sshpass -e`。
- SSH 探测和失败分类。
- 固定只读健康检查。
- `ssh_command` 执行 argv 风格远端程序。
- `task_batch` 按任务逐个审计，风险项可确认后续跑。
- `cleanup_paths` 对一组精确远端路径做一次确认。
- `session_start` / `session_send` / `session_read` / `session_stop` 管理有限交互会话。
- `file_upload` / `file_download` 通过 SCP 传输文件。
- `forward_start` / `forward_stop` / `forward_list` 管理本地端口转发。
- `host_select` / `host_recent` / `host_permission_set` 持久化本地状态。
- `host_add` / `host_update` / `host_remove` / `secret_set` 通过确认流程管理本地主机配置和 secrets。

## 安装

要求：

- Node.js `>=20`
- 系统 OpenSSH 客户端：`ssh`、`scp`
- 如果使用密码登录，需要安装 `sshpass`

从 GitHub 源码安装：

```bash
git clone https://github.com/Da-bai-da/smooth-ssh-mcp.git
cd smooth-ssh-mcp
npm install
npm run build
node dist/server.js init
node dist/server.js doctor --config ~/.config/smooth-ssh-mcp/hosts.yaml --secrets ~/.config/smooth-ssh-mcp/secrets.env
```

发布到 npm 后也可以全局安装：

```bash
npm install -g smooth-ssh-mcp
smooth-ssh-mcp init
smooth-ssh-mcp doctor --config ~/.config/smooth-ssh-mcp/hosts.yaml --secrets ~/.config/smooth-ssh-mcp/secrets.env
smooth-ssh-mcp --help
smooth-ssh-mcp --version
```

## 初始化配置

推荐先运行 `init` 生成本地配置骨架：

```bash
node dist/server.js init
```

默认写入 `~/.config/smooth-ssh-mcp/hosts.yaml` 和 `~/.config/smooth-ssh-mcp/secrets.env`，目录权限为 `700`，文件权限为 `600`。如果文件已存在，`init` 会保留原文件；需要重新生成时再加 `--force`。

```bash
node dist/server.js init --force
node dist/server.js init --config /path/to/hosts.yaml --secrets /path/to/secrets.env
```

## 配置主机

最小配置示例：

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

引用 `~/.ssh/config` 中的 Host：

```yaml
hosts:
  - id: gateway
    sshConfigHost: openwrt-gw
    environment: staging
    tags: [openwrt, gateway]
```

密码登录只写环境变量名，不写真实密码：

```yaml
hosts:
  - id: password-vps
    hostname: 203.0.113.20
    user: root
    port: 22
    passwordEnv: SMOOTH_SSH_PASSWORD_PASSWORD_VPS
```

真实密码可以放在 MCP client 的 secret env，或用 wrapper 加载本机 secrets 文件。

## Doctor 检查

`doctor` 子命令会检查 Node.js 版本、`ssh`、`scp`、可选的 `sshpass`、inventory 文件、secrets 文件和权限。

```bash
node dist/server.js doctor --config ~/.config/smooth-ssh-mcp/hosts.yaml --secrets ~/.config/smooth-ssh-mcp/secrets.env
node dist/server.js doctor --config ~/.config/smooth-ssh-mcp/hosts.yaml --secrets ~/.config/smooth-ssh-mcp/secrets.env --json
```

## MCP 客户端配置

stdio 示例：

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

Codex wrapper 示例：

```toml
[mcp_servers.smooth-ssh]
command = "/path/to/smooth-ssh-mcp/bin/smooth-ssh-mcp-codex"
```

wrapper 默认读取：

- `SMOOTH_SSH_MCP_CONFIG`，默认 `~/.config/smooth-ssh-mcp/hosts.yaml`
- `SMOOTH_SSH_MCP_SECRETS`，默认 `~/.config/smooth-ssh-mcp/secrets.env`

`secrets.env` 必须属于当前用户，权限必须是 `600` 或 `400`。wrapper 只按 `KEY=value` 数据格式导出变量，不执行 secrets 文件中的 shell 代码。

## Tools

| Tool | 说明 |
| --- | --- |
| `capability_list` | 列出结构化能力和 shell fallback 策略。 |
| `host_list` | 列出主机别名和非敏感元数据。 |
| `host_get` | 查看单个主机配置，不返回密码或私钥内容。 |
| `host_add` | 确认后把主机添加到本地 inventory。密码通过 `passwordEnv` 写入 secrets，不写进 hosts.yaml。 |
| `host_update` | 确认后更新本地 inventory 中的主机。 |
| `host_remove` | 确认后从本地 inventory 删除主机，可选删除对应 secret。 |
| `secret_set` | 确认后向本地 Smooth SSH secrets 文件写入一个 key。 |
| `host_select` | 保存当前默认主机。 |
| `host_recent` | 查看当前选择和最近使用过的主机。 |
| `host_permission_set` | 保存某台主机的权限等级。设置 `1` 需要确认。 |
| `host_connect` | 探测指定或当前主机，可选开启交互会话。 |
| `ssh_probe` | 只读 SSH 连接探测并分类失败原因。 |
| `host_health` | 固定只读巡检：主机、负载、内存、磁盘、服务、端口、Docker、关键日志。 |
| `ssh_command` | 以 argv 风格执行单个远端程序。 |
| `task_batch` | 逐个执行 argv 任务；遇到风险项停止并返回 resume index。 |
| `ssh_exec` | bounded shell fallback，优先使用结构化工具。 |
| `cleanup_paths` | 对一组精确远端路径执行删除或清空目录，使用一次确认。 |
| `session_start` | 开启有限交互 SSH 会话。 |
| `session_send` | 向已打开会话发送输入，风险输入会触发确认。 |
| `session_read` | 读取并清空会话输出缓冲区。 |
| `session_stop` | 停止托管会话。 |
| `session_list` | 列出托管会话。 |
| `file_upload` | 通过 SCP 上传本地文件。 |
| `file_download` | 通过 SCP 下载远端文件。 |
| `forward_start` | 启动托管本地端口转发。 |
| `forward_stop` | 停止托管端口转发。 |
| `forward_list` | 列出托管端口转发。 |

## 权限等级

每台主机可以使用数字权限等级：

- `1`：最高权限。风险操作视为已授权，跳过 smooth-ssh 的常规确认层；主机硬开关和灾难命令拦截仍然生效。
- `2`：默认推荐。只读操作直接执行；写入、sudo、重启、上传、下载、端口转发等风险操作需要确认。
- `3`：只读受限。只允许明确识别的只读 `exec`；写入、sudo、重启、上传、下载、端口转发和交互 PTY 直接拒绝。

可以在 `hosts.yaml` 的 `policy.permissionLevel` 中设置，也可以通过 `host_permission_set` 持久覆盖。

## 确认流程

高风险操作会先返回：

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

确认后，用同一个 tool 携带 `confirmationToken` 重试同一操作：

```json
{
  "hostId": "prod-api",
  "command": "hostname",
  "confirmationToken": "4f2d..."
}
```

`task_batch` 被风险任务阻塞时会返回 `blocked.resumeFrom`。确认后使用同一任务列表加 `startAt: blocked.resumeFrom`，可以从阻塞项继续，避免重跑已完成任务。

## 有限交互会话边界

`session_start` 使用系统 `ssh -tt` 和 stdin/stdout 管道，不使用 `node-pty`。

适合：

- 简单 REPL
- 一次性菜单
- 需要保持 cwd 或短期上下文的命令

不适合：

- `vim`、`top`、`htop`、`tmux` 等全屏 TUI
- 依赖真实终端尺寸、光标控制或复杂 ANSI 刷新的程序
- 长时间无人值守会话

会话有 TTL、idle timeout、最大会话数和 ring buffer。`session_read` 读取后会清空缓冲区。

## 安全模型

`smooth-ssh-mcp` 是防误操作和可审计连接层，不是远端 shell 沙箱。

默认策略包括：

- prod/high-risk 主机执行无法确认只读性的命令会要求确认。
- sudo、写操作、复杂 shell、上传、下载、端口转发会要求确认。
- 涉及 `.env`、`.ssh`、私钥、`.pem`、`.key`、`/etc/shadow` 等敏感远端路径的命令不会免确认。
- 下载敏感路径默认拒绝。
- SCP 远端路径禁止空白和 shell 元字符，避免文件传输变成命令执行通道。
- `rm -rf /`、`mkfs`、`dd of=...`、重启关机等灾难命令默认拒绝。
- 不自动输入 sudo 密码。
- 不自动修改 `known_hosts`。
- `acceptNewHostKey: true` 只允许 OpenSSH 对首次连接保存新 host key；已变更的 host key 仍由 OpenSSH 拒绝。
- 密码认证只从环境变量读取，并通过 `SSHPASS` 传给 `sshpass -e`。

## 审计日志

运行 MCP server 时默认写入 JSONL 审计日志：

```text
~/.config/smooth-ssh-mcp/audit.jsonl
```

审计记录包含 tool 名称、hostId、operation、结果类型、退出码、耗时、截断状态和脱敏统计。`confirmationToken`、`env`、`stdin`、密码和 secret 字段会被写成 `[REDACTED]`。

可通过环境变量调整：

```bash
SMOOTH_SSH_MCP_AUDIT=0 smooth-ssh-mcp
SMOOTH_SSH_MCP_AUDIT_LOG=/path/to/audit.jsonl smooth-ssh-mcp
```

## 状态文件

`host_select`、`host_recent`、`host_permission_set` 会写入：

```text
~/.config/smooth-ssh-mcp/state.json
```

状态文件只保存 hostId、时间戳、使用次数、使用原因和 permission level，不保存密码、私钥路径、sessionId 或 shell 状态。

## 开发

```bash
npm test
npm run typecheck
npm run build
npm run test:cli
npm pack --dry-run
```

GitHub Actions 会在 push 和 pull request 上运行 `npm ci`、`npm run typecheck`、`npm test`、`npm run build`、CLI smoke test 和 `npm pack --dry-run`。
