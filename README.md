# smooth-ssh-mcp

一个面向 AI 助手的 SSH 连接管理 MCP server。它不是完整终端模拟器，而是把系统 OpenSSH 包成更适合模型调用的连接层：主机别名、连接探测、命令执行、有限交互会话、SCP 文件传输、本地端口转发、安全确认和输出脱敏。

## 特性

- 使用系统 `ssh` / `scp`，兼容 `~/.ssh/config`、ssh-agent、ProxyJump、known_hosts、硬件密钥和证书。
- 支持密码登录：通过 `passwordEnv` 引用进程环境变量，并使用系统 `sshpass -e` 调用 OpenSSH；不把密码写入 `hosts.yaml`。
- 所有本地进程调用使用 argv 数组，`shell: false`。
- OpenSSH `ControlMaster` / `ControlPath` / `ControlPersist` 自动连接复用。
- host inventory 使用 YAML/JSON，只保存连接元数据和私钥路径，不保存密码、私钥内容或 sudo 密码。
- 远程操作优先走结构化能力和 argv 风格命令，`ssh_exec` 只作为 shell 兜底。
- 风险策略覆盖 safety profile、prod、sudo、写操作、未知 argv、复杂 shell、交互输入、文件传输、端口转发和敏感远端路径。
- 确认 token 绑定具体 host、operation、command/path/ports，5 分钟过期且一次性消费。
- stdout/stderr 返回前默认脱敏和截断。

## 安装

```bash
cd /path/to/smooth-ssh-mcp
npm install
npm run build
```

## 配置主机

复制示例：

```bash
mkdir -p ~/.config/smooth-ssh-mcp
cp examples/hosts.example.yaml /home/you/.config/smooth-ssh-mcp/hosts.yaml
chmod 600 /home/you/.config/smooth-ssh-mcp/hosts.yaml
```

也可以启动时指定：

```bash
node dist/server.js --config /path/to/hosts.yaml
```

## MCP 客户端配置

stdio 启动命令：

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
        "SMOOTH_SSH_PASSWORD_VPS_PASSWORD": "set-this-in-your-client-secret-env"
      }
    }
  }
}
```

如果某台主机使用密码登录，在 `hosts.yaml` 中只写环境变量名：

```yaml
hosts:
  - id: vps-password
    hostname: 203.0.113.20
    user: root
    port: 22
    passwordEnv: SMOOTH_SSH_PASSWORD_VPS_PASSWORD
```

然后在 MCP 客户端配置的 `env` 里提供 `SMOOTH_SSH_PASSWORD_VPS_PASSWORD`。运行环境需要安装 `sshpass`。

本机如果使用 wrapper 加载 `~/.config/smooth-ssh-mcp/secrets.env`，文件必须由当前用户拥有，并设置为 `chmod 600` 或 `chmod 400`。wrapper 会拒绝加载权限过宽的 secrets 文件，并只按 `KEY=value` 数据格式导出变量，不执行 secrets 文件中的 shell 代码。

## Tools

- `host_list`：列出主机别名和非敏感元数据。
- `host_get`：查看单个主机配置。
- `host_select`：把某个 hostId 保存为当前默认选择。
- `host_recent`：查看当前选择和最近使用过的主机。
- `host_permission_set`：为某台主机保存数字权限等级：`1` 最高权限，`2` 确认式运维，`3` 只读受限。设置 `1` 会跳过常规确认层，因此必须先通过一次确认。
- `capability_list`：列出结构化能力目录和 shell 兜底策略。
- `host_connect`：一键使用指定或当前选择的主机完成探测；`startSession: true` 时再按策略打开交互会话。对 `tcp` / `timeout` 类瞬时失败会短重试。
- `ssh_probe`：只读连接探测，分类常见 SSH 失败。
- `host_health`：固定只读巡检，覆盖主机、负载、内存、磁盘、服务、端口、Docker 和关键日志。默认返回 compact `summary`；需要原始逐项输出时传 `includeRaw: true` 或 `detail: "full"`。
- `ssh_command`：用 argv 风格执行单个远端程序，避免模型现场拼接 shell 链。
- `task_batch`：把多个 argv 任务逐个执行并逐个审计；默认用 compact 返回，每个任务只保留前 `2048` 字节 stdout/stderr，避免 `find` / `grep` 这类扫描输出撑大 MCP 记录。`outputLimitBytes` 最高 `4096`，扫描任务建议不传或设为 `1024` / `2048`。需要完整输出时传 `detail: "full"`。遇到需要确认的任务会停止并返回 `blocked.index` / `blocked.resumeFrom`；确认后可用同一任务列表加 `startAt: blocked.resumeFrom` 从被阻塞项继续，避免重跑已完成任务。
- `cleanup_paths`：对精确远端路径执行清理；支持删除整个路径或清空目录内容，先返回整组路径预览并用一次确认 token 执行。
- `ssh_exec`：shell 兜底工具，执行有超时和输出上限的远端命令。优先使用上面的结构化工具。
- `session_start` / `session_send` / `session_read` / `session_stop` / `session_list`：有限交互 SSH 会话。
- `file_upload` / `file_download`：通过 SCP 传输文件。
- `forward_start` / `forward_stop` / `forward_list`：托管本地 `ssh -N -L` 端口转发。`forward_start` 可能先返回 `starting`，客户端应再调用 `forward_list` 确认状态。

## 客户端确认边界

MCP tool annotations 已把连接和观察类工具标成低摩擦只读提示：`host_list`、`host_get`、`host_recent`、`capability_list`、`host_connect`、`ssh_probe`、`host_health`、`session_start`、`session_read`、`session_list`、`session_stop`、`forward_list`、`forward_stop`。

这些工具不应因为“连接服务器 / 读取会话 / 查看最近主机”本身要求人工确认。需要确认的边界仍由服务端策略返回 `confirmationRequired`：远端命令执行、风险 `session_send` 输入、上传/下载、开启端口转发、设置 `permissionLevel=1`，以及 sudo、写入、重启、网络/防火墙/SSH 配置、删除、未知高风险 argv、读取敏感远端路径或其他高风险操作。清理多个远端路径时优先使用 `cleanup_paths`，避免逐条 `rm -rf` 反复确认。

## 有限交互会话边界

`session_start` 使用系统 `ssh -tt`，通过 stdin/stdout 管道交互，不使用 `node-pty`。`host_connect` 默认只探测连接，不保留 PTY；需要 shell 时显式传 `startSession: true`。

适合：

- 简单 REPL。
- 一次性菜单。
- 需要保持 cwd 或短期上下文的交互。

不适合：

- `vim`、`top`、`htop`、`tmux` 等全屏 TUI。
- 依赖真实终端尺寸、光标控制或复杂 ANSI 刷新的程序。
- 长时间无人值守会话。

会话有 TTL、idle timeout、最大会话数和 ring buffer。`session_read` 读取后会清空缓冲区。

`session_stop`、远端 shell 自己退出，以及 MCP server 进程退出时，都会停止托管 SSH 子进程并尝试执行 `ssh -O exit` 清理对应 OpenSSH control socket。清理是 best-effort：socket 已经不存在或 master 已退出时会忽略失败。

`session_send` 是已经打开交互会话后的输入通道，会对明显的 sudo、写入、删除、重启、防火墙和敏感路径读取输入做策略确认，但它仍不是完整终端沙箱。敏感或生产主机建议禁用 `allowPty`，自动化操作优先使用 `ssh_exec`，让每次命令都经过更明确的策略判断和确认。

## 确认流程

高风险操作会先返回 `confirmationRequired`，不会直接执行。确认后，用同一个 tool 携带返回的 `confirmationToken` 重试同一操作。

如果 MCP 客户端支持 form elicitation，`ssh_exec`、`ssh_command`、`task_batch`、`cleanup_paths`、风险 `session_send`、`host_permission_set(permissionLevel=1)`、文件传输和端口转发等风险工具会优先弹出“确认执行 / 取消”的选择式确认；选择确认后工具会自动携带 token 重试。`task_batch` 会使用 `blocked.resumeFrom` 自动从被阻塞项继续。客户端不支持选择式确认时，仍返回 `confirmationRequired` 给助手走文字确认 fallback。

示例：

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

批量任务的确认 token 只授权当前被阻塞的具体命令；`task_batch` 会把 token 传给内部 argv 命令，执行到下一个高风险任务时仍会再次停止。被阻塞结果包含 `blocked.resumeFrom`；选择式确认会自动从该索引继续，文字确认 fallback 重试时手动传 `startAt: blocked.resumeFrom` 可避免重跑前面已完成的任务。多路径清理场景应使用 `cleanup_paths`，一次确认绑定整组精确路径。

重试：

```json
{
  "hostId": "prod-api",
  "command": "hostname",
  "confirmationToken": "4f2d..."
}
```

## 主机选择状态

`host_select` / `host_recent` / `host_permission_set` 会把当前选择、最近使用的 hostId 和权限档位保存到：

```text
~/.config/smooth-ssh-mcp/state.json
```

状态文件只保存 hostId、时间戳、使用次数、使用原因和 permission level，不保存密码、私钥路径、sessionId 或 shell 状态。重启 Codex 后，服务器列表、最近选择和权限档位仍然可用，但已经打开的交互 session 不会恢复。

## 安全模型

这个 MCP server 是防误操作和可审计连接层，不是远端 shell 沙箱。默认路径是结构化工具和 argv 风格命令；远端 shell 仍保留为兜底能力，但复杂 shell 语法会按策略确认。

权限等级：

- `1`：最高权限。风险操作视为已授权，跳过 smooth-ssh 的常规确认层；`allowExec` / `allowUpload` 等主机硬开关和内置灾难命令拦截仍然生效。通过 `host_permission_set` 升级到 `1` 本身必须确认。
- `2`：默认推荐。只读操作直接执行；写入、sudo、重启、上传、下载、端口转发等风险操作走确认。
- `3`：只读受限。只允许明确识别的只读 `exec`；写入、sudo、重启、上传、下载、端口转发和交互 PTY 直接拒绝。

可以在 `hosts.yaml` 的 `policy.permissionLevel` 中设置，也可以通过 `host_permission_set` 持久覆盖某台主机的权限等级。权限模型只保留数字等级，配置中不支持未列出的旧策略键。

默认策略：

- 权限 `2` 下 prod 主机执行无法确认只读性的原始 shell 命令需要确认。
- 权限 `2` 下 prod/high-risk 主机执行未知 argv 命令需要确认；优先使用已识别的只读命令或更明确的结构化工具。
- 权限 `2` 下 sudo、写操作、复杂 shell、上传、下载、端口转发需要确认；权限 `1` 下这些操作视为已授权。
- 任意 `exec` / `pty-input` 命令只要引用 `.env`、`.ssh`、私钥、`.pem`、`.key` 或 `/etc/shadow` 等敏感远端路径，就不会免确认。
- 有限白名单形态的只读复杂命令（例如 `ps ... | head`、`grep -RInE ...`）允许直接执行；会执行代码的管道、删除、Docker prune/rm、服务重启、防火墙修改等仍需要确认。
- 下载 `/etc/shadow`、`.ssh`、`.env`、私钥等敏感路径默认拒绝。
- SCP 远端路径禁止空白和 shell 元字符，避免文件传输通道变成命令执行通道。
- `rm -rf /`、`mkfs`、`dd of=...`、重启关机等默认拒绝。
- 不自动输入 sudo 密码。
- 不自动修改 `known_hosts`。
- 可按主机配置 `acceptNewHostKey: true`，让 OpenSSH 对首次连接的保存主机使用 `StrictHostKeyChecking=accept-new`；已变更的 host key 仍会被 OpenSSH 拒绝。
- 不保存密码、私钥内容、sudo 密码；密码认证只从环境变量读取，并通过 `SSHPASS` 传给 `sshpass -e`。
- `session_start` 打开的交互式 PTY 不会逐命令套用 `ssh_exec` 的安全解析；需要审计或高风险操作时优先用 `ssh_exec`。

## 开发

```bash
npm test
npm run typecheck
npm run build
```
