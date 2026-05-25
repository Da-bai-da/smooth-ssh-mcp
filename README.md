# smooth-ssh-mcp

[中文说明](README.zh-CN.md) | [English README](README.en.md)

An MCP server that gives AI assistants a safer, structured way to use OpenSSH.

`smooth-ssh-mcp` wraps the system `ssh` and `scp` clients as a managed connection layer with host aliases, connection probes, argv-style remote commands, bounded interactive sessions, SCP transfer, local port forwards, risk confirmation, and output redaction.

`smooth-ssh-mcp` 是一个面向 AI 助手的 SSH 连接管理 MCP server。它复用系统 OpenSSH，并提供主机别名、连接探测、结构化远端命令、有限交互会话、SCP 文件传输、本地端口转发、风险确认和输出脱敏。

## Documentation

- [中文说明](README.zh-CN.md)
- [English README](README.en.md)

## Quick Start

```bash
git clone https://github.com/Da-bai-da/smooth-ssh-mcp.git
cd smooth-ssh-mcp
npm install
npm run build
```

See the language-specific README for host inventory, MCP client configuration, permission levels, confirmation flow, and security model.

请查看对应语言的 README，了解主机 inventory、MCP 客户端配置、权限等级、确认流程和安全模型。
