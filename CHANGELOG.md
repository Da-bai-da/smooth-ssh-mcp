# Changelog

## 0.1.4 - 2026-06-01

- Breaking: renamed the local MCP client wrapper from `smooth-ssh-mcp-codex` to `smooth-ssh-mcp-local`.
- Exposed `smooth-ssh-mcp-local` as an npm bin for stable global npm installs.
- Updated client configuration examples to use the client-neutral local wrapper name.
- Strengthened release checks to reject the old wrapper name in package metadata and tarball contents.

## 0.1.3 - 2026-05-27

- Added a unified `npm run release:check` command for release readiness validation.
- Updated CI to run the same release check on Node.js 20 and 24.
- Added package metadata, CLI version, executable bit, and npm package content checks before release.
- Documented the release check workflow in English and Chinese README files.

## 0.1.2 - 2026-05-26

- Added confirmed host configuration management tools: `host_add`, `host_update`, `host_remove`, and `secret_set`.
- Added version metadata support for CLI and MCP server responses.
- Updated audit redaction and policy handling for configuration operations.

## 0.1.1 - 2026-05-26

- Fixed CLI execution through npm global bin symlinks.

## 0.1.0 - 2026-05-26

- Initial public release.
