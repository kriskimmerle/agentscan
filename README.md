![CI](https://github.com/kriskimmerle/agentscan/actions/workflows/test.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)

# agentscan

**AI Agent Security Posture Scanner** — enumerate all AI coding agents on a machine and map their aggregate permission surface.

Developers run 3-5 AI agents simultaneously. Nobody audits the aggregate. Each agent has different config files, MCP servers, shell access, filesystem scope, and credential exposure. `agentscan` maps them all in one command.

## What It Scans

| Agent | Config Locations | What It Checks |
|-------|-----------------|----------------|
| **Claude Desktop** | `~/Library/Application Support/Claude/` | MCP servers, secrets in config |
| **Claude Code** | `~/.claude/`, `~/.claude.json`, project `.claude/` | Permissions, allowed tools, dangerous flags, MCP |
| **Cursor** | `~/.cursor/`, `~/Library/.../Cursor/` | MCP servers, `.cursorrules` secrets |
| **VS Code** | `~/Library/.../Code/User/` | Copilot, Cline, Continue, Roo Code, MCP |
| **Windsurf** | `~/Library/.../Windsurf/`, `~/.codeium/` | MCP servers, settings |
| **Zed** | `~/.config/zed/` | API keys in config, assistant settings |
| **Codex CLI** | `~/.codex/` | Approval mode, instruction secrets |
| **aider** | `~/.aider.*` | Config secrets, .env files |
| **Moltbot/OpenClaw** | `~/clawd/`, `~/.config/moltbot/` | AGENTS.md, sudo usage, running processes |

## What It Finds

### Per-Agent
- 🔑 **Hardcoded secrets** (API keys, tokens, passwords in config files)
- 🛡️ **MCP server risks** (shell execution, dangerous commands, unvetted packages, filesystem scope)
- ⚡ **Dangerous permissions** (permanently allowed tools, `--dangerously-skip-permissions`, full-auto mode)
- 📂 **Filesystem exposure** (system directory access, sensitive path mounts)
- 🔓 **Credential exposure** (sensitive environment variables passed to MCP servers)

### Cross-Agent
- 📊 **Agent density** (too many agents = too many attack surfaces)
- 🔗 **Shared MCP servers** (same server in multiple agents multiplies risk)
- 🐚 **Shell access concentration** (multiple agents with shell = high blast radius)
- 📈 **Total MCP surface area** (aggregate permission footprint)

## Quick Start

```bash
# Scan everything
python3 agentscan.py

# JSON output
python3 agentscan.py --format json

# Scan specific agents
python3 agentscan.py --agents "claude code" cursor

# CI mode (exit 1 if grade below C)
python3 agentscan.py --ci --threshold C
```

## Example Output

```
agentscan v0.1.0 — AI Agent Security Posture Scanner
Platform: macos | Host: dev-machine.local

SUMMARY
  Agents installed:  4 / 9
  MCP servers:       7
  Findings:          12
  Grade:             D (risk score: 38)

════════════════════════════════════════════════════════════
Claude Desktop
  Config files: 1
  MCP servers:  3
  Findings:     4

  MCP Servers:
    • filesystem ⚠
      Command: npx @modelcontextprotocol/server-filesystem /
      ↳ Full filesystem access — check allowed paths
    • shell ⚠
      Command: npx @anthropic/mcp-shell
      ↳ Direct shell execution — highest risk
    • postgres ⚠
      Command: npx @modelcontextprotocol/server-postgres
      ↳ Database access — production risk
      ↳ Exposes sensitive env vars: DATABASE_URL

  Findings:
    [CRITICAL] Secret in config: OpenAI API key
      Found OpenAI API key pattern in claude_desktop_config.json
      → Move secrets to environment variables or a credential vault
    [HIGH] MCP server 'shell': Direct shell execution
      Direct shell execution — highest risk
      → Review MCP server permissions and scope access minimally
    ...

════════════════════════════════════════════════════════════
CROSS-AGENT FINDINGS
  [HIGH] Multiple agents with shell access: 2
    Agents with shell: Claude Desktop, Cursor
    → Limit shell access to one agent. Use MCP tools for others.
  [MEDIUM] MCP server 'filesystem' shared across agents
    Configured in: Claude Desktop, Cursor
    → Use separate MCP server instances per agent where possible
```

## Grading

| Grade | Risk Score | Meaning |
|-------|-----------|---------|
| **A** | 0 | Clean — no findings |
| **B** | 1-5 | Minor issues (info/low findings only) |
| **C** | 6-15 | Moderate risk (some medium findings) |
| **D** | 16-30 | High risk (high severity findings) |
| **F** | 31+ | Critical risk (secrets exposed, shell everywhere) |

Severity weights: Critical=25, High=10, Medium=3, Low=1, Info=0

## CI Integration

```yaml
# GitHub Actions
- name: Agent Security Audit
  run: python3 agentscan.py --ci --threshold C --format json > agentscan.json
```

```bash
# Pre-commit hook
python3 agentscan.py --ci --threshold B --no-color
```

## Secret Patterns Detected

| Pattern | Description |
|---------|-------------|
| `sk-[a-zA-Z0-9]{48}` | OpenAI API key |
| `sk-proj-*` | OpenAI project key |
| `sk-ant-*` | Anthropic API key |
| `ghp_*` | GitHub PAT (classic) |
| `github_pat_*` | GitHub PAT (fine-grained) |
| `AKIA*` | AWS access key |
| `xox[bpors]-*` | Slack token |
| `glpat-*` | GitLab PAT |
| `SG.*` | SendGrid API key |

## MCP Risk Assessment

The scanner evaluates each MCP server for:

1. **Command risk** — Is the server launched via dangerous commands (bash, sh, docker)?
2. **Package risk** — Is it an unvetted third-party npm package via npx?
3. **Known server risk** — Is it a server type known for broad access (filesystem, shell, database)?
4. **Credential exposure** — Does the server receive sensitive environment variables?
5. **Flag risk** — Are dangerous flags used (--no-sandbox, --dangerously-*)?

## Requirements

- Python 3.9+
- Zero dependencies (stdlib only)
- macOS and Linux supported
- Single file (`agentscan.py`)

## Limitations

- **Config-based scanning only** — agentscan reads config files, not runtime state
- **No network monitoring** — doesn't track what agents actually do at runtime
- **Config location assumptions** — custom config paths may be missed
- **Extension detection** — VS Code extension detection relies on known directory names
- **Credential patterns** — regex-based, can miss obfuscated or rotated secrets

For runtime monitoring, pair with [secure-openclaw-patterns](https://github.com/kriskimmerle/secure-openclaw-patterns).

## Related

- [mcplint](https://github.com/kriskimmerle/mcplint) — MCP configuration security linter (deeper per-file analysis)
- [agentlint](https://github.com/kriskimmerle/agentlint) — AI agent instruction file security auditor
- [secure-openclaw-patterns](https://github.com/kriskimmerle/secure-openclaw-patterns) — Defense-in-depth security patterns
- [agent-security-patterns](https://github.com/kriskimmerle/agent-security-patterns) — Threat model for autonomous AI agents

## License

MIT © 2026 Kris Kimmerle
