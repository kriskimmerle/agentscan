#!/usr/bin/env python3
"""agentscan — AI Agent Security Posture Scanner

Enumerate all AI coding agents on a machine. Map permissions, MCP servers,
credential exposure, shell access, filesystem access for each. Unified risk report.

Supported agents:
  - Claude Desktop (macOS/Linux/Windows)
  - Claude Code CLI (~/.claude/, .claude/ per-project)
  - Cursor (~/.cursor/, project .cursorrules)
  - VS Code + Copilot / Cline / Continue / Roo Code
  - Windsurf (Codeium)
  - Zed
  - Codex CLI
  - Aider

Zero dependencies. Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


__version__ = "0.1.0"

# ─── Data Structures ────────────────────────────────────────────────


@dataclass
class MCPServer:
    """Represents a configured MCP server."""
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    risks: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A security finding for an agent."""
    severity: str  # critical, high, medium, low, info
    category: str  # permissions, credentials, mcp, filesystem, network, shell
    title: str
    detail: str
    remediation: str = ""


@dataclass
class AgentReport:
    """Security report for a single agent."""
    name: str
    version: str = ""
    installed: bool = False
    config_paths: list[str] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    permissions: dict[str, Any] = field(default_factory=dict)
    raw_config: dict[str, Any] = field(default_factory=dict)


# ─── Platform Helpers ────────────────────────────────────────────────


def get_platform() -> str:
    """Return normalized platform name."""
    s = platform.system()
    if s == "Darwin":
        return "macos"
    elif s == "Linux":
        return "linux"
    elif s == "Windows":
        return "windows"
    return s.lower()


def expand_path(path: str) -> Path:
    """Expand ~ and environment variables in path."""
    return Path(os.path.expandvars(os.path.expanduser(path)))


def get_app_support_dir() -> Path:
    """Get the platform-specific application support directory."""
    plat = get_platform()
    if plat == "macos":
        return Path.home() / "Library" / "Application Support"
    elif plat == "linux":
        return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    elif plat == "windows":
        return Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return Path.home() / ".config"


def read_json(path: Path) -> dict | None:
    """Safely read a JSON file, handling JSONC (comments)."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        # Strip single-line comments (// ...)
        text = re.sub(r'//[^\n]*', '', text)
        # Strip multi-line comments (/* ... */)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        # Handle trailing commas (common in JSONC)
        text = re.sub(r',\s*([}\]])', r'\1', text)
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return None


def run_cmd(cmd: list[str], timeout: int = 5) -> str | None:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


# ─── Secret Detection ────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
    (r'sk-proj-[a-zA-Z0-9_-]{48,}', "OpenAI project key"),
    (r'sk-ant-[a-zA-Z0-9_-]{20,}', "Anthropic API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT (classic)"),
    (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub PAT (fine-grained)"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth token"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'xox[bpors]-[a-zA-Z0-9-]+', "Slack token"),
    (r'glpat-[a-zA-Z0-9_-]{20}', "GitLab PAT"),
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API key"),
]

SENSITIVE_ENV_VARS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "SLACK_TOKEN", "SLACK_BOT_TOKEN",
    "DATABASE_URL", "DB_PASSWORD", "REDIS_URL",
    "STRIPE_SECRET_KEY", "SENDGRID_API_KEY",
    "NPM_TOKEN", "PYPI_TOKEN",
    "SSH_PRIVATE_KEY", "PRIVATE_KEY",
}


def scan_for_secrets(text: str) -> list[str]:
    """Scan text for known secret patterns. Returns list of descriptions."""
    found = []
    for pattern, desc in SECRET_PATTERNS:
        if re.search(pattern, text):
            found.append(desc)
    return found


def check_env_exposure(env_dict: dict[str, str]) -> list[str]:
    """Check environment variables for sensitive values."""
    exposed = []
    for key in env_dict:
        if key.upper() in SENSITIVE_ENV_VARS:
            exposed.append(key)
        # Check values for secrets
        val = env_dict.get(key, "")
        secrets = scan_for_secrets(val)
        if secrets:
            exposed.append(f"{key} (contains {secrets[0]})")
    return exposed


# ─── MCP Analysis ────────────────────────────────────────────────────

DANGEROUS_MCP_COMMANDS = {
    "npx": "Executes npm packages (potential supply chain risk)",
    "node": "Runs arbitrary JavaScript",
    "python": "Runs arbitrary Python",
    "python3": "Runs arbitrary Python",
    "bash": "Runs arbitrary shell commands",
    "sh": "Runs arbitrary shell commands",
    "docker": "Docker access (container escape risk)",
    "kubectl": "Kubernetes access",
    "ssh": "Remote shell access",
}

KNOWN_RISKY_MCP_SERVERS = {
    "filesystem": "Full filesystem access — check allowed paths",
    "everything": "Broad tool access — review scope",
    "puppeteer": "Browser automation — can access any URL",
    "playwright": "Browser automation — can access any URL",
    "sqlite": "Database access — check which databases",
    "postgres": "Database access — production risk",
    "mysql": "Database access — production risk",
    "shell": "Direct shell execution — highest risk",
    "terminal": "Terminal access — highest risk",
    "exec": "Command execution — highest risk",
}


def analyze_mcp_server(name: str, config: dict) -> MCPServer:
    """Analyze an MCP server configuration for risks."""
    command = config.get("command", "")
    args = config.get("args", [])
    env = config.get("env", {})
    url = config.get("url", "")
    risks = []

    # Check command
    cmd_base = Path(command).name if command else ""
    if cmd_base in DANGEROUS_MCP_COMMANDS:
        risks.append(f"Uses {cmd_base}: {DANGEROUS_MCP_COMMANDS[cmd_base]}")

    # Check for known risky servers
    name_lower = name.lower()
    for risky_name, desc in KNOWN_RISKY_MCP_SERVERS.items():
        if risky_name in name_lower:
            risks.append(desc)

    # Check env for secrets
    exposed = check_env_exposure(env)
    if exposed:
        risks.append(f"Exposes sensitive env vars: {', '.join(exposed)}")

    # Check args for suspicious patterns
    args_str = " ".join(str(a) for a in args)
    if "--dangerously" in args_str or "--no-sandbox" in args_str:
        risks.append("Uses dangerous flags (sandbox disabled)")
    if "/etc/" in args_str or "/var/" in args_str:
        risks.append("Accesses system directories")

    # Check for unvetted npm packages via npx
    if cmd_base == "npx" and args:
        pkg = args[0] if args else ""
        if pkg.startswith("-"):
            pkg = args[1] if len(args) > 1 else ""
        if pkg and not pkg.startswith("@anthropic") and not pkg.startswith("@modelcontextprotocol"):
            risks.append(f"Runs third-party npm package: {pkg}")

    return MCPServer(
        name=name, command=command, args=args, env=env, url=url, risks=risks
    )


# ─── Agent Scanners ─────────────────────────────────────────────────


def scan_claude_desktop() -> AgentReport:
    """Scan Claude Desktop for macOS/Linux/Windows."""
    report = AgentReport(name="Claude Desktop")
    app_support = get_app_support_dir()

    # Find config
    config_path = app_support / "Claude" / "claude_desktop_config.json"
    if not config_path.exists():
        # Also check lowercase
        config_path = app_support / "claude" / "claude_desktop_config.json"

    if not config_path.exists():
        return report

    report.installed = True
    report.config_paths.append(str(config_path))

    config = read_json(config_path)
    if not config:
        report.findings.append(Finding(
            severity="medium", category="config",
            title="Config file unreadable",
            detail=f"Could not parse {config_path}",
        ))
        return report

    report.raw_config = config

    # Scan MCP servers
    mcp_servers = config.get("mcpServers", {})
    for name, srv_config in mcp_servers.items():
        server = analyze_mcp_server(name, srv_config)
        report.mcp_servers.append(server)
        for risk in server.risks:
            report.findings.append(Finding(
                severity="high" if "shell" in risk.lower() or "execution" in risk.lower() else "medium",
                category="mcp",
                title=f"MCP server '{name}': {risk.split(':')[0]}",
                detail=risk,
                remediation="Review MCP server permissions and scope access minimally",
            ))

    # Check for sensitive data in config
    config_text = json.dumps(config)
    secrets = scan_for_secrets(config_text)
    for secret in secrets:
        report.findings.append(Finding(
            severity="critical", category="credentials",
            title=f"Secret in config: {secret}",
            detail=f"Found {secret} pattern in {config_path}",
            remediation="Move secrets to environment variables or a credential vault",
        ))

    return report


def scan_claude_code() -> AgentReport:
    """Scan Claude Code CLI configuration."""
    report = AgentReport(name="Claude Code")

    # Check if installed
    version = run_cmd(["claude", "--version"])
    if version:
        report.installed = True
        report.version = version

    # Check global config
    claude_json = Path.home() / ".claude.json"
    if claude_json.exists():
        report.config_paths.append(str(claude_json))
        config = read_json(claude_json)
        if config:
            report.raw_config["global"] = config

    # Check settings
    claude_dir = Path.home() / ".claude"
    settings_files = [
        claude_dir / "settings.json",
        claude_dir / "settings.local.json",
    ]
    for sf in settings_files:
        if sf.exists():
            report.config_paths.append(str(sf))
            settings = read_json(sf)
            if settings:
                report.raw_config[sf.name] = settings

                # Check for allowed tools (dangerous permissions)
                allowed = settings.get("permissions", {}).get("allow", [])
                if allowed:
                    report.permissions["allowed_tools"] = allowed
                    for tool in allowed:
                        if isinstance(tool, str):
                            if "Bash" in tool or "bash" in tool:
                                report.findings.append(Finding(
                                    severity="high", category="shell",
                                    title="Bash execution permanently allowed",
                                    detail=f"Tool '{tool}' is in permanent allow list",
                                    remediation="Remove from allow list; use per-session approval",
                                ))
                            if "mcp__" in tool:
                                report.findings.append(Finding(
                                    severity="medium", category="mcp",
                                    title=f"MCP tool permanently allowed: {tool}",
                                    detail=f"Tool '{tool}' is in permanent allow list",
                                    remediation="Review if permanent access is necessary",
                                ))

                # Check denied tools
                denied = settings.get("permissions", {}).get("deny", [])
                if denied:
                    report.permissions["denied_tools"] = denied

    # Check for dangerously-skip-permissions in history/scripts
    history = claude_dir / "history.jsonl"
    if history.exists():
        report.config_paths.append(str(history))
        try:
            text = history.read_text(errors="replace")
            if "--dangerously-skip-permissions" in text:
                report.findings.append(Finding(
                    severity="high", category="permissions",
                    title="dangerously-skip-permissions used",
                    detail="Found --dangerously-skip-permissions in Claude Code history",
                    remediation="Avoid using --dangerously-skip-permissions outside containers",
                ))
        except OSError:
            pass

    # Check project-level configs
    projects_dir = claude_dir / "projects"
    if projects_dir.exists():
        for proj_settings in projects_dir.rglob("settings.json"):
            report.config_paths.append(str(proj_settings))
            ps = read_json(proj_settings)
            if ps:
                allowed = ps.get("permissions", {}).get("allow", [])
                if allowed:
                    report.findings.append(Finding(
                        severity="medium", category="permissions",
                        title=f"Project-level permissions: {proj_settings.parent.name}",
                        detail=f"Allowed tools: {allowed}",
                    ))

    if report.config_paths:
        report.installed = True

    return report


def scan_cursor() -> AgentReport:
    """Scan Cursor editor configuration."""
    report = AgentReport(name="Cursor")
    app_support = get_app_support_dir()

    # Cursor stores settings similar to VS Code
    cursor_dirs = [
        app_support / "Cursor" / "User",
        Path.home() / ".cursor",
    ]

    for d in cursor_dirs:
        settings_path = d / "settings.json"
        if settings_path.exists():
            report.installed = True
            report.config_paths.append(str(settings_path))
            settings = read_json(settings_path)
            if settings:
                report.raw_config[str(settings_path)] = settings

                # Check AI-related settings
                if settings.get("cursor.general.enableShadowWorkspace"):
                    report.findings.append(Finding(
                        severity="medium", category="permissions",
                        title="Shadow workspace enabled",
                        detail="Cursor can create hidden workspaces for agent operations",
                    ))

                # Check for MCP servers (Cursor supports MCP)
                mcp_config = settings.get("mcpServers", {})
                if not mcp_config:
                    # Also check nested paths
                    mcp_config = settings.get("cursor", {}).get("mcpServers", {})
                for name, srv_config in mcp_config.items():
                    server = analyze_mcp_server(name, srv_config)
                    report.mcp_servers.append(server)
                    for risk in server.risks:
                        report.findings.append(Finding(
                            severity="high" if "shell" in risk.lower() else "medium",
                            category="mcp",
                            title=f"Cursor MCP '{name}': {risk.split(':')[0]}",
                            detail=risk,
                        ))

    # Check for .cursorrules files in common project locations
    home = Path.home()
    for candidate in [home / "Projects", home / "Developer", home / "code", home / "src"]:
        if candidate.exists():
            for rules_file in candidate.rglob(".cursorrules"):
                report.config_paths.append(str(rules_file))
                try:
                    text = rules_file.read_text(errors="replace")
                    secrets = scan_for_secrets(text)
                    if secrets:
                        report.findings.append(Finding(
                            severity="critical", category="credentials",
                            title=f"Secret in .cursorrules: {secrets[0]}",
                            detail=f"Found in {rules_file}",
                            remediation="Remove secrets from instruction files",
                        ))
                except OSError:
                    pass

    # Check for Cursor MCP config file
    cursor_mcp = Path.home() / ".cursor" / "mcp.json"
    if cursor_mcp.exists():
        report.config_paths.append(str(cursor_mcp))
        mcp_data = read_json(cursor_mcp)
        if mcp_data:
            report.raw_config["mcp.json"] = mcp_data
            servers = mcp_data.get("mcpServers", {})
            for name, srv_config in servers.items():
                server = analyze_mcp_server(name, srv_config)
                report.mcp_servers.append(server)
                for risk in server.risks:
                    report.findings.append(Finding(
                        severity="high" if "shell" in risk.lower() else "medium",
                        category="mcp",
                        title=f"Cursor MCP '{name}': {risk.split(':')[0]}",
                        detail=risk,
                    ))

    return report


def scan_vscode() -> AgentReport:
    """Scan VS Code and extensions (Copilot, Cline, Continue, Roo Code)."""
    report = AgentReport(name="VS Code + Extensions")
    app_support = get_app_support_dir()

    vscode_user = app_support / "Code" / "User"
    settings_path = vscode_user / "settings.json"

    if not settings_path.exists():
        return report

    report.installed = True
    report.config_paths.append(str(settings_path))
    settings = read_json(settings_path) or {}
    report.raw_config["settings"] = settings

    # Check GitHub Copilot settings
    copilot_enable = settings.get("github.copilot.enable", {})
    if copilot_enable:
        report.permissions["copilot_languages"] = copilot_enable

    # Check for MCP servers in VS Code settings
    mcp_config = settings.get("mcpServers", {})
    for name, srv_config in mcp_config.items():
        server = analyze_mcp_server(name, srv_config)
        report.mcp_servers.append(server)
        for risk in server.risks:
            report.findings.append(Finding(
                severity="medium", category="mcp",
                title=f"VS Code MCP '{name}': {risk.split(':')[0]}",
                detail=risk,
            ))

    # Check Cline settings
    cline_dir = vscode_user / "globalStorage" / "saoudrizwan.claude-dev"
    if cline_dir.exists():
        report.findings.append(Finding(
            severity="info", category="permissions",
            title="Cline extension installed",
            detail=f"Cline config at {cline_dir}",
        ))
        cline_settings = cline_dir / "settings" / "cline_mcp_settings.json"
        if cline_settings.exists():
            report.config_paths.append(str(cline_settings))
            cs = read_json(cline_settings)
            if cs:
                for name, srv_config in cs.get("mcpServers", {}).items():
                    server = analyze_mcp_server(name, srv_config)
                    report.mcp_servers.append(server)
                    for risk in server.risks:
                        report.findings.append(Finding(
                            severity="medium", category="mcp",
                            title=f"Cline MCP '{name}': {risk.split(':')[0]}",
                            detail=risk,
                        ))

    # Check Continue extension
    continue_dir = vscode_user / "globalStorage" / "continue.continue"
    if continue_dir.exists():
        report.findings.append(Finding(
            severity="info", category="permissions",
            title="Continue extension installed",
            detail=f"Continue config at {continue_dir}",
        ))
    # Also check ~/.continue/
    continue_home = Path.home() / ".continue"
    if continue_home.exists():
        config_json = continue_home / "config.json"
        if config_json.exists():
            report.config_paths.append(str(config_json))
            cc = read_json(config_json)
            if cc:
                # Continue allows custom commands
                custom_cmds = cc.get("customCommands", [])
                if custom_cmds:
                    report.findings.append(Finding(
                        severity="medium", category="shell",
                        title="Continue: custom commands configured",
                        detail=f"{len(custom_cmds)} custom command(s)",
                    ))

    # Check Roo Code
    roo_dir = vscode_user / "globalStorage" / "rooveterinaryinc.roo-cline"
    if roo_dir.exists():
        report.findings.append(Finding(
            severity="info", category="permissions",
            title="Roo Code extension installed",
            detail=f"Roo Code config at {roo_dir}",
        ))

    # Check for secrets in settings
    settings_text = json.dumps(settings)
    secrets = scan_for_secrets(settings_text)
    for secret in secrets:
        report.findings.append(Finding(
            severity="critical", category="credentials",
            title=f"Secret in VS Code settings: {secret}",
            detail=f"Found in {settings_path}",
            remediation="Move secrets to environment variables",
        ))

    return report


def scan_windsurf() -> AgentReport:
    """Scan Windsurf (Codeium) editor."""
    report = AgentReport(name="Windsurf")
    app_support = get_app_support_dir()

    windsurf_user = app_support / "Windsurf" / "User"
    settings_path = windsurf_user / "settings.json"

    if not settings_path.exists():
        return report

    report.installed = True
    report.config_paths.append(str(settings_path))
    settings = read_json(settings_path) or {}
    report.raw_config["settings"] = settings

    # Check for MCP servers
    mcp_config = settings.get("mcpServers", {})
    for name, srv_config in mcp_config.items():
        server = analyze_mcp_server(name, srv_config)
        report.mcp_servers.append(server)
        for risk in server.risks:
            report.findings.append(Finding(
                severity="medium", category="mcp",
                title=f"Windsurf MCP '{name}': {risk.split(':')[0]}",
                detail=risk,
            ))

    # Windsurf MCP config
    ws_mcp = Path.home() / ".codeium" / "windsurf" / "mcp_config.json"
    if ws_mcp.exists():
        report.config_paths.append(str(ws_mcp))
        mcp_data = read_json(ws_mcp)
        if mcp_data:
            for name, srv_config in mcp_data.get("mcpServers", {}).items():
                server = analyze_mcp_server(name, srv_config)
                report.mcp_servers.append(server)
                for risk in server.risks:
                    report.findings.append(Finding(
                        severity="medium", category="mcp",
                        title=f"Windsurf MCP '{name}': {risk.split(':')[0]}",
                        detail=risk,
                    ))

    return report


def scan_zed() -> AgentReport:
    """Scan Zed editor."""
    report = AgentReport(name="Zed")

    config_path = Path.home() / ".config" / "zed" / "settings.json"
    if not config_path.exists():
        return report

    report.installed = True
    report.config_paths.append(str(config_path))
    settings = read_json(config_path) or {}
    report.raw_config["settings"] = settings

    # Check assistant config
    assistant = settings.get("assistant", {})
    if assistant:
        report.permissions["assistant"] = assistant

    # Check language model providers
    lm = settings.get("language_models", {})
    if lm:
        for provider, pconfig in lm.items():
            if isinstance(pconfig, dict) and pconfig.get("api_key"):
                report.findings.append(Finding(
                    severity="critical", category="credentials",
                    title=f"API key in Zed config: {provider}",
                    detail=f"Hardcoded API key for {provider} in settings.json",
                    remediation="Use environment variables instead of hardcoded keys",
                ))

    return report


def scan_codex() -> AgentReport:
    """Scan OpenAI Codex CLI."""
    report = AgentReport(name="Codex CLI")

    # Check if installed
    version = run_cmd(["codex", "--version"])
    if version:
        report.installed = True
        report.version = version

    # Check config
    codex_config = Path.home() / ".codex" / "config.json"
    if codex_config.exists():
        report.installed = True
        report.config_paths.append(str(codex_config))
        config = read_json(codex_config)
        if config:
            report.raw_config["config"] = config

            # Check approval mode
            mode = config.get("approvalMode", "suggest")
            report.permissions["approval_mode"] = mode
            if mode == "full-auto":
                report.findings.append(Finding(
                    severity="high", category="permissions",
                    title="Codex in full-auto mode",
                    detail="Commands execute without human approval",
                    remediation="Use 'suggest' or 'auto-edit' mode for safer operation",
                ))

    # Also check for codex instructions
    codex_instructions = Path.home() / ".codex" / "instructions.md"
    if codex_instructions.exists():
        report.config_paths.append(str(codex_instructions))
        try:
            text = codex_instructions.read_text(errors="replace")
            secrets = scan_for_secrets(text)
            if secrets:
                report.findings.append(Finding(
                    severity="critical", category="credentials",
                    title=f"Secret in Codex instructions: {secrets[0]}",
                    detail=f"Found in {codex_instructions}",
                ))
        except OSError:
            pass

    return report


def scan_aider() -> AgentReport:
    """Scan aider configuration."""
    report = AgentReport(name="aider")

    # Check if installed
    version = run_cmd(["aider", "--version"])
    if version:
        report.installed = True
        report.version = version

    # Check config files
    for config_name in [".aider.conf.yml", ".aider.model.settings.yml"]:
        config_path = Path.home() / config_name
        if config_path.exists():
            report.installed = True
            report.config_paths.append(str(config_path))
            try:
                text = config_path.read_text(errors="replace")
                secrets = scan_for_secrets(text)
                if secrets:
                    report.findings.append(Finding(
                        severity="critical", category="credentials",
                        title=f"Secret in aider config: {secrets[0]}",
                        detail=f"Found in {config_path}",
                    ))
            except OSError:
                pass

    # Check .env for aider
    env_path = Path.home() / ".aider.env"
    if env_path.exists():
        report.config_paths.append(str(env_path))
        try:
            text = env_path.read_text(errors="replace")
            secrets = scan_for_secrets(text)
            if secrets:
                report.findings.append(Finding(
                    severity="high", category="credentials",
                    title=f"Secret in .aider.env: {secrets[0]}",
                    detail=f"Found in {env_path}",
                    remediation="Use a credential vault instead of .env files",
                ))
        except OSError:
            pass

    return report


def scan_moltbot() -> AgentReport:
    """Scan Moltbot/OpenClaw/Clawd configuration."""
    report = AgentReport(name="Moltbot/OpenClaw")

    # Check common locations
    config_paths = [
        Path.home() / ".config" / "moltbot" / "config.yaml",
        Path.home() / ".config" / "moltbot" / "config.json",
        Path.home() / ".moltbot.yaml",
        Path.home() / ".moltbot.json",
    ]

    for cp in config_paths:
        if cp.exists():
            report.installed = True
            report.config_paths.append(str(cp))

    # Check for clawd workspace
    clawd_dir = Path.home() / "clawd"
    if clawd_dir.exists():
        report.installed = True
        agents_md = clawd_dir / "AGENTS.md"
        if agents_md.exists():
            report.config_paths.append(str(agents_md))
            try:
                text = agents_md.read_text(errors="replace")
                if "sudo" in text.lower():
                    report.findings.append(Finding(
                        severity="high", category="permissions",
                        title="Agent instructions mention sudo",
                        detail=f"Found 'sudo' in {agents_md}",
                        remediation="Avoid granting agents sudo access",
                    ))
                secrets = scan_for_secrets(text)
                if secrets:
                    report.findings.append(Finding(
                        severity="critical", category="credentials",
                        title=f"Secret in AGENTS.md: {secrets[0]}",
                        detail=f"Found in {agents_md}",
                    ))
            except OSError:
                pass

    # Check if moltbot is running
    running = run_cmd(["pgrep", "-f", "moltbot"])
    if running:
        report.findings.append(Finding(
            severity="info", category="permissions",
            title="Moltbot process running",
            detail=f"PID(s): {running}",
        ))

    return report


# ─── Aggregate Analysis ─────────────────────────────────────────────


def aggregate_findings(reports: list[AgentReport]) -> list[Finding]:
    """Generate cross-agent findings."""
    findings = []

    installed = [r for r in reports if r.installed]
    if len(installed) > 3:
        findings.append(Finding(
            severity="medium", category="permissions",
            title=f"High agent density: {len(installed)} agents installed",
            detail=f"Agents: {', '.join(r.name for r in installed)}. "
                   "Each agent is an independent attack surface.",
            remediation="Audit whether all agents are actively used. Remove unused ones.",
        ))

    # Check for overlapping MCP servers
    mcp_by_name: dict[str, list[str]] = {}
    for r in installed:
        for srv in r.mcp_servers:
            mcp_by_name.setdefault(srv.name, []).append(r.name)
    for name, agents in mcp_by_name.items():
        if len(agents) > 1:
            findings.append(Finding(
                severity="medium", category="mcp",
                title=f"MCP server '{name}' shared across agents",
                detail=f"Configured in: {', '.join(agents)}. "
                       "Shared MCP servers multiply attack surface.",
                remediation="Use separate MCP server instances per agent where possible",
            ))

    # Count total MCP servers
    total_mcp = sum(len(r.mcp_servers) for r in installed)
    if total_mcp > 10:
        findings.append(Finding(
            severity="high", category="mcp",
            title=f"Large MCP surface area: {total_mcp} servers total",
            detail="Each MCP server is an attack surface. "
                   "Combined, they create a large permission surface.",
            remediation="Audit each MCP server. Remove unused ones.",
        ))

    # Check for shell access across agents
    shell_agents = []
    for r in installed:
        for f in r.findings:
            if f.category == "shell" or "shell" in f.title.lower() or "bash" in f.title.lower():
                if r.name not in shell_agents:
                    shell_agents.append(r.name)
    if len(shell_agents) > 1:
        findings.append(Finding(
            severity="high", category="shell",
            title=f"Multiple agents with shell access: {len(shell_agents)}",
            detail=f"Agents with shell: {', '.join(shell_agents)}. "
                   "Each agent with shell access can execute arbitrary commands.",
            remediation="Limit shell access to one agent. Use MCP tools for others.",
        ))

    return findings


# ─── Scoring ─────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}


def calculate_grade(findings: list[Finding]) -> tuple[str, int]:
    """Calculate security grade from findings."""
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    if score == 0:
        return "A", score
    elif score <= 5:
        return "B", score
    elif score <= 15:
        return "C", score
    elif score <= 30:
        return "D", score
    else:
        return "F", score


# ─── Output Formatting ──────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[91m",  # Red
    "high": "\033[93m",      # Yellow
    "medium": "\033[33m",    # Dark yellow
    "low": "\033[36m",       # Cyan
    "info": "\033[90m",      # Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"

GRADE_COLORS = {
    "A": "\033[92m", "B": "\033[93m", "C": "\033[33m",
    "D": "\033[91m", "F": "\033[91m",
}


def format_text(reports: list[AgentReport], aggregate: list[Finding], no_color: bool = False) -> str:
    """Format results as human-readable text."""
    lines = []

    if no_color:
        sev_c = {k: "" for k in SEVERITY_COLORS}
        grade_c = {k: "" for k in GRADE_COLORS}
        reset = bold = ""
    else:
        sev_c = SEVERITY_COLORS
        grade_c = GRADE_COLORS
        reset = RESET
        bold = BOLD

    lines.append(f"{bold}agentscan v{__version__} — AI Agent Security Posture Scanner{reset}")
    lines.append(f"Platform: {get_platform()} | Host: {platform.node()}")
    lines.append("")

    # Summary
    installed = [r for r in reports if r.installed]
    total_findings = sum(len(r.findings) for r in reports) + len(aggregate)
    total_mcp = sum(len(r.mcp_servers) for r in reports)

    lines.append(f"{bold}SUMMARY{reset}")
    lines.append(f"  Agents installed:  {len(installed)} / {len(reports)}")
    lines.append(f"  MCP servers:       {total_mcp}")
    lines.append(f"  Findings:          {total_findings}")

    all_findings = []
    for r in reports:
        all_findings.extend(r.findings)
    all_findings.extend(aggregate)
    grade, score = calculate_grade(all_findings)
    lines.append(f"  Grade:             {grade_c.get(grade, '')}{grade}{reset} (risk score: {score})")
    lines.append("")

    # Per-agent reports
    for report in reports:
        if not report.installed:
            continue

        lines.append(f"{bold}{'═' * 60}{reset}")
        lines.append(f"{bold}{report.name}{reset}" +
                      (f" v{report.version}" if report.version else ""))
        lines.append(f"  Config files: {len(report.config_paths)}")
        lines.append(f"  MCP servers:  {len(report.mcp_servers)}")
        lines.append(f"  Findings:     {len(report.findings)}")

        if report.mcp_servers:
            lines.append(f"\n  {bold}MCP Servers:{reset}")
            for srv in report.mcp_servers:
                risk_marker = f" {sev_c['high']}⚠{reset}" if srv.risks else ""
                lines.append(f"    • {srv.name}{risk_marker}")
                if srv.command:
                    lines.append(f"      Command: {srv.command} {' '.join(srv.args)}")
                if srv.url:
                    lines.append(f"      URL: {srv.url}")
                for risk in srv.risks:
                    lines.append(f"      {sev_c['high']}↳ {risk}{reset}")

        if report.findings:
            lines.append(f"\n  {bold}Findings:{reset}")
            # Sort by severity
            sorted_findings = sorted(
                report.findings,
                key=lambda f: list(SEVERITY_WEIGHTS.keys()).index(f.severity)
            )
            for f in sorted_findings:
                color = sev_c.get(f.severity, "")
                lines.append(f"    {color}[{f.severity.upper()}]{reset} {f.title}")
                lines.append(f"      {f.detail}")
                if f.remediation:
                    lines.append(f"      → {f.remediation}")

        if report.config_paths:
            lines.append(f"\n  {bold}Config paths:{reset}")
            for cp in report.config_paths:
                lines.append(f"    {cp}")

        lines.append("")

    # Aggregate findings
    if aggregate:
        lines.append(f"{bold}{'═' * 60}{reset}")
        lines.append(f"{bold}CROSS-AGENT FINDINGS{reset}")
        for f in aggregate:
            color = sev_c.get(f.severity, "")
            lines.append(f"  {color}[{f.severity.upper()}]{reset} {f.title}")
            lines.append(f"    {f.detail}")
            if f.remediation:
                lines.append(f"    → {f.remediation}")
        lines.append("")

    # Not installed
    not_installed = [r for r in reports if not r.installed]
    if not_installed:
        lines.append(f"{bold}Not detected:{reset} {', '.join(r.name for r in not_installed)}")
        lines.append("")

    return "\n".join(lines)


def format_json(reports: list[AgentReport], aggregate: list[Finding]) -> str:
    """Format results as JSON."""
    all_findings = []
    for r in reports:
        all_findings.extend(r.findings)
    all_findings.extend(aggregate)
    grade, score = calculate_grade(all_findings)

    data = {
        "version": __version__,
        "platform": get_platform(),
        "host": platform.node(),
        "grade": grade,
        "risk_score": score,
        "agents": [],
        "aggregate_findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
            }
            for f in aggregate
        ],
    }

    for r in reports:
        agent = {
            "name": r.name,
            "installed": r.installed,
            "version": r.version,
            "config_paths": r.config_paths,
            "mcp_servers": [
                {
                    "name": s.name,
                    "command": s.command,
                    "args": s.args,
                    "url": s.url,
                    "risks": s.risks,
                }
                for s in r.mcp_servers
            ],
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                }
                for f in r.findings
            ],
            "permissions": r.permissions,
        }
        data["agents"].append(agent)

    return json.dumps(data, indent=2)


def format_json_summary(reports: list[AgentReport], aggregate: list[Finding]) -> str:
    """Format results as condensed JSON summary."""
    all_findings = []
    for r in reports:
        all_findings.extend(r.findings)
    all_findings.extend(aggregate)
    grade, score = calculate_grade(all_findings)

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    # Get top critical/high findings (max 5 each)
    critical_findings = [f for f in all_findings if f.severity == "critical"][:5]
    high_findings = [f for f in all_findings if f.severity == "high"][:5]

    data = {
        "version": __version__,
        "grade": grade,
        "risk_score": score,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "installed_agents": [
            {"name": r.name, "version": r.version, "mcp_servers": len(r.mcp_servers)}
            for r in reports if r.installed
        ],
        "top_critical": [
            {"category": f.category, "title": f.title}
            for f in critical_findings
        ],
        "top_high": [
            {"category": f.category, "title": f.title}
            for f in high_findings
        ],
    }

    return json.dumps(data, indent=2)


# ─── Main ────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agentscan",
        description="AI Agent Security Posture Scanner — enumerate all AI coding agents "
                    "and map their aggregate permission surface.",
    )
    parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--json-summary", action="store_true",
        help="Output condensed JSON summary with grade, counts, and top findings",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--ci", action="store_true",
        help="CI mode: exit 1 if grade below threshold",
    )
    parser.add_argument(
        "--threshold", default="C",
        help="Minimum passing grade for CI mode (default: C)",
    )
    parser.add_argument(
        "--agents", nargs="+",
        help="Only scan specific agents (by name)",
    )
    parser.add_argument(
        "--version", "-v", action="version", version=f"agentscan {__version__}",
    )
    args = parser.parse_args()

    # Run all scanners
    all_scanners = {
        "Claude Desktop": scan_claude_desktop,
        "Claude Code": scan_claude_code,
        "Cursor": scan_cursor,
        "VS Code": scan_vscode,
        "Windsurf": scan_windsurf,
        "Zed": scan_zed,
        "Codex CLI": scan_codex,
        "aider": scan_aider,
        "Moltbot": scan_moltbot,
    }

    if args.agents:
        # Filter to requested agents
        agent_filter = {a.lower() for a in args.agents}
        scanners = {
            name: fn for name, fn in all_scanners.items()
            if name.lower() in agent_filter or any(f in name.lower() for f in agent_filter)
        }
    else:
        scanners = all_scanners

    reports = []
    for name, scanner in scanners.items():
        try:
            report = scanner()
            reports.append(report)
        except Exception as e:
            report = AgentReport(name=name)
            report.findings.append(Finding(
                severity="low", category="config",
                title=f"Scanner error: {e}",
                detail=f"Failed to scan {name}",
            ))
            reports.append(report)

    # Cross-agent analysis
    aggregate = aggregate_findings(reports)

    # Output
    if args.json_summary:
        print(format_json_summary(reports, aggregate))
    elif args.format == "json":
        print(format_json(reports, aggregate))
    else:
        no_color = args.no_color or not sys.stdout.isatty()
        print(format_text(reports, aggregate, no_color=no_color))

    # CI mode
    if args.ci:
        all_findings = []
        for r in reports:
            all_findings.extend(r.findings)
        all_findings.extend(aggregate)
        grade, _ = calculate_grade(all_findings)
        grades = ["A", "B", "C", "D", "F"]
        if grades.index(grade) > grades.index(args.threshold):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
