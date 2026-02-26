#!/usr/bin/env python3
"""Comprehensive tests for agentscan."""

import json
import platform
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

# Import the module
sys.path.insert(0, str(Path(__file__).parent))
import agentscan


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def mock_home(tmp_path):
    """Mock home directory."""
    with patch("pathlib.Path.home", return_value=tmp_path):
        yield tmp_path


@pytest.fixture
def mock_macos():
    """Mock macOS platform."""
    with patch("platform.system", return_value="Darwin"):
        yield


@pytest.fixture
def mock_linux():
    """Mock Linux platform."""
    with patch("platform.system", return_value="Linux"):
        yield


@pytest.fixture
def mock_windows():
    """Mock Windows platform."""
    with patch("platform.system", return_value="Windows"):
        yield


# ─── Platform Helpers Tests ─────────────────────────────────────────


def test_get_platform_macos(mock_macos):
    """Test platform detection on macOS."""
    assert agentscan.get_platform() == "macos"


def test_get_platform_linux(mock_linux):
    """Test platform detection on Linux."""
    assert agentscan.get_platform() == "linux"


def test_get_platform_windows(mock_windows):
    """Test platform detection on Windows."""
    assert agentscan.get_platform() == "windows"


def test_expand_path_tilde(mock_home):
    """Test path expansion with tilde."""
    with patch("os.path.expanduser", lambda x: str(mock_home / x.replace("~/", ""))):
        result = agentscan.expand_path("~/test")
        assert str(result) == str(mock_home / "test")


def test_expand_path_env_var():
    """Test path expansion with environment variable."""
    with patch.dict("os.environ", {"TEST_VAR": "/test/path"}):
        result = agentscan.expand_path("$TEST_VAR/file")
        assert "/test/path/file" in str(result)


def test_get_app_support_dir_macos(mock_home, mock_macos):
    """Test app support directory on macOS."""
    result = agentscan.get_app_support_dir()
    assert result == mock_home / "Library" / "Application Support"


def test_get_app_support_dir_linux(mock_home, mock_linux):
    """Test app support directory on Linux."""
    result = agentscan.get_app_support_dir()
    assert str(result) == str(mock_home / ".config")


def test_get_app_support_dir_windows(mock_home, mock_windows):
    """Test app support directory on Windows."""
    with patch.dict("os.environ", {"APPDATA": str(mock_home / "AppData" / "Roaming")}):
        result = agentscan.get_app_support_dir()
        assert result == mock_home / "AppData" / "Roaming"


def test_read_json_valid(tmp_path):
    """Test reading valid JSON file."""
    json_file = tmp_path / "test.json"
    data = {"key": "value"}
    json_file.write_text(json.dumps(data))
    result = agentscan.read_json(json_file)
    assert result == data


def test_read_json_with_comments(tmp_path):
    """Test reading JSONC (JSON with comments)."""
    json_file = tmp_path / "test.json"
    content = """{
        // Single line comment
        "key": "value",  // inline comment
        /* Multi-line
           comment */
        "another": "test",
    }"""
    json_file.write_text(content)
    result = agentscan.read_json(json_file)
    assert result is not None
    assert result["key"] == "value"
    assert result["another"] == "test"


def test_read_json_trailing_commas(tmp_path):
    """Test reading JSON with trailing commas."""
    json_file = tmp_path / "test.json"
    content = '{"key": "value", "list": [1, 2, 3,],}'
    json_file.write_text(content)
    result = agentscan.read_json(json_file)
    assert result is not None
    assert result["key"] == "value"


def test_read_json_nonexistent(tmp_path):
    """Test reading nonexistent file."""
    result = agentscan.read_json(tmp_path / "nonexistent.json")
    assert result is None


def test_read_json_invalid(tmp_path):
    """Test reading invalid JSON."""
    json_file = tmp_path / "invalid.json"
    json_file.write_text("{invalid json")
    result = agentscan.read_json(json_file)
    assert result is None


def test_run_cmd_success():
    """Test successful command execution."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="output\n")
        result = agentscan.run_cmd(["echo", "test"])
        assert result == "output"


def test_run_cmd_failure():
    """Test failed command execution."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=1, stdout="")
        result = agentscan.run_cmd(["false"])
        assert result is None


def test_run_cmd_not_found():
    """Test command not found."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = agentscan.run_cmd(["nonexistent"])
        assert result is None


def test_run_cmd_timeout():
    """Test command timeout."""
    with patch("subprocess.run", side_effect=TimeoutExpired("test", 5)):
        result = agentscan.run_cmd(["sleep", "10"], timeout=1)
        assert result is None


# ─── Secret Detection Tests ─────────────────────────────────────────


def test_scan_for_secrets_openai():
    """Test OpenAI API key detection."""
    text = "My key is sk-" + "x" * 48
    result = agentscan.scan_for_secrets(text)
    assert "OpenAI API key" in result


def test_scan_for_secrets_anthropic():
    """Test Anthropic API key detection."""
    text = "sk-ant-api03-abc123def456xyz789qwerty"  # 20+ chars after sk-ant-
    result = agentscan.scan_for_secrets(text)
    assert "Anthropic API key" in result


def test_scan_for_secrets_github_pat():
    """Test GitHub PAT detection."""
    text = "ghp_" + "x" * 36
    result = agentscan.scan_for_secrets(text)
    assert "GitHub PAT (classic)" in result


def test_scan_for_secrets_aws():
    """Test AWS access key detection."""
    text = "AKIAIOSFODNN7EXAMPLE"
    result = agentscan.scan_for_secrets(text)
    assert "AWS access key" in result


def test_scan_for_secrets_multiple():
    """Test multiple secret detection."""
    text = f"sk-{'x' * 48} and ghp_{'y' * 36}"
    result = agentscan.scan_for_secrets(text)
    assert len(result) >= 2


def test_scan_for_secrets_none():
    """Test no secrets detected."""
    text = "Just normal text here"
    result = agentscan.scan_for_secrets(text)
    assert len(result) == 0


def test_check_env_exposure_sensitive_keys():
    """Test sensitive environment variable detection."""
    env = {"OPENAI_API_KEY": "sk-test", "NORMAL_VAR": "value"}
    result = agentscan.check_env_exposure(env)
    assert "OPENAI_API_KEY" in result


def test_check_env_exposure_secret_in_value():
    """Test secret in environment variable value."""
    env = {"MY_VAR": "sk-" + "x" * 48}
    result = agentscan.check_env_exposure(env)
    assert len(result) > 0
    assert "OpenAI API key" in str(result)


def test_check_env_exposure_clean():
    """Test clean environment variables."""
    env = {"PATH": "/usr/bin", "HOME": "/home/user"}
    result = agentscan.check_env_exposure(env)
    assert len(result) == 0


# ─── MCP Analysis Tests ─────────────────────────────────────────────


def test_analyze_mcp_server_basic():
    """Test basic MCP server analysis."""
    config = {"command": "node", "args": ["server.js"]}
    server = agentscan.analyze_mcp_server("test", config)
    assert server.name == "test"
    assert server.command == "node"
    assert len(server.risks) > 0


def test_analyze_mcp_server_dangerous_command():
    """Test dangerous command detection."""
    config = {"command": "bash", "args": ["-c", "echo hello"]}
    server = agentscan.analyze_mcp_server("shell", config)
    assert any("bash" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_npx_third_party():
    """Test npx third-party package detection."""
    config = {"command": "npx", "args": ["suspicious-package"]}
    server = agentscan.analyze_mcp_server("test", config)
    assert any("third-party" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_npx_anthropic():
    """Test npx with Anthropic package (safe)."""
    config = {"command": "npx", "args": ["@anthropic/mcp-server"]}
    server = agentscan.analyze_mcp_server("test", config)
    # Should not flag as third-party
    assert not any("third-party" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_risky_name():
    """Test risky server name detection."""
    config = {"command": "test"}
    server = agentscan.analyze_mcp_server("filesystem", config)
    assert any("filesystem" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_env_secrets():
    """Test environment variable secret detection."""
    config = {
        "command": "node",
        "env": {"OPENAI_API_KEY": "sk-test"}
    }
    server = agentscan.analyze_mcp_server("test", config)
    assert any("env" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_dangerous_flags():
    """Test dangerous flag detection."""
    config = {
        "command": "node",
        "args": ["--dangerously-skip-sandbox", "server.js"]
    }
    server = agentscan.analyze_mcp_server("test", config)
    assert any("dangerous" in risk.lower() for risk in server.risks)


def test_analyze_mcp_server_system_paths():
    """Test system path access detection."""
    config = {
        "command": "node",
        "args": ["--path", "/etc/passwd"]
    }
    server = agentscan.analyze_mcp_server("test", config)
    assert any("system" in risk.lower() for risk in server.risks)


# ─── Claude Desktop Scanner Tests ───────────────────────────────────


def test_scan_claude_desktop_not_installed(mock_home, mock_macos):
    """Test Claude Desktop when not installed."""
    report = agentscan.scan_claude_desktop()
    assert report.name == "Claude Desktop"
    assert not report.installed


def test_scan_claude_desktop_basic_config(mock_home, mock_macos):
    """Test Claude Desktop with basic config."""
    config_path = mock_home / "Library" / "Application Support" / "Claude"
    config_path.mkdir(parents=True)
    config_file = config_path / "claude_desktop_config.json"
    config_file.write_text(json.dumps({"mcpServers": {}}))
    
    report = agentscan.scan_claude_desktop()
    assert report.installed
    assert len(report.config_paths) > 0


def test_scan_claude_desktop_mcp_servers(mock_home, mock_macos):
    """Test Claude Desktop MCP server detection."""
    config_path = mock_home / "Library" / "Application Support" / "Claude"
    config_path.mkdir(parents=True)
    config_file = config_path / "claude_desktop_config.json"
    config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"]
            }
        }
    }
    config_file.write_text(json.dumps(config))
    
    report = agentscan.scan_claude_desktop()
    assert len(report.mcp_servers) == 1
    assert report.mcp_servers[0].name == "test-server"


def test_scan_claude_desktop_secrets_in_config(mock_home, mock_macos):
    """Test Claude Desktop secret detection."""
    config_path = mock_home / "Library" / "Application Support" / "Claude"
    config_path.mkdir(parents=True)
    config_file = config_path / "claude_desktop_config.json"
    config = {
        "apiKey": "sk-" + "x" * 48,
        "mcpServers": {}
    }
    config_file.write_text(json.dumps(config))
    
    report = agentscan.scan_claude_desktop()
    assert any(f.severity == "critical" for f in report.findings)
    assert any("secret" in f.title.lower() for f in report.findings)


# ─── Claude Code Scanner Tests ──────────────────────────────────────


def test_scan_claude_code_not_installed(mock_home):
    """Test Claude Code when not installed."""
    with patch("agentscan.run_cmd", return_value=None):
        report = agentscan.scan_claude_code()
        # Still might find configs even without CLI
        assert report.name == "Claude Code"


def test_scan_claude_code_with_version(mock_home):
    """Test Claude Code version detection."""
    with patch("agentscan.run_cmd", return_value="claude 1.0.0"):
        report = agentscan.scan_claude_code()
        assert report.installed
        assert report.version == "claude 1.0.0"


def test_scan_claude_code_bash_allowed(mock_home):
    """Test Claude Code bash permission detection."""
    claude_dir = mock_home / ".claude"
    claude_dir.mkdir(parents=True)
    settings = claude_dir / "settings.json"
    config = {
        "permissions": {
            "allow": ["Bash"]
        }
    }
    settings.write_text(json.dumps(config))
    
    report = agentscan.scan_claude_code()
    assert any("bash" in f.title.lower() for f in report.findings)
    assert any(f.severity == "high" for f in report.findings)


def test_scan_claude_code_dangerously_skip_permissions(mock_home):
    """Test detection of dangerously-skip-permissions."""
    claude_dir = mock_home / ".claude"
    claude_dir.mkdir(parents=True)
    history = claude_dir / "history.jsonl"
    history.write_text('{"command": "claude --dangerously-skip-permissions"}')
    
    report = agentscan.scan_claude_code()
    assert any("dangerously-skip-permissions" in f.title.lower() for f in report.findings)


# ─── Cursor Scanner Tests ───────────────────────────────────────────


def test_scan_cursor_not_installed(mock_home, mock_macos):
    """Test Cursor when not installed."""
    report = agentscan.scan_cursor()
    assert report.name == "Cursor"
    assert not report.installed


def test_scan_cursor_basic_config(mock_home, mock_macos):
    """Test Cursor with basic config."""
    cursor_dir = mock_home / "Library" / "Application Support" / "Cursor" / "User"
    cursor_dir.mkdir(parents=True)
    settings = cursor_dir / "settings.json"
    settings.write_text(json.dumps({}))
    
    report = agentscan.scan_cursor()
    assert report.installed


def test_scan_cursor_shadow_workspace(mock_home, mock_macos):
    """Test Cursor shadow workspace detection."""
    cursor_dir = mock_home / "Library" / "Application Support" / "Cursor" / "User"
    cursor_dir.mkdir(parents=True)
    settings = cursor_dir / "settings.json"
    config = {"cursor.general.enableShadowWorkspace": True}
    settings.write_text(json.dumps(config))
    
    report = agentscan.scan_cursor()
    assert any("shadow" in f.title.lower() for f in report.findings)


def test_scan_cursor_cursorrules_secrets(mock_home):
    """Test .cursorrules secret detection."""
    projects_dir = mock_home / "Projects"
    projects_dir.mkdir(parents=True)
    cursorrules = projects_dir / ".cursorrules"
    cursorrules.write_text("My API key: sk-" + "x" * 48)
    
    report = agentscan.scan_cursor()
    assert any(f.severity == "critical" for f in report.findings)


# ─── VS Code Scanner Tests ──────────────────────────────────────────


def test_scan_vscode_not_installed(mock_home, mock_macos):
    """Test VS Code when not installed."""
    report = agentscan.scan_vscode()
    assert report.name == "VS Code + Extensions"
    assert not report.installed


def test_scan_vscode_basic_config(mock_home, mock_macos):
    """Test VS Code with basic config."""
    vscode_dir = mock_home / "Library" / "Application Support" / "Code" / "User"
    vscode_dir.mkdir(parents=True)
    settings = vscode_dir / "settings.json"
    settings.write_text(json.dumps({}))
    
    report = agentscan.scan_vscode()
    assert report.installed


def test_scan_vscode_copilot_settings(mock_home, mock_macos):
    """Test VS Code Copilot settings detection."""
    vscode_dir = mock_home / "Library" / "Application Support" / "Code" / "User"
    vscode_dir.mkdir(parents=True)
    settings = vscode_dir / "settings.json"
    config = {
        "github.copilot.enable": {
            "*": True,
            "python": True
        }
    }
    settings.write_text(json.dumps(config))
    
    report = agentscan.scan_vscode()
    assert "copilot_languages" in report.permissions


def test_scan_vscode_secrets_in_settings(mock_home, mock_macos):
    """Test VS Code secret detection."""
    vscode_dir = mock_home / "Library" / "Application Support" / "Code" / "User"
    vscode_dir.mkdir(parents=True)
    settings = vscode_dir / "settings.json"
    config = {"apiKey": "sk-" + "x" * 48}
    settings.write_text(json.dumps(config))
    
    report = agentscan.scan_vscode()
    assert any(f.severity == "critical" for f in report.findings)


# ─── Aggregate Analysis Tests ───────────────────────────────────────


def test_aggregate_findings_high_agent_density():
    """Test detection of high agent density."""
    reports = [
        agentscan.AgentReport(name=f"Agent{i}", installed=True)
        for i in range(5)
    ]
    findings = agentscan.aggregate_findings(reports)
    assert any("agent density" in f.title.lower() for f in findings)


def test_aggregate_findings_shared_mcp():
    """Test detection of shared MCP servers."""
    reports = [
        agentscan.AgentReport(
            name="Agent1",
            installed=True,
            mcp_servers=[agentscan.MCPServer(name="shared")]
        ),
        agentscan.AgentReport(
            name="Agent2",
            installed=True,
            mcp_servers=[agentscan.MCPServer(name="shared")]
        ),
    ]
    findings = agentscan.aggregate_findings(reports)
    assert any("shared" in f.title.lower() for f in findings)


def test_aggregate_findings_large_mcp_surface():
    """Test detection of large MCP surface area."""
    servers = [agentscan.MCPServer(name=f"server{i}") for i in range(15)]
    reports = [
        agentscan.AgentReport(
            name="Agent1",
            installed=True,
            mcp_servers=servers
        )
    ]
    findings = agentscan.aggregate_findings(reports)
    assert any("mcp surface" in f.title.lower() for f in findings)


def test_aggregate_findings_multiple_shell_access():
    """Test detection of multiple agents with shell access."""
    reports = [
        agentscan.AgentReport(
            name="Agent1",
            installed=True,
            findings=[
                agentscan.Finding(
                    severity="high",
                    category="shell",
                    title="Shell access enabled",
                    detail="Test"
                )
            ]
        ),
        agentscan.AgentReport(
            name="Agent2",
            installed=True,
            findings=[
                agentscan.Finding(
                    severity="high",
                    category="shell",
                    title="Bash execution",
                    detail="Test"
                )
            ]
        ),
    ]
    findings = agentscan.aggregate_findings(reports)
    assert any("shell" in f.title.lower() for f in findings)


# ─── Scoring Tests ──────────────────────────────────────────────────


def test_calculate_grade_a():
    """Test grade A calculation (no findings)."""
    findings = []
    grade, score = agentscan.calculate_grade(findings)
    assert grade == "A"
    assert score == 0


def test_calculate_grade_b():
    """Test grade B calculation."""
    findings = [
        agentscan.Finding(severity="low", category="test", title="Test", detail="Test")
    ]
    grade, score = agentscan.calculate_grade(findings)
    assert grade == "B"


def test_calculate_grade_c():
    """Test grade C calculation."""
    findings = [
        agentscan.Finding(severity="medium", category="test", title="Test", detail="Test"),
        agentscan.Finding(severity="medium", category="test", title="Test", detail="Test"),
    ]
    grade, score = agentscan.calculate_grade(findings)
    assert grade == "C"


def test_calculate_grade_d():
    """Test grade D calculation."""
    findings = [
        agentscan.Finding(severity="high", category="test", title="Test", detail="Test"),
        agentscan.Finding(severity="high", category="test", title="Test", detail="Test"),
    ]
    grade, score = agentscan.calculate_grade(findings)
    assert grade == "D"


def test_calculate_grade_f():
    """Test grade F calculation."""
    findings = [
        agentscan.Finding(severity="critical", category="test", title="Test", detail="Test"),
        agentscan.Finding(severity="critical", category="test", title="Test", detail="Test"),
    ]
    grade, score = agentscan.calculate_grade(findings)
    assert grade == "F"


# ─── Output Formatting Tests ────────────────────────────────────────


def test_format_text_basic():
    """Test text output formatting."""
    reports = [
        agentscan.AgentReport(
            name="TestAgent",
            installed=True,
            findings=[
                agentscan.Finding(
                    severity="medium",
                    category="test",
                    title="Test finding",
                    detail="Test detail"
                )
            ]
        )
    ]
    output = agentscan.format_text(reports, [], no_color=True)
    assert "TestAgent" in output
    assert "Test finding" in output
    assert "MEDIUM" in output


def test_format_text_with_mcp():
    """Test text output with MCP servers."""
    reports = [
        agentscan.AgentReport(
            name="TestAgent",
            installed=True,
            mcp_servers=[
                agentscan.MCPServer(
                    name="test-server",
                    command="node",
                    args=["server.js"],
                    risks=["Test risk"]
                )
            ]
        )
    ]
    output = agentscan.format_text(reports, [], no_color=True)
    assert "test-server" in output
    assert "Test risk" in output


def test_format_json_basic():
    """Test JSON output formatting."""
    reports = [
        agentscan.AgentReport(
            name="TestAgent",
            installed=True,
            findings=[
                agentscan.Finding(
                    severity="medium",
                    category="test",
                    title="Test finding",
                    detail="Test detail"
                )
            ]
        )
    ]
    output = agentscan.format_json(reports, [])
    data = json.loads(output)
    assert "version" in data
    assert "grade" in data
    assert len(data["agents"]) == 1
    assert data["agents"][0]["name"] == "TestAgent"


def test_format_json_with_aggregate():
    """Test JSON output with aggregate findings."""
    reports = []
    aggregate = [
        agentscan.Finding(
            severity="high",
            category="test",
            title="Aggregate finding",
            detail="Test"
        )
    ]
    output = agentscan.format_json(reports, aggregate)
    data = json.loads(output)
    assert len(data["aggregate_findings"]) == 1
    assert data["aggregate_findings"][0]["title"] == "Aggregate finding"


# ─── Main Function Tests ────────────────────────────────────────────


def test_main_default():
    """Test main function with default arguments."""
    with patch("sys.argv", ["agentscan"]):
        with patch("agentscan.scan_claude_desktop", return_value=agentscan.AgentReport(name="Test")):
            with patch("agentscan.scan_claude_code", return_value=agentscan.AgentReport(name="Test")):
                with patch("agentscan.scan_cursor", return_value=agentscan.AgentReport(name="Test")):
                    with patch("agentscan.scan_vscode", return_value=agentscan.AgentReport(name="Test")):
                        with patch("agentscan.scan_windsurf", return_value=agentscan.AgentReport(name="Test")):
                            with patch("agentscan.scan_zed", return_value=agentscan.AgentReport(name="Test")):
                                with patch("agentscan.scan_codex", return_value=agentscan.AgentReport(name="Test")):
                                    with patch("agentscan.scan_aider", return_value=agentscan.AgentReport(name="Test")):
                                        with patch("agentscan.scan_moltbot", return_value=agentscan.AgentReport(name="Test")):
                                            with patch("builtins.print"):
                                                result = agentscan.main()
                                                assert result == 0


def test_main_json_format():
    """Test main function with JSON format."""
    with patch("sys.argv", ["agentscan", "--format", "json"]):
        with patch("agentscan.scan_claude_desktop", return_value=agentscan.AgentReport(name="Test")):
            with patch("agentscan.scan_claude_code", return_value=agentscan.AgentReport(name="Test")):
                with patch("agentscan.scan_cursor", return_value=agentscan.AgentReport(name="Test")):
                    with patch("agentscan.scan_vscode", return_value=agentscan.AgentReport(name="Test")):
                        with patch("agentscan.scan_windsurf", return_value=agentscan.AgentReport(name="Test")):
                            with patch("agentscan.scan_zed", return_value=agentscan.AgentReport(name="Test")):
                                with patch("agentscan.scan_codex", return_value=agentscan.AgentReport(name="Test")):
                                    with patch("agentscan.scan_aider", return_value=agentscan.AgentReport(name="Test")):
                                        with patch("agentscan.scan_moltbot", return_value=agentscan.AgentReport(name="Test")):
                                            with patch("builtins.print") as mock_print:
                                                result = agentscan.main()
                                                assert result == 0
                                                # Verify JSON was printed
                                                assert mock_print.called


def test_main_ci_mode_pass():
    """Test CI mode with passing grade."""
    with patch("sys.argv", ["agentscan", "--ci", "--threshold", "C"]):
        reports_mock = [
            agentscan.AgentReport(
                name="Test",
                findings=[agentscan.Finding(severity="low", category="test", title="Test", detail="Test")]
            )
        ]
        with patch("agentscan.scan_claude_desktop", return_value=reports_mock[0]):
            with patch("agentscan.scan_claude_code", return_value=agentscan.AgentReport(name="Test")):
                with patch("agentscan.scan_cursor", return_value=agentscan.AgentReport(name="Test")):
                    with patch("agentscan.scan_vscode", return_value=agentscan.AgentReport(name="Test")):
                        with patch("agentscan.scan_windsurf", return_value=agentscan.AgentReport(name="Test")):
                            with patch("agentscan.scan_zed", return_value=agentscan.AgentReport(name="Test")):
                                with patch("agentscan.scan_codex", return_value=agentscan.AgentReport(name="Test")):
                                    with patch("agentscan.scan_aider", return_value=agentscan.AgentReport(name="Test")):
                                        with patch("agentscan.scan_moltbot", return_value=agentscan.AgentReport(name="Test")):
                                            with patch("builtins.print"):
                                                result = agentscan.main()
                                                assert result == 0


def test_main_ci_mode_fail():
    """Test CI mode with failing grade."""
    with patch("sys.argv", ["agentscan", "--ci", "--threshold", "B"]):
        reports_mock = [
            agentscan.AgentReport(
                name="Test",
                findings=[
                    agentscan.Finding(severity="critical", category="test", title="Test", detail="Test"),
                    agentscan.Finding(severity="high", category="test", title="Test", detail="Test"),
                ]
            )
        ]
        with patch("agentscan.scan_claude_desktop", return_value=reports_mock[0]):
            with patch("agentscan.scan_claude_code", return_value=agentscan.AgentReport(name="Test")):
                with patch("agentscan.scan_cursor", return_value=agentscan.AgentReport(name="Test")):
                    with patch("agentscan.scan_vscode", return_value=agentscan.AgentReport(name="Test")):
                        with patch("agentscan.scan_windsurf", return_value=agentscan.AgentReport(name="Test")):
                            with patch("agentscan.scan_zed", return_value=agentscan.AgentReport(name="Test")):
                                with patch("agentscan.scan_codex", return_value=agentscan.AgentReport(name="Test")):
                                    with patch("agentscan.scan_aider", return_value=agentscan.AgentReport(name="Test")):
                                        with patch("agentscan.scan_moltbot", return_value=agentscan.AgentReport(name="Test")):
                                            with patch("builtins.print"):
                                                result = agentscan.main()
                                                assert result == 1


def test_main_filter_agents():
    """Test filtering specific agents."""
    with patch("sys.argv", ["agentscan", "--agents", "Claude"]):
        with patch("agentscan.scan_claude_desktop") as mock_claude:
            with patch("agentscan.scan_claude_code") as mock_claude_code:
                mock_claude.return_value = agentscan.AgentReport(name="Claude Desktop")
                mock_claude_code.return_value = agentscan.AgentReport(name="Claude Code")
                with patch("builtins.print"):
                    result = agentscan.main()
                    assert result == 0
                    # Should have called Claude scanners
                    assert mock_claude.called
                    assert mock_claude_code.called


# ─── Additional Scanner Tests ───────────────────────────────────────


def test_scan_windsurf_not_installed(mock_home, mock_macos):
    """Test Windsurf when not installed."""
    report = agentscan.scan_windsurf()
    assert report.name == "Windsurf"
    assert not report.installed


def test_scan_zed_not_installed(mock_home):
    """Test Zed when not installed."""
    report = agentscan.scan_zed()
    assert report.name == "Zed"
    assert not report.installed


def test_scan_zed_api_key_in_config(mock_home):
    """Test Zed API key detection."""
    config_dir = mock_home / ".config" / "zed"
    config_dir.mkdir(parents=True)
    settings = config_dir / "settings.json"
    config = {
        "language_models": {
            "openai": {"api_key": "sk-" + "x" * 48}
        }
    }
    settings.write_text(json.dumps(config))
    
    report = agentscan.scan_zed()
    assert any(f.severity == "critical" for f in report.findings)
    assert any("api key" in f.title.lower() for f in report.findings)


def test_scan_codex_not_installed(mock_home):
    """Test Codex when not installed."""
    with patch("agentscan.run_cmd", return_value=None):
        report = agentscan.scan_codex()
        assert report.name == "Codex CLI"


def test_scan_codex_full_auto_mode(mock_home):
    """Test Codex full-auto mode detection."""
    codex_dir = mock_home / ".codex"
    codex_dir.mkdir(parents=True)
    config_file = codex_dir / "config.json"
    config = {"approvalMode": "full-auto"}
    config_file.write_text(json.dumps(config))
    
    with patch("agentscan.run_cmd", return_value=None):
        report = agentscan.scan_codex()
        assert any("full-auto" in f.title.lower() for f in report.findings)


def test_scan_aider_not_installed(mock_home):
    """Test aider when not installed."""
    with patch("agentscan.run_cmd", return_value=None):
        report = agentscan.scan_aider()
        assert report.name == "aider"


def test_scan_aider_secrets_in_env(mock_home):
    """Test aider .env secret detection."""
    env_file = mock_home / ".aider.env"
    env_file.write_text("OPENAI_API_KEY=sk-" + "x" * 48)
    
    with patch("agentscan.run_cmd", return_value=None):
        report = agentscan.scan_aider()
        assert any(f.severity in ["high", "critical"] for f in report.findings)


def test_scan_moltbot_not_installed(mock_home):
    """Test Moltbot when not installed."""
    report = agentscan.scan_moltbot()
    assert report.name == "Moltbot/OpenClaw"
    assert not report.installed


def test_scan_moltbot_sudo_in_agents_md(mock_home):
    """Test Moltbot sudo detection in AGENTS.md."""
    clawd_dir = mock_home / "clawd"
    clawd_dir.mkdir(parents=True)
    agents_md = clawd_dir / "AGENTS.md"
    agents_md.write_text("You have sudo access to the system")
    
    report = agentscan.scan_moltbot()
    assert report.installed
    assert any("sudo" in f.title.lower() for f in report.findings)


# Make TimeoutExpired available
from subprocess import TimeoutExpired
