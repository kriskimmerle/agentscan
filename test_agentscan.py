#!/usr/bin/env python3
"""Test suite for agentscan - AI Agent Security Posture Scanner"""

import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import agentscan


class TestPlatformHelpers(unittest.TestCase):
    """Test platform detection and path handling"""

    def test_get_platform_macos(self):
        """Test macOS platform detection"""
        with patch('platform.system', return_value='Darwin'):
            self.assertEqual(agentscan.get_platform(), 'macos')

    def test_get_platform_linux(self):
        """Test Linux platform detection"""
        with patch('platform.system', return_value='Linux'):
            self.assertEqual(agentscan.get_platform(), 'linux')

    def test_get_platform_windows(self):
        """Test Windows platform detection"""
        with patch('platform.system', return_value='Windows'):
            self.assertEqual(agentscan.get_platform(), 'windows')

    def test_expand_path_home(self):
        """Test home directory expansion"""
        result = agentscan.expand_path('~/test')
        self.assertTrue(str(result).startswith(str(Path.home())))
        self.assertTrue(str(result).endswith('test'))

    def test_expand_path_env_var(self):
        """Test environment variable expansion"""
        os.environ['TEST_VAR'] = '/tmp/test'
        result = agentscan.expand_path('$TEST_VAR/subdir')
        self.assertIn('test', str(result))
        self.assertIn('subdir', str(result))

    def test_get_app_support_dir_macos(self):
        """Test macOS app support directory"""
        with patch('agentscan.get_platform', return_value='macos'):
            result = agentscan.get_app_support_dir()
            self.assertTrue(str(result).endswith('Library/Application Support'))

    def test_get_app_support_dir_linux(self):
        """Test Linux config directory"""
        with patch('agentscan.get_platform', return_value='linux'):
            with patch.dict(os.environ, {'XDG_CONFIG_HOME': '/custom/config'}, clear=False):
                result = agentscan.get_app_support_dir()
                self.assertEqual(result, Path('/custom/config'))


class TestJSONHandling(unittest.TestCase):
    """Test JSON and JSONC parsing"""

    def test_read_json_valid(self):
        """Test reading valid JSON file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'key': 'value'}, f)
            f.flush()
            result = agentscan.read_json(Path(f.name))
            self.assertEqual(result, {'key': 'value'})
            os.unlink(f.name)

    def test_read_json_with_comments(self):
        """Test reading JSONC with single-line comments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{\n  // This is a comment\n  "key": "value"\n}')
            f.flush()
            result = agentscan.read_json(Path(f.name))
            self.assertEqual(result, {'key': 'value'})
            os.unlink(f.name)

    def test_read_json_with_multiline_comments(self):
        """Test reading JSONC with multi-line comments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{\n  /* Multi\n  line\n  comment */\n  "key": "value"\n}')
            f.flush()
            result = agentscan.read_json(Path(f.name))
            self.assertEqual(result, {'key': 'value'})
            os.unlink(f.name)

    def test_read_json_trailing_comma(self):
        """Test reading JSONC with trailing commas"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{\n  "key": "value",\n}')
            f.flush()
            result = agentscan.read_json(Path(f.name))
            self.assertEqual(result, {'key': 'value'})
            os.unlink(f.name)

    def test_read_json_nonexistent(self):
        """Test reading non-existent file returns None"""
        result = agentscan.read_json(Path('/nonexistent/file.json'))
        self.assertIsNone(result)

    def test_read_json_invalid(self):
        """Test reading invalid JSON returns None"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ invalid json }')
            f.flush()
            result = agentscan.read_json(Path(f.name))
            self.assertIsNone(result)
            os.unlink(f.name)


class TestSecretDetection(unittest.TestCase):
    """Test secret pattern detection"""

    def test_scan_for_secrets_openai_key(self):
        """Test detection of OpenAI API key"""
        text = 'sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH'
        result = agentscan.scan_for_secrets(text)
        self.assertTrue(any('OpenAI' in r for r in result))

    def test_scan_for_secrets_openai_project_key(self):
        """Test detection of OpenAI project key"""
        text = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234'
        result = agentscan.scan_for_secrets(text)
        self.assertTrue(any('OpenAI project' in r for r in result))

    def test_scan_for_secrets_anthropic_key(self):
        """Test detection of Anthropic API key"""
        text = 'sk-ant-1234567890abcdefghij'
        result = agentscan.scan_for_secrets(text)
        self.assertTrue(any('Anthropic' in r for r in result))

    def test_scan_for_secrets_github_pat(self):
        """Test detection of GitHub PAT"""
        text = 'ghp_1234567890abcdefghijklmnopqrstuv'
        result = agentscan.scan_for_secrets(text)
        self.assertTrue(any('GitHub PAT' in r for r in result))

    def test_scan_for_secrets_aws_key(self):
        """Test detection of AWS access key"""
        text = 'AKIAIOSFODNN7EXAMPLE'
        result = agentscan.scan_for_secrets(text)
        self.assertTrue(any('AWS' in r for r in result))

    def test_scan_for_secrets_clean_text(self):
        """Test no false positives on clean text"""
        text = 'This is a normal string with no secrets'
        result = agentscan.scan_for_secrets(text)
        self.assertEqual(result, [])

    def test_check_env_exposure_sensitive_vars(self):
        """Test detection of sensitive environment variables"""
        env = {
            'OPENAI_API_KEY': 'sk-test',
            'SAFE_VAR': 'safe_value'
        }
        result = agentscan.check_env_exposure(env)
        self.assertIn('OPENAI_API_KEY', result)
        self.assertEqual(len(result), 1)

    def test_check_env_exposure_secret_in_value(self):
        """Test detection of secrets in env var values"""
        env = {
            'CUSTOM_VAR': 'ghp_1234567890abcdefghijklmnopqrstuv'
        }
        result = agentscan.check_env_exposure(env)
        self.assertTrue(any('CUSTOM_VAR' in r and 'GitHub PAT' in r for r in result))


class TestMCPAnalysis(unittest.TestCase):
    """Test MCP server risk analysis"""

    def test_analyze_mcp_server_dangerous_command(self):
        """Test detection of dangerous MCP commands"""
        config = {'command': 'bash', 'args': ['-c', 'script.sh']}
        server = agentscan.analyze_mcp_server('test-server', config)
        self.assertTrue(any('bash' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_risky_name(self):
        """Test detection of risky server names"""
        config = {'command': 'node', 'args': ['server.js']}
        server = agentscan.analyze_mcp_server('filesystem-access', config)
        self.assertTrue(any('filesystem' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_env_exposure(self):
        """Test detection of exposed credentials in env"""
        config = {
            'command': 'node',
            'env': {'OPENAI_API_KEY': 'sk-test'}
        }
        server = agentscan.analyze_mcp_server('test-server', config)
        self.assertTrue(any('env' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_dangerous_flags(self):
        """Test detection of dangerous command flags"""
        config = {
            'command': 'node',
            'args': ['--no-sandbox', 'server.js']
        }
        server = agentscan.analyze_mcp_server('test-server', config)
        self.assertTrue(any('dangerous flags' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_system_directories(self):
        """Test detection of system directory access"""
        config = {
            'command': 'node',
            'args': ['server.js', '--path=/etc/passwd']
        }
        server = agentscan.analyze_mcp_server('test-server', config)
        self.assertTrue(any('system directories' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_third_party_npm(self):
        """Test detection of third-party npm packages"""
        config = {
            'command': 'npx',
            'args': ['suspicious-package']
        }
        server = agentscan.analyze_mcp_server('test-server', config)
        self.assertTrue(any('third-party' in r.lower() for r in server.risks))

    def test_analyze_mcp_server_safe_config(self):
        """Test safe MCP server config"""
        config = {
            'command': 'node',
            'args': ['server.js']
        }
        server = agentscan.analyze_mcp_server('safe-server', config)
        # Only 'node' risk, nothing else
        self.assertEqual(len(server.risks), 1)
        self.assertTrue('JavaScript' in server.risks[0])


class TestDataStructures(unittest.TestCase):
    """Test data structure initialization and behavior"""

    def test_mcp_server_creation(self):
        """Test MCPServer dataclass creation"""
        server = agentscan.MCPServer(
            name='test',
            command='node',
            args=['server.js'],
            risks=['test risk']
        )
        self.assertEqual(server.name, 'test')
        self.assertEqual(server.command, 'node')
        self.assertEqual(len(server.args), 1)
        self.assertEqual(len(server.risks), 1)

    def test_finding_creation(self):
        """Test Finding dataclass creation"""
        finding = agentscan.Finding(
            severity='high',
            category='permissions',
            title='Test finding',
            detail='Test detail',
            remediation='Fix it'
        )
        self.assertEqual(finding.severity, 'high')
        self.assertEqual(finding.category, 'permissions')
        self.assertTrue(finding.title)

    def test_agent_report_defaults(self):
        """Test AgentReport default values"""
        report = agentscan.AgentReport(name='TestAgent')
        self.assertEqual(report.name, 'TestAgent')
        self.assertFalse(report.installed)
        self.assertEqual(len(report.config_paths), 0)
        self.assertEqual(len(report.mcp_servers), 0)
        self.assertEqual(len(report.findings), 0)


class TestScoring(unittest.TestCase):
    """Test security scoring and grading"""

    def test_calculate_grade_perfect(self):
        """Test grade A with no findings"""
        findings = []
        grade, score = agentscan.calculate_grade(findings)
        self.assertEqual(grade, 'A')
        self.assertEqual(score, 0)

    def test_calculate_grade_b(self):
        """Test grade B with low findings"""
        findings = [
            agentscan.Finding('low', 'test', 'test', 'test'),
            agentscan.Finding('info', 'test', 'test', 'test')
        ]
        grade, score = agentscan.calculate_grade(findings)
        self.assertEqual(grade, 'B')
        self.assertLessEqual(score, 5)

    def test_calculate_grade_c(self):
        """Test grade C with medium findings"""
        findings = [
            agentscan.Finding('medium', 'test', 'test', 'test'),
            agentscan.Finding('medium', 'test', 'test', 'test')
        ]
        grade, score = agentscan.calculate_grade(findings)
        self.assertEqual(grade, 'C')

    def test_calculate_grade_f(self):
        """Test grade F with critical findings"""
        findings = [
            agentscan.Finding('critical', 'test', 'test', 'test'),
            agentscan.Finding('high', 'test', 'test', 'test'),
            agentscan.Finding('high', 'test', 'test', 'test')
        ]
        grade, score = agentscan.calculate_grade(findings)
        self.assertEqual(grade, 'F')
        self.assertGreater(score, 30)

    def test_severity_weights(self):
        """Test severity weight values"""
        self.assertEqual(agentscan.SEVERITY_WEIGHTS['critical'], 25)
        self.assertEqual(agentscan.SEVERITY_WEIGHTS['high'], 10)
        self.assertEqual(agentscan.SEVERITY_WEIGHTS['medium'], 3)
        self.assertEqual(agentscan.SEVERITY_WEIGHTS['low'], 1)
        self.assertEqual(agentscan.SEVERITY_WEIGHTS['info'], 0)


class TestAggregateFunctions(unittest.TestCase):
    """Test cross-agent analysis"""

    def test_aggregate_high_density(self):
        """Test detection of high agent density"""
        reports = [
            agentscan.AgentReport(name=f'Agent{i}', installed=True)
            for i in range(5)
        ]
        aggregate = agentscan.aggregate_findings(reports)
        self.assertTrue(any('density' in f.title.lower() for f in aggregate))

    def test_aggregate_shared_mcp(self):
        """Test detection of shared MCP servers"""
        mcp = agentscan.MCPServer(name='shared-server', command='node')
        reports = [
            agentscan.AgentReport(name='Agent1', installed=True, mcp_servers=[mcp]),
            agentscan.AgentReport(name='Agent2', installed=True, mcp_servers=[mcp])
        ]
        aggregate = agentscan.aggregate_findings(reports)
        self.assertTrue(any('shared' in f.title.lower() for f in aggregate))

    def test_aggregate_large_mcp_surface(self):
        """Test detection of large MCP surface area"""
        reports = []
        for i in range(3):
            mcps = [
                agentscan.MCPServer(name=f'server-{i}-{j}', command='node')
                for j in range(5)
            ]
            reports.append(agentscan.AgentReport(
                name=f'Agent{i}',
                installed=True,
                mcp_servers=mcps
            ))
        aggregate = agentscan.aggregate_findings(reports)
        self.assertTrue(any('surface area' in f.title.lower() or 'servers total' in f.title.lower() for f in aggregate))


class TestOutputFormatting(unittest.TestCase):
    """Test output formatting functions"""

    def test_format_json_structure(self):
        """Test JSON output structure"""
        reports = [agentscan.AgentReport(name='TestAgent', installed=True)]
        aggregate = []
        output = agentscan.format_json(reports, aggregate)
        data = json.loads(output)
        self.assertIn('version', data)
        self.assertIn('platform', data)
        self.assertIn('grade', data)
        self.assertIn('agents', data)
        self.assertEqual(len(data['agents']), 1)

    def test_format_text_no_crash(self):
        """Test text output doesn't crash"""
        reports = [
            agentscan.AgentReport(
                name='TestAgent',
                installed=True,
                findings=[
                    agentscan.Finding('high', 'test', 'Test finding', 'Detail')
                ]
            )
        ]
        aggregate = []
        output = agentscan.format_text(reports, aggregate, no_color=True)
        self.assertIn('TestAgent', output)
        self.assertIn('Test finding', output)


class TestCommandExecution(unittest.TestCase):
    """Test command execution helper"""

    def test_run_cmd_success(self):
        """Test successful command execution"""
        result = agentscan.run_cmd(['echo', 'test'])
        self.assertEqual(result, 'test')

    def test_run_cmd_nonexistent(self):
        """Test non-existent command returns None"""
        result = agentscan.run_cmd(['nonexistent-command-xyz'])
        self.assertIsNone(result)

    def test_run_cmd_failure(self):
        """Test failed command returns None"""
        result = agentscan.run_cmd(['ls', '/nonexistent-directory-xyz'])
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
