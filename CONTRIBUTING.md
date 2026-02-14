# Contributing to agentscan

Thanks for your interest in contributing to agentscan!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/kriskimmerle/agentscan.git
   cd agentscan
   ```

2. No dependencies needed - agentscan uses only Python stdlib.

3. Run tests:
   ```bash
   python -m unittest test_agentscan -v
   ```

## Code Style

- Follow PEP 8 style guidelines
- Maximum line length: 100 characters
- Use type hints where possible
- Add docstrings for public functions and classes

## Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Aim for good test coverage of new code
- Use `unittest` (no external dependencies)

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Run tests: `python -m unittest test_agentscan`
5. Run linter: `flake8 agentscan.py`
6. Commit with clear message: `git commit -m "Add feature X"`
7. Push to your fork: `git push origin feature-name`
8. Open a pull request

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Include tests for new functionality
- Update documentation if needed
- Ensure CI passes (all Python versions)
- Respond to review feedback promptly

## Adding Support for New Agents

To add support for a new AI coding agent:

1. Create a new scanner function following the pattern:
   ```python
   def scan_new_agent() -> AgentReport:
       """Scan NewAgent configuration."""
       report = AgentReport(name="NewAgent")
       # ... implementation
       return report
   ```

2. Add the scanner to `all_scanners` dict in `main()`

3. Add tests in `test_agentscan.py`

4. Update README.md to list the new agent

## Reporting Issues

- Check existing issues first
- Include agentscan version (`agentscan --version`)
- Include OS and Python version
- Provide steps to reproduce
- Include relevant config snippets (redact secrets!)

## Questions?

Open an issue with the `question` label.
