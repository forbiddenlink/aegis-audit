# Contributing to AegisAudit

Thank you for your interest in contributing to AegisAudit! This document provides guidelines and instructions for setting up your development environment and contributing to the project.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Git
- (Optional) Docker for container testing

### Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/forbiddenlink/aegis-audit.git
   cd aegisaudit
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install in editable mode with dev dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Workflow

### Running Tests

Run the full test suite with coverage:
```bash
pytest
```

Run tests for a specific module:
```bash
pytest tests/test_checks_headers.py
```

View coverage report in browser:
```bash
pytest --cov-report=html
open htmlcov/index.html
```

### Code Quality

**Linting with ruff:**
```bash
ruff check aegisaudit/ tests/
```

**Auto-fix linting issues:**
```bash
ruff check --fix aegisaudit/ tests/
```

**Format code:**
```bash
ruff format aegisaudit/ tests/
```

**Type checking with mypy:**
```bash
mypy aegisaudit/
```

### Pre-commit Hooks

Pre-commit hooks will automatically run on `git commit`. To run manually on all files:
```bash
pre-commit run --all-files
```

## Code Style Guidelines

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints for all function signatures
- Write docstrings for public functions and classes
- Keep functions focused and under 50 lines when possible
- Aim for >80% test coverage on new code

### Example Function

```python
def check_example(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
    """
    Check for example security issue.
    
    Args:
        artifact: The scanned artifact to check
        config: Configuration and policy settings
    
    Returns:
        List of findings for this check
    """
    findings = []
    # Implementation here
    return findings
```

## Adding New Security Checks

### Web Checks (DAST-like)

1. Create a new file in `aegisaudit/checks/` (e.g., `my_check.py`)
2. Implement a check function:
   ```python
   def check_my_security_feature(artifact: ScanArtifact, config: AegisConfig) -> List[Finding]:
       findings = []
       # Your check logic
       return findings
   ```
3. Register the check in `aegisaudit/runner.py` by adding it to `CHECK_MODULES`
4. Add tests in `tests/test_checks_my_check.py`
5. Update `docs/07-check-catalog.md` with documentation

### SAST Checks

1. Add detection logic to relevant file in `aegisaudit/sast/`:
   - `secrets.py` for credential detection
   - `static.py` for AST-based analysis
   - `dependencies.py` for vulnerability scanning
2. Add tests in `tests/test_sast_scanner.py`

## Testing Guidelines

- Write tests for all new features and bug fixes
- Include both positive and negative test cases
- Test edge cases and error conditions
- Use descriptive test names: `test_<what>_<condition>_<expected>`

Example:
```python
def test_hsts_header_missing_triggers_finding():
    """Missing HSTS header should create HIGH severity finding."""
    # Test implementation
```

## Submitting Changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Add tests** for your changes

4. **Run tests and linting**
   ```bash
   pytest
   ruff check .
   mypy aegisaudit/
   ```

5. **Commit your changes** with a descriptive message
   ```bash
   git commit -m "Add: new security check for XYZ header"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub with:
   - Clear description of the changes
   - Reference to any related issues
   - Screenshots/examples if applicable

### Commit Message Guidelines

Use conventional commits format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: add Permissions-Policy header check
fix: handle malformed CSP headers gracefully
docs: update README with Docker usage
test: add edge cases for cookie parsing
```

## Project Structure

```
aegisaudit/
├── aegisaudit/          # Main package
│   ├── checks/          # Web security checks
│   ├── sast/            # Static analysis checks
│   ├── reporters/       # Report generators
│   ├── cli.py           # CLI interface
│   ├── models.py        # Data models
│   └── scoring.py       # Scoring engine
├── tests/               # Test suite
├── docs/                # Documentation
├── templates/           # HTML report templates
└── pyproject.toml       # Project configuration
```

## Getting Help

- **Issues**: Check [existing issues](https://github.com/forbiddenlink/aegis-audit/issues) or create a new one
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: See `docs/` directory for detailed documentation

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other contributors

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to AegisAudit! 🛡️
