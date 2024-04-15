# Contributing

Thank you for considering a contribution to **secure-ai-sandbox**.

## Getting Started

### Prerequisites

- Python 3.12+
- Docker 24+
- Terraform 1.5+
- `kubectl` and `gcloud` CLI (for GKE deployments)

### Local Development Setup

```bash
# Clone the repo
git clone https://github.com/vanigundu18/secure-ai-sandbox.git
cd secure-ai-sandbox

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install gateway dependencies
pip install -r gateway/requirements.txt
pip install pytest pytest-cov

# Run tests
pytest gateway/tests/ -v

# Start the gateway locally (dry-run mode without ANTHROPIC_API_KEY)
cd gateway
uvicorn app.main:app --reload --port 8080
```

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/vanigundu18/secure-ai-sandbox/issues) with:
- A clear title and description
- Steps to reproduce
- Expected vs. actual behaviour
- Environment details (OS, Python version, Docker version)

### Proposing Changes

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes. Keep commits atomic and descriptive.

3. Add or update tests. Every guardrail rule change **must** be accompanied by tests in `gateway/tests/`.

4. Ensure all tests pass and coverage does not decrease:
   ```bash
   pytest gateway/tests/ -v --cov=app --cov-report=term-missing
   ```

5. Open a Pull Request against `main`. Fill in the PR template.

### Guardrail Rule Contributions

New injection detection patterns are especially welcome. When adding a rule to `guardrails.py`:

- Add the compiled regex to `_INJECTION_PATTERNS` with an appropriate `Severity`
- Give the rule a descriptive kebab-case name (e.g., `"token-smuggling"`)
- Add at least two test cases in `test_guardrails.py`: one that triggers the rule, one that doesn't
- Include a comment explaining what attack vector the rule addresses

### Code Style

- Python: follow PEP 8; line length ≤ 100 characters
- Terraform: `terraform fmt` before committing
- Kubernetes YAML: 2-space indentation, no trailing whitespace

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Rebase onto `main` before requesting review
- Do not include unrelated refactoring in a feature PR
- Security-sensitive changes (guardrail rules, IAM policies, network policies) require two approvals

## License

By contributing, you agree your contributions will be licensed under the [Apache License 2.0](LICENSE).
