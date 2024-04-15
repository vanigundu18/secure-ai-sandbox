# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please disclose it responsibly:

1. **Email**: Send a report to the repository owner via the email on their GitHub profile.
2. **Subject line**: `[SECURITY] secure-ai-sandbox — <brief description>`
3. **Include**:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce the issue
   - Any proof-of-concept code (if applicable)
   - Your suggested fix or mitigation (optional but appreciated)

You can expect an acknowledgement within **48 hours** and a remediation timeline within **7 days** for critical issues.

## Scope

The following are in scope for vulnerability reports:

- **Guardrail bypass**: Techniques to circumvent the prompt injection detection pipeline
- **PII leakage**: Ways the output sanitizer may fail to redact sensitive data
- **Container escape**: Vulnerabilities in the Dockerfile or Kubernetes configurations that could allow privilege escalation
- **Dependency vulnerabilities**: Critical CVEs in `requirements.txt` dependencies
- **Terraform misconfigurations**: IAM over-permissioning or network policy gaps

The following are **out of scope**:

- Issues in third-party services (GCP, Anthropic API)
- Theoretical attacks without proof of concept
- Social engineering attacks

## Security Architecture

This project applies the following security controls:

### Container Security
- Multi-stage Docker build with minimal runtime surface
- Non-root execution (UID 10001)
- Read-only root filesystem
- All Linux capabilities dropped
- Seccomp `RuntimeDefault` profile enforced

### Kubernetes Security
- Pod Security Standard `restricted` enforced on all namespaces
- Default-deny NetworkPolicy for ingress and egress
- Metadata server (`169.254.169.254`) explicitly blocked in the sandbox namespace
- Workload Identity used — no static key files

### Guardrail Pipeline
- 5 independent screening layers; early-exit on first violation
- 40+ compiled injection pattern rules
- PII redaction applied to both input and output
- Keyword hash logged (not plaintext) to prevent attack vocabulary in logs

### CI/CD
- Container images scanned with Trivy on every build
- SBOM generated for each released image
- Keyless signing via Workload Identity Federation (no long-lived credentials in CI)
