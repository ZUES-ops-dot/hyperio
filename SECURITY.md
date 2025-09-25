# Security Policy

Thank you for helping keep HyperionScan and its users safe. We take security research seriously and appreciate responsible disclosures.

## Supported Versions

Security fixes are applied to the latest `main` branch and included in tagged releases. Older releases will receive fixes only if they are still widely deployed.

| Version | Supported |
|---------|-----------|
| main    | Success        |
| < latest release | Warning Best effort |
| Older than 1 release | Failure        |

## Reporting a Vulnerability

1. **Do not** open a public issue for security-sensitive findings.
2. Email **security@hyperionscan.dev** with the subject `SECURITY: <short summary>`.
3. Include:
   - Detailed description and impact
   - Steps to reproduce (PoC, logs, screenshots)
   - Affected versions/commit SHA
   - Suggested remediation (if known)

We aim to acknowledge reports within **3 business days** and provide status updates at least every **7 days** until resolution.

## Coordinated Disclosure

We prefer a coordinated disclosure timeline. Once a fix or mitigation is available, we will credit researchers (unless anonymity is requested) and publish release notes summarizing the issue and fix.

## Scope

- HyperionScan Rust codebase (`src/`, `plugins/`, `ml_agents/`)
- CLI wrappers and setup scripts (`hyperionscan.ps1`, `setup_ai.*`)
- Default configuration files and shipped artifacts

The following are **out of scope**:

- Third-party dependencies (report upstream)
- Non-production assets (e.g., test fixtures)
- Social engineering or physical attacks

## Safe Harbor

We will not pursue legal action against security researchers who:

1. Make a good-faith effort to comply with this policy.
2. Avoid privacy violations, destruction of data, denial of service, or interruption/degradation of our services.
3. Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue.

Thank you for helping us build a safer smart contract ecosystem!
