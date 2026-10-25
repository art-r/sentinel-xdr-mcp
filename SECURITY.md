Security Policy
## Supported Versions

This project is maintained on a best-effort basis. Security fixes may be provided for the latest version, but support for older releases is not guaranteed.

|Version	Security | Updates |
|---|---|
| Latest release	| Best effort |
| Older releases	| Not guaranteed |

Users are encouraged to run the latest available version and review release notes before upgrading.

## Reporting a Vulnerability

If you discover a potential security vulnerability, please report it responsibly.

Please do not disclose suspected vulnerabilities in public GitHub issues, discussions, pull requests, or other public channels.

Use GitHub's private vulnerability reporting if private vulnerability reporting is enabled for this repository. This allows you to report a vulnerability without publicly exposing technical details.

If private vulnerability reporting is unavailable, contact the repository maintainer privately through a contact method listed on their GitHub profile.

When reporting a vulnerability, please include as much of the following information as you can safely provide:

A description of the vulnerability and its potential impact.
The affected version, component, or configuration.
Steps to reproduce the issue, including a minimal proof of concept where appropriate.
Any relevant logs, error messages, or other technical details, with secrets and sensitive information removed.
Suggested mitigations or fixes, if known.

Please avoid including real credentials, access tokens, tenant-specific secrets, personal data, or sensitive production security telemetry in your report.

## What to Expect

Reports are reviewed on a best-effort basis, subject to the maintainer's availability.

There is no guaranteed response or remediation timeframe. If a vulnerability is confirmed, reasonable efforts will be made to assess its severity, develop an appropriate fix or mitigation, and communicate relevant guidance.

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability. Coordinated disclosure is appreciated.

## Scope and Security Considerations

This project provides an MCP interface to Microsoft Sentinel, Azure Log Analytics, and optionally Microsoft Defender XDR. Vulnerabilities that could compromise the confidentiality, integrity, or availability of the server, its clients, or connected services are particularly relevant.

Examples of in-scope issues include:

- Authentication or authorization bypasses, including Entra ID or app-role enforcement failures.
- Unauthorized access to Sentinel, Log Analytics, or Defender XDR data.
- KQL validation or query restrictions that can be bypassed to perform unauthorized operations. Please make sure to read trust-model and readme files fully beforehand to understand the expected scope of the kql validations
- Cross-caller data exposure or failures in per-caller rate limiting.
- Exposure of credentials, access tokens, sensitive telemetry, or other secrets through logs, errors, or audit records.
- Injection vulnerabilities, unsafe tool execution, or other flaws that enable unauthorized actions through the MCP interface.
- Security weaknesses in configuration, token validation, or integration boundaries that result in unauthorized access.

This list is illustrative, not exhaustive.

General bugs, feature requests, configuration questions, and issues without a security impact can be reported through the repository's regular GitHub issue tracker.

## Deployment and Operational Security

This project provides security controls, but it does not eliminate the need for secure deployment and configuration.

Operators are responsible for reviewing the code and configuration, protecting credentials, assigning only the necessary Microsoft permissions, and securing the environment in which the server and its MCP clients run.

In particular:

- Apply least-privilege principles to Entra ID application permissions and app-role assignments.
- Restrict access to the MCP server to authorized clients and callers.
- Treat tool outputs and retrieved security telemetry as potentially sensitive.
- Review KQL validation and tool authorization behavior before exposing the server to untrusted clients.
- Protect audit logs and ensure they do not expose secrets or sensitive data.
- Keep dependencies and deployment components updated.
- Do not assume that rate limiting, redaction, or query validation alone makes an otherwise insecure deployment safe.

Operators should independently verify that the implemented controls meet their environment's security and compliance requirements.

## Security Updates

Security fixes and relevant advisories will be published through the repository's releases, commits, or GitHub Security Advisories, as appropriate and where feasible.

Because this is an independent project maintained on a best-effort basis, ongoing maintenance and the availability of security updates are not guaranteed.
