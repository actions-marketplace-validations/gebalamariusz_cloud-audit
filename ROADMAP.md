# Roadmap

> Current version: **v0.8.0** (March 2026)

## Completed

### v0.1.0 -- Initial Release
- 17 curated AWS security checks (IAM, S3, EC2, VPC, RDS, EIP)
- Rich CLI with progress bar and colored output
- JSON and HTML report output
- Health score (0-100) based on finding severity
- Docker support

### v0.2.0 -- Remediation & CIS Mapping
- Every finding includes copy-paste remediation (AWS CLI + Terraform HCL + docs link)
- CIS AWS Foundations Benchmark references on applicable checks
- `--export-fixes` generates a commented shell script for safe bulk remediation
- Effort estimation per finding (LOW / MEDIUM / HIGH)
- moto-based test suite with 80%+ coverage

### v0.3.0 -- Visibility & Detection
- CloudTrail checks (enabled, log validation, bucket exposure)
- GuardDuty checks (enabled, unresolved findings)
- AWS Config checks (enabled, recorder active)
- KMS checks (key rotation, permissive policies)
- CloudWatch alarm checks (root account usage)
- Total: 27 checks

### v0.4.0 -- Compute & Secrets
- Lambda checks (public URLs, deprecated runtimes, secrets in env vars)
- ECS checks (privileged mode, logging, ECS exec)
- SSM checks (unmanaged instances, insecure parameters)
- Secrets Manager checks (rotation, unused secrets)
- Additional IAM, S3, EC2 checks
- Total: 42 checks

### v0.5.0 / v0.5.1 -- CI/CD Integration
- SARIF v2.1.0 output for GitHub Code Scanning (`--format sarif`)
- Markdown output for PR comments (`--format markdown`)
- Configuration file (`.cloud-audit.yml`) with suppressions
- Environment variables for CI/CD pipelines
- Exit codes: 0 (clean), 1 (findings), 2 (errors)
- `list-checks` command (no AWS credentials required)
- Cross-account scanning via `--role-arn` (STS AssumeRole)
- OIDC authentication support for GitHub Actions
- 3 additional checks (NACL, termination protection, RDS auto-upgrade)
- Total: 45 checks, 170+ tests

### v0.6.0 -- Security Hardening
- Jinja2 minimum bumped to >=3.1.6 (CVE-2025-27516)
- Shell injection protection in `--export-fixes` output and remediation commands
- Dockerfile hardened (non-root user, pinned base image digest)
- SHA-pinned GitHub Actions in CI/CD workflows
- `make_check()` helper for consistent check registration
- ECS/GuardDuty pagination fixes, SG deduplication, NACL TCP/UDP detection
- S3 bucket cache with proper reset between scans
- SARIF, HTML, and Markdown report fixes
- 173 tests passing

### v0.7.0 -- Report Quality & Check Accuracy
- SARIF spec compliance (physicalLocation + logicalLocations, help.markdown, semanticVersion)
- S3 encryption check pivoted to SSE-KMS vs SSE-S3 (reflects AWS Jan 2023 default encryption)
- Markdown table escaping hardened (all columns)
- HTML report accessibility (ARIA attributes on score ring and severity badges)
- Ruff lint rules expanded (RUF, PIE, RET)
- 179 tests passing

### v0.8.0 -- Diff & CI/CD
- `cloud-audit diff` command -- compare two scans, show new/fixed/changed findings
- Terminal, markdown, and JSON diff output
- Exit code 1 on regression (new findings) for CI gating
- Scope warnings (region/account changes between scans)
- CI/CD examples: daily scan with cache-based diff, post-deploy scan
- 213 tests passing

### v0.9.0 -- Attack Chains (March 2026)
- **Attack chain detection** -- 16 rules that correlate findings into exploitable attack paths
- First open-source CLI scanner with compound risk detection
- Rules based on MITRE ATT&CK, Datadog pathfinding.cloud, and AWS CIRT research
- 5 tiers: Internet Exposure, Missing Controls, Data Protection, Container/Secrets, CI/CD
- Resource relationship collection (EC2->IAM role, Lambda->role, OIDC->policies)
- New checks: aws-iam-007 (OIDC trust policy), aws-ec2-006 (EBS default encryption)
- Enhanced HTML report with executive summary, priority grouping, CIS pass/fail
- 47 checks, 16 attack chains, 246 tests

## What's Next

### v1.0.0 - Production Ready
- **Cost-Security Fusion** - dollar-cost estimates per finding ("$X/month at risk per attack chain")
- **Historical Score Tracking** - persistent score history with trends ("73/100, up from 61 last week")
- **50+ curated checks** - community contributions welcome
- **Show HN launch** - demo refresh, blog post, community push

### v1.1.0 - CI/CD Native
- **GitHub Action** - reusable action for CI integration (`gebalamariusz/cloud-audit-action@v1`)
- **Terraform Drift Detection** - compare scan results against tfstate to find security-relevant drift
- **Root Cause Grouping** - "fix 1 setting, close 12 findings" for account-level misconfigurations
- **More attack chain rules** - expand based on community feedback and new attack research

### v1.2.0 - Enterprise Ready
- **Multi-account scanning** - AWS Organizations support, aggregate attack chains across accounts
- **OTel-Native Security Traces** - emit findings as OpenTelemetry spans for Grafana/Datadog
- **Triage command** - generate suppression YAML from scan results
- **Performance benchmarks** on accounts of various sizes

## Considering

- Azure provider (~25 checks)
- Custom check plugins (user-defined checks via Python or YAML)
- Slack/Teams notifications

## Design Principles

1. **High-signal only** -- if an attacker can't exploit it, the check doesn't exist
2. **Every finding = a ready fix** -- AWS CLI + Terraform HCL + documentation link
3. **Reports for engineers and managers** -- beautiful, useful, actionable
4. **Zero config to start** -- `pip install cloud-audit && cloud-audit scan` gives value immediately
5. **Fast** -- seconds, not hours
6. **CIS mapping included** -- key CIS AWS Foundations Benchmark controls mapped to checks
