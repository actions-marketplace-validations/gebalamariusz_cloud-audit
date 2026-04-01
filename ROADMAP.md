# Roadmap

> Current version: **v1.2.1** (April 2026)

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

### v0.9.1 -- GitHub Action & Pre-commit (March 2026)
- **GitHub Action** -- reusable composite action for CI/CD with SARIF upload, OIDC auth, diff baseline
- **pre-commit hooks** -- scan and diff hooks for the pre-commit framework
- Lambda deprecated runtimes extended with EOL dates (community PR #18)

### v1.0.0 -- Production Ready (March 2026)
- **Breach cost estimation** -- dollar-risk estimates per finding and attack chain with verified source URLs (IBM, Verizon, OCC, MITRE)
- **MCP Server** -- first free, standalone AWS security MCP server. Install: `claude mcp add cloud-audit -- uvx cloud-audit-mcp`
- 278 tests passing

### v1.1.0 -- CIS Compliance Engine (March 2026)
- **CIS AWS Foundations Benchmark v3.0.0** -- 62 controls mapped, 55 automated, per-control evidence and remediation
- `--compliance cis_aws_v3` CLI flag with readiness scoring
- Compliance HTML and Markdown reports (auditor-ready, per-control PASS/FAIL with evidence)
- `list-frameworks` and `show-framework` commands
- 33 new checks (80 total) for full CIS v3.0 automated coverage
- 4 new attack chain rules (20 total) with CIS control mapping
- 3 new service modules (Account, EFS, Security Hub)
- MkDocs documentation site (25 pages) at haitmg.pl/cloud-audit/
- 303 tests passing

### v1.2.0 -- SOC 2 Type II Compliance (April 2026)
- **SOC 2 Type II** compliance mapping -- 43 Trust Services Criteria (AICPA 2017, revised 2022), 24 automated, 19 manual
- `--compliance soc2_type2` CLI flag with readiness scoring
- SOC 2 compliance HTML and Markdown reports (auditor-ready)
- 78 of 80 checks mapped across 12 SOC 2 categories
- 20 attack chain rules mapped to SOC 2 controls
- SOC 2 documentation page
- 335 tests passing

## What's Next

### v1.3.0 - Multi-Framework Compliance & Intelligence
- **BSI C5:2020** compliance mapping (121 criteria -- zero open-source competition)
- **ISO 27001:2022** compliance mapping (93 Annex A controls)
- **HIPAA Security Rule** compliance mapping (36 implementation specifications)
- **NIS2 Directive** compliance mapping (~40 technical measures)
- **Root Cause Grouping** -- "fix 1 setting, close 12 findings" for account-level misconfigurations
- **Historical Score Tracking** -- persistent score history with trends for Type II audits
- Compliance report improvements based on feedback

### v1.4.0 - Enterprise Ready
- **Multi-account scanning** -- AWS Organizations support, aggregate attack chains across accounts
- **Triage command** -- generate suppression YAML from scan results
- **Performance benchmarks** on accounts of various sizes

## Considering

- Azure provider (~25 checks)
- Custom check plugins (user-defined checks via Python or YAML)
- Slack/Teams notifications
- PCI DSS v4.0 compliance mapping
- DORA (EU financial sector) compliance mapping

## Design Principles

1. **High-signal only** -- if an attacker can't exploit it, the check doesn't exist
2. **Every finding = a ready fix** -- AWS CLI + Terraform HCL + documentation link
3. **Compliance-grade output** -- per-control evidence, readiness scoring, auditor-ready reports
4. **Reports for engineers and managers** -- beautiful, useful, actionable
5. **Zero config to start** -- `pip install cloud-audit && cloud-audit scan` gives value immediately
6. **Fast** -- seconds, not hours
