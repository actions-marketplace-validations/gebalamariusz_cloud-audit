<p align="center">
  <img src="assets/logo-nobg.png" alt="cloud-audit logo" width="200">
</p>

<!-- mcp-name: io.github.gebalamariusz/cloud-audit -->
<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Find AWS attack chains and get exact fixes.</strong>
</p>

<p align="center">
  Open-source CLI scanner that correlates findings into exploitable paths<br>
  and generates copy-paste remediation (AWS CLI + Terraform).
</p>

<p align="center">
  Detect exploitable attack paths &nbsp;-&nbsp; Get AWS CLI + Terraform fixes &nbsp;-&nbsp; Run locally, no SaaS required
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/dm/cloud-audit?style=flat" alt="PyPI downloads"></a>
  <a href="https://ghcr.io/gebalamariusz/cloud-audit"><img src="https://img.shields.io/badge/Docker-GHCR-blue?style=flat&logo=docker" alt="Docker"></a>
  <a href="https://www.helpnetsecurity.com/2026/03/11/cloud-audit-open-source-aws-security-scanner/"><img src="https://img.shields.io/badge/Featured_in-HelpNet_Security-blue?style=flat" alt="Featured in HelpNet Security"></a>
  <a href="https://haitmg.pl/cloud-audit/"><img src="https://img.shields.io/badge/Docs-haitmg.pl-blue?style=flat" alt="Documentation"></a>
</p>

<p align="center">
  <a href="https://haitmg.pl/cloud-audit/">Documentation</a> -
  <a href="https://haitmg.pl/cloud-audit/getting-started/quick-start/">Quick Start</a> -
  <a href="https://haitmg.pl/cloud-audit/compliance/cis-aws-v3/">CIS AWS v3.0</a> -
  <a href="https://haitmg.pl/cloud-audit/features/attack-chains/">Attack Chains</a> -
  <a href="https://haitmg.pl/cloud-audit/features/mcp-server/">MCP Server</a>
</p>

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan
```

Uses your default AWS credentials and region. Try without an AWS account:

```bash
cloud-audit demo
```

---

## What You Get

```
+------- Health Score -------+
| 42 / 100                   |   Risk exposure: $725K - $7.3M
+----------------------------+

+---- Attack Chains (3 detected) -----------------------------------+
|  CRITICAL  Internet-Exposed Admin Instance                         |
|            i-0abc123 - public SG + admin IAM role + IMDSv1         |
|            Fix: Restrict security group (effort: LOW)              |
|                                                                    |
|  CRITICAL  CI/CD to Admin Takeover                                 |
|            github-deploy - OIDC no sub + admin policy              |
|            Fix: Add sub condition (effort: LOW)                    |
+--------------------------------------------------------------------+

Findings by severity:  CRITICAL: 3  HIGH: 8  MEDIUM: 12  LOW: 5
```

80 checks across 18 AWS services. Every finding includes AWS CLI + Terraform remediation.

<p align="center">
  <a href="https://www.youtube.com/watch?v=5uHoqggmTB8">
    <img src="https://img.youtube.com/vi/5uHoqggmTB8/hqdefault.jpg" alt="cloud-audit demo video" width="500">
  </a>
  <br>
  <sub>Watch the 1-minute demo</sub>
</p>

If cloud-audit helped you find something you missed, consider giving it a star. It helps others discover the project.

---

## Features

### Attack Chain Detection

Other scanners give you a flat list of findings. cloud-audit correlates them into attack paths an attacker would actually exploit.

```
  Internet --> Public SG --> EC2 (IMDSv1) --> Admin IAM Creds --> Account Takeover
               aws-vpc-002   aws-ec2-004       Detected: AC-01, AC-02
```

Examples from the 20 built-in rules:

| Chain | What it catches |
|---|---|
| Internet-Exposed Admin Instance | Public SG + admin IAM role + IMDSv1 = account takeover |
| CI/CD to Admin Takeover | OIDC without sub condition + admin policy = pipeline hijack |
| SSRF to Credential Theft | Public instance + IMDSv1 + no VPC flow logs = invisible exfiltration |

Based on [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) and [Datadog pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud). [See all 20 rules in the docs](https://haitmg.pl/cloud-audit/features/attack-chains/).

### Copy-Paste Remediation

Every finding includes AWS CLI commands, Terraform HCL, and documentation links. Export all fixes as a runnable script:

```bash
cloud-audit scan --export-fixes fixes.sh
```

### Scan Diff

Compare scans to track drift. Catches ClickOps changes, manual console edits, and regressions that IaC scanning misses.

```bash
cloud-audit diff yesterday.json today.json
```

Exit code 0 = no new findings, 1 = regression. See [daily-scan-with-diff.yml](examples/daily-scan-with-diff.yml) for a CI/CD workflow.

### CIS AWS v3.0 Compliance

Built-in compliance engine for the CIS Amazon Web Services Foundations Benchmark v3.0.0. 55 of 62 recommendations are automated (7 require manual review). Each control has evidence templates for auditors and per-control remediation guidance.

Planned: SOC 2, ISO 27001, BSI C5, HIPAA, NIS2.

### Breach Cost Estimation

Every finding includes a dollar-range risk estimate based on published breach data (IBM Cost of a Data Breach 2024, Verizon DBIR, enforcement actions). Attack chains use compound risk multipliers. Every estimate links to its source.

### MCP Server for AI Agents

Ask Claude Code, Cursor, or VS Code Copilot to scan your AWS account:

```bash
claude mcp add cloud-audit -- uvx --from cloud-audit cloud-audit-mcp
```

6 tools: `scan_aws`, `get_findings`, `get_attack_chains`, `get_remediation`, `get_health_score`, `list_checks`. Free and standalone - no SaaS account needed.

---

## How It Compares

| Feature | Prowler | Trivy | Checkov | cloud-audit |
|---------|---------|-------|---------|-------------|
| Checks | 576 | 517 | 2500+ | **80** |
| Attack chain detection | No | No | No | **20 rules** |
| Remediation per finding | CIS only | No | Links | **100% (CLI + Terraform)** |
| Breach cost estimation | No | No | No | **Per finding + chain** |
| CIS v3.0 compliance engine | Yes | No | No | **62 controls with evidence** |
| MCP server (AI agents) | Paid ($99/mo) | No | No | **Free, standalone** |

cloud-audit has fewer checks than Prowler but deeper output per finding: remediation code, attack chain context, cost estimates, and compliance evidence. If you need exhaustive compliance coverage across multiple clouds, Prowler is the better choice. If you need a focused scan that shows how findings combine into real attack paths and tells you exactly how to fix each one, cloud-audit is built for that.

<sub>Feature snapshot as of March 2026. Verify against upstream docs for the latest details.</sub>

---

## Reports

```bash
cloud-audit scan --format html --output report.html    # Client-ready HTML
cloud-audit scan --format json --output report.json    # Machine-readable
cloud-audit scan --format sarif --output results.sarif # GitHub Code Scanning
cloud-audit scan --format markdown --output report.md  # PR comments
```

Format is auto-detected from file extension.

<p align="center">
  <img src="assets/report-preview.png" alt="cloud-audit HTML report" width="700">
</p>

## Installation

```bash
pip install cloud-audit          # pip (recommended)
pipx install cloud-audit         # pipx (isolated)
docker run ghcr.io/gebalamariusz/cloud-audit scan  # Docker
```

Docker with credentials:

```bash
docker run -v ~/.aws:/home/cloudaudit/.aws:ro ghcr.io/gebalamariusz/cloud-audit scan
```

## Usage

```bash
cloud-audit scan -R                                    # Show remediation
cloud-audit scan --profile prod --regions eu-central-1  # Specific profile/region
cloud-audit scan --regions all                          # All enabled regions
cloud-audit scan --min-severity high                   # Filter by severity
cloud-audit scan --role-arn arn:aws:iam::...:role/audit # Cross-account
cloud-audit scan --quiet                               # Exit code only (CI/CD)
cloud-audit list-checks                                # List all checks
```

| Exit code | Meaning |
|-----------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Scan error |

<details>
<summary>Configuration file</summary>

Create `.cloud-audit.yml` in your project root:

```yaml
provider: aws
regions:
  - eu-central-1
  - eu-west-1
min_severity: medium
exclude_checks:
  - aws-eip-001
suppressions:
  - check_id: aws-vpc-001
    resource_id: vpc-abc123
    reason: "Legacy VPC, migration planned for Q3"
    accepted_by: "jane@example.com"
    expires: "2026-09-30"
```

</details>

<details>
<summary>Environment variables</summary>

| Variable | Example |
|----------|---------|
| `CLOUD_AUDIT_REGIONS` | `eu-central-1,eu-west-1` |
| `CLOUD_AUDIT_MIN_SEVERITY` | `high` |
| `CLOUD_AUDIT_EXCLUDE_CHECKS` | `aws-eip-001,aws-iam-001` |
| `CLOUD_AUDIT_ROLE_ARN` | `arn:aws:iam::...:role/auditor` |

Precedence: CLI flags > env vars > config file > defaults.

</details>

## CI/CD

```yaml
- run: pip install cloud-audit
- run: cloud-audit scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Ready-to-use workflows: [basic scan](examples/github-actions.yml), [daily diff](examples/daily-scan-with-diff.yml), [post-deploy](examples/post-deploy-scan.yml).

## AWS Permissions

cloud-audit requires **read-only** access. Attach `SecurityAudit`:

```bash
aws iam attach-role-policy --role-name auditor --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit never modifies your infrastructure.

## What It Checks

80 checks across IAM, S3, EC2, VPC, RDS, EIP, EFS, CloudTrail, GuardDuty, KMS, CloudWatch, Lambda, ECS, SSM, Secrets Manager, AWS Config, Security Hub, and Account.

<details>
<summary>Full check list (80 checks)</summary>

### IAM (16 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-iam-001` | Critical | Root account without MFA |
| `aws-iam-002` | High | IAM user with console access but no MFA |
| `aws-iam-003` | Medium | Access key older than 90 days |
| `aws-iam-004` | Medium | Access key unused for 45+ days |
| `aws-iam-005` | Critical | IAM policy with Action:\* and Resource:\* |
| `aws-iam-006` | Medium | Password policy below CIS requirements |
| `aws-iam-007` | Critical | OIDC trust policy without sub condition |
| `aws-iam-008` | Critical | Root account has active access keys |
| `aws-iam-009` | Medium | Multiple active access keys per user |
| `aws-iam-010` | Medium | Direct policy attachment on user (not via group) |
| `aws-iam-011` | Medium | No AWSSupportAccess role |
| `aws-iam-012` | Medium | IAM Access Analyzer not enabled |
| `aws-iam-013` | Medium | Expired SSL/TLS certificate in IAM |
| `aws-iam-014` | Medium | AWSCloudShellFullAccess attached |
| `aws-iam-015` | Medium | Root uses virtual MFA (not hardware) |
| `aws-iam-016` | Medium | EC2 instance without IAM role |

### S3 (7 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-s3-001` | High | S3 bucket without public access block |
| `aws-s3-002` | Low | S3 bucket using SSE-S3 instead of SSE-KMS |
| `aws-s3-003` | Low | S3 bucket without versioning |
| `aws-s3-004` | Low | S3 bucket without lifecycle rules |
| `aws-s3-005` | Medium | S3 bucket without access logging |
| `aws-s3-006` | Medium | S3 bucket policy does not deny HTTP |
| `aws-s3-007` | Low | S3 bucket without MFA Delete |

### EC2 (6 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-ec2-001` | High | Publicly shared AMI |
| `aws-ec2-002` | Medium | Unencrypted EBS volume |
| `aws-ec2-003` | Low | Stopped EC2 instance (EBS charges continue) |
| `aws-ec2-004` | High | EC2 instance with IMDSv1 (SSRF risk) |
| `aws-ec2-005` | Low | EC2 instance without termination protection |
| `aws-ec2-006` | Medium | EBS default encryption disabled |

### VPC (5 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-vpc-001` | Medium | Default VPC in use |
| `aws-vpc-002` | Critical | Security group open to 0.0.0.0/0 or ::/0 on sensitive ports |
| `aws-vpc-003` | Medium | VPC without flow logs |
| `aws-vpc-004` | Medium | NACL allows internet access to admin ports |
| `aws-vpc-005` | Medium | Default security group has active rules |

### RDS (4 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-rds-001` | Critical | Publicly accessible RDS instance |
| `aws-rds-002` | High | Unencrypted RDS instance |
| `aws-rds-003` | Medium | Single-AZ RDS instance |
| `aws-rds-004` | Low | RDS auto minor version upgrade disabled |

### CloudTrail (7 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-ct-001` | Critical | No multi-region CloudTrail trail |
| `aws-ct-002` | High | CloudTrail log file validation disabled |
| `aws-ct-003` | Critical | CloudTrail S3 bucket is publicly accessible |
| `aws-ct-004` | High | CloudTrail S3 bucket has no access logging |
| `aws-ct-005` | Medium | CloudTrail not encrypted with KMS |
| `aws-ct-006` | Medium | S3 object-level write events not logged |
| `aws-ct-007` | Medium | S3 object-level read events not logged |

### CloudWatch (15 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-cw-001` | High | No alarm for root account usage |
| `aws-cw-002` | Medium | No alarm for unauthorized API calls |
| `aws-cw-003` | Medium | No alarm for console sign-in without MFA |
| `aws-cw-004` | Medium | No alarm for IAM policy changes |
| `aws-cw-005` | Medium | No alarm for CloudTrail config changes |
| `aws-cw-006` | Medium | No alarm for console auth failures |
| `aws-cw-007` | Medium | No alarm for CMK disable/deletion |
| `aws-cw-008` | Medium | No alarm for S3 bucket policy changes |
| `aws-cw-009` | Medium | No alarm for Config changes |
| `aws-cw-010` | Medium | No alarm for security group changes |
| `aws-cw-011` | Medium | No alarm for NACL changes |
| `aws-cw-012` | Medium | No alarm for network gateway changes |
| `aws-cw-013` | Medium | No alarm for route table changes |
| `aws-cw-014` | Medium | No alarm for VPC changes |
| `aws-cw-015` | Medium | No alarm for Organizations changes |

### Other Services (20 checks)

| ID | Severity | Description |
|----|----------|-------------|
| `aws-gd-001` | High | GuardDuty not enabled |
| `aws-gd-002` | Medium | GuardDuty findings unresolved for 30+ days |
| `aws-cfg-001` | Medium | AWS Config not enabled |
| `aws-cfg-002` | High | AWS Config recorder stopped |
| `aws-kms-001` | Medium | KMS key without automatic rotation |
| `aws-kms-002` | High | KMS key policy with Principal:\* |
| `aws-lambda-001` | High | Lambda function URL with no authentication |
| `aws-lambda-002` | Medium | Lambda running on a deprecated runtime |
| `aws-lambda-003` | High | Potential secrets in Lambda env vars |
| `aws-ecs-001` | Critical | ECS task running in privileged mode |
| `aws-ecs-002` | High | ECS task without log configuration |
| `aws-ecs-003` | Medium | ECS service with Execute Command enabled |
| `aws-ssm-001` | Medium | EC2 instance not managed by SSM |
| `aws-ssm-002` | High | SSM parameter stored as plain String |
| `aws-sm-001` | Medium | Secret without rotation |
| `aws-sm-002` | Low | Secret unused for 90+ days |
| `aws-eip-001` | Low | Unattached Elastic IP |
| `aws-efs-001` | Medium | EFS file system not encrypted |
| `aws-sh-001` | Medium | Security Hub not enabled |
| `aws-account-001` | Medium | No security alternate contact |

</details>

## Alternatives

- **[Prowler](https://github.com/prowler-cloud/prowler)** - 576+ checks, multi-cloud, full CIS coverage, auto-remediation. The most comprehensive open-source scanner.
- **[Trivy](https://github.com/aquasecurity/trivy)** - Container, IaC, and cloud scanner. Strong on containers, growing cloud coverage.
- **[Steampipe](https://github.com/turbot/steampipe)** - SQL-based cloud querying. Very flexible.
- **[AWS Security Hub](https://aws.amazon.com/security-hub/)** - Native AWS service with continuous monitoring. Free 30-day trial.

## Documentation

cloud-audit has grown beyond what a single README can cover. The full documentation is at **[haitmg.pl/cloud-audit](https://haitmg.pl/cloud-audit/)** and includes:

- **[Getting Started](https://haitmg.pl/cloud-audit/getting-started/installation/)** - installation, quick start, demo mode
- **[Compliance](https://haitmg.pl/cloud-audit/compliance/overview/)** - CIS AWS v3.0 with all 62 controls, planned SOC 2, BSI C5, HIPAA, NIS2
- **[Attack Chains](https://haitmg.pl/cloud-audit/features/attack-chains/)** - all 20 rules with MITRE ATT&CK references
- **[MCP Server](https://haitmg.pl/cloud-audit/features/mcp-server/)** - full setup guide for Claude Code, Cursor, VS Code
- **[Configuration](https://haitmg.pl/cloud-audit/configuration/config-file/)** - config file, env vars, suppressions
- **[CI/CD](https://haitmg.pl/cloud-audit/ci-cd/github-actions/)** - GitHub Actions, SARIF, pre-commit hooks
- **[Reports](https://haitmg.pl/cloud-audit/reports/html/)** - HTML, JSON, SARIF, Markdown output formats
- **[All 80 Checks](https://haitmg.pl/cloud-audit/checks/)** - full check reference by service

This README covers the essentials. For compliance framework details, advanced configuration, and per-check documentation, see the full docs.

## What's Next

- SOC 2, BSI C5, HIPAA, NIS2 compliance frameworks
- Terraform drift detection
- Root cause grouping

Past releases: [CHANGELOG.md](CHANGELOG.md)

## Development

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"

pytest -v                          # tests
ruff check src/ tests/             # lint
ruff format --check src/ tests/    # format
mypy src/                          # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new check.

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)
