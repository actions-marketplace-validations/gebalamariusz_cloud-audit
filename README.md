<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Open-source AWS security scanner. 46 checks, each with a ready-to-use fix.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/dm/cloud-audit?style=flat" alt="PyPI downloads"></a>
  <a href="https://ghcr.io/gebalamariusz/cloud-audit"><img src="https://img.shields.io/badge/Docker-GHCR-blue?style=flat&logo=docker" alt="Docker"></a>
  <a href="https://www.helpnetsecurity.com/2026/03/11/cloud-audit-open-source-aws-security-scanner/"><img src="https://img.shields.io/badge/Featured_in-HelpNet_Security-blue?style=flat" alt="Featured in HelpNet Security"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/gebalamariusz/cloud-audit/main/assets/demo.gif" alt="cloud-audit terminal demo" width="700">
</p>

cloud-audit scans your AWS account and tells you exactly how to fix what it finds - AWS CLI commands, Terraform HCL, and documentation links you can copy-paste.

46 checks across 15 AWS resource types. Mapped to 16 CIS AWS Foundations Benchmark controls.

**Two things no other open-source CLI scanner does:**

### 1. Every finding includes a copy-paste fix

You don't just get a list of problems - you get the exact commands to fix them:

```
$ cloud-audit scan -R

  CRITICAL  Root account without MFA enabled
  Resource:   arn:aws:iam::123456789012:root
  Compliance: CIS 1.5
  CLI:        aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa
  Terraform:  resource "aws_iam_virtual_mfa_device" "root" { ... }
  Docs:       https://docs.aws.amazon.com/IAM/latest/UserGuide/...
```

### 2. Built-in scan diff - track what changed

Run daily scans and compare them. See what got fixed, what's new, and what stayed the same - without a SaaS dashboard or paid backend.

```
$ cloud-audit diff yesterday.json today.json

╭───────── Score Change ──────────╮
│ 54 -> 68 (+14)                  │
╰─────────────────────────────────╯

Fixed (2):
  CRITICAL  aws-iam-001     root               Root account without MFA
  HIGH      aws-vpc-002     sg-abc123          SG open on port 22

New (1):
  HIGH      aws-rds-001     staging-db         RDS publicly accessible

Unchanged (8):
  ...
```

This catches what IaC scanning misses: ClickOps changes, manual console edits, security group rules someone opened "temporarily" three months ago. Prowler offers similar tracking, but only through their paid cloud platform. Trivy, ScoutSuite, and Steampipe don't have it at all.

Exit code 0 = no new findings, 1 = regression. Plug it into a cron job, get notified when something gets worse. See [daily-scan-with-diff.yml](examples/daily-scan-with-diff.yml) for a ready-to-use GitHub Actions workflow.

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan
```

That's it. Uses your default AWS credentials and region. You'll get a health score and a list of findings in your terminal.

```bash
# Show remediation details for each finding
cloud-audit scan -R

# Specific profile and regions
cloud-audit scan --profile production --regions eu-central-1,eu-west-1

# Export all fixes as a runnable bash script
cloud-audit scan --export-fixes fixes.sh
```

## Try it without an AWS account

```bash
pip install cloud-audit
cloud-audit demo
```

The `demo` command runs a simulated scan with sample data - output format, health score, and remediation details without any AWS credentials.

## Who is this for

- **Small teams without a security team** - get visibility into AWS security without buying a platform
- **DevOps/SRE running pre-deploy checks** - catch misconfigurations before they ship
- **Consultants auditing client accounts** - generate a professional HTML report in one command
- **Teams that want CIS evidence without Security Hub** - 16 CIS controls mapped, included in reports

## What it checks

46 checks across IAM, S3, EC2, EIP, VPC, RDS, Lambda, ECS, CloudTrail, GuardDuty, KMS, SSM, Secrets Manager, CloudWatch, and AWS Config.

**By severity:** 8 Critical, 14 High, 16 Medium, 8 Low.

Every check answers one question: *would an attacker exploit this?* If not, the check doesn't exist.

<details>
<summary>Full check list</summary>

### Security

| ID | Severity | Description |
|----|----------|-------------|
| `aws-iam-001` | Critical | Root account without MFA |
| `aws-iam-002` | High | IAM user with console access but no MFA |
| `aws-iam-003` | Medium | Access key older than 90 days |
| `aws-iam-004` | Medium | Access key unused for 30+ days |
| `aws-iam-005` | Critical | IAM policy with Action: \* and Resource: \* |
| `aws-iam-006` | Medium | Password policy below CIS requirements |
| `aws-iam-007` | Critical | OIDC trust policy without sub condition |
| `aws-s3-001` | High | S3 bucket without public access block |
| `aws-s3-002` | Low | S3 bucket using SSE-S3 instead of SSE-KMS |
| `aws-s3-005` | Medium | S3 bucket without access logging |
| `aws-ec2-001` | High | Publicly shared AMI |
| `aws-ec2-002` | Medium | Unencrypted EBS volume |
| `aws-ec2-004` | High | EC2 instance with IMDSv1 (SSRF risk) |
| `aws-vpc-001` | Medium | Default VPC in use |
| `aws-vpc-002` | Critical | Security group open to 0.0.0.0/0 on sensitive ports |
| `aws-vpc-003` | Medium | VPC without flow logs |
| `aws-vpc-004` | Medium | Network ACL allows all inbound from 0.0.0.0/0 |
| `aws-rds-001` | Critical | Publicly accessible RDS instance |
| `aws-rds-002` | High | Unencrypted RDS instance |
| `aws-ct-001` | Critical | No multi-region CloudTrail trail |
| `aws-ct-002` | High | CloudTrail log file validation disabled |
| `aws-ct-003` | Critical | CloudTrail S3 bucket is publicly accessible |
| `aws-gd-001` | High | GuardDuty not enabled |
| `aws-gd-002` | Medium | GuardDuty findings unresolved for 30+ days |
| `aws-cfg-001` | Medium | AWS Config not enabled |
| `aws-cfg-002` | High | AWS Config recorder stopped |
| `aws-kms-001` | Medium | KMS key without automatic rotation |
| `aws-kms-002` | High | KMS key policy with Principal: \* |
| `aws-cw-001` | High | No CloudWatch alarm for root account usage |
| `aws-lambda-001` | High | Lambda function URL with no authentication |
| `aws-lambda-002` | Medium | Lambda running on a deprecated runtime |
| `aws-lambda-003` | High | Potential secrets in Lambda environment variables |
| `aws-ecs-001` | Critical | ECS task running in privileged mode |
| `aws-ecs-002` | High | ECS task without log configuration |
| `aws-ecs-003` | Medium | ECS service with Execute Command enabled |
| `aws-ssm-001` | Medium | EC2 instance not managed by Systems Manager |
| `aws-ssm-002` | High | SSM parameter with secret stored as plain String |
| `aws-sm-001` | Medium | Secrets Manager secret without rotation |

### Cost

| ID | Severity | Description |
|----|----------|-------------|
| `aws-eip-001` | Low | Unattached Elastic IP ($3.65/month) |
| `aws-ec2-003` | Low | Stopped EC2 instance (EBS charges continue) |
| `aws-s3-004` | Low | S3 bucket without lifecycle rules |
| `aws-sm-002` | Low | Secrets Manager secret unused for 90+ days ($0.40/month) |

### Reliability

| ID | Severity | Description |
|----|----------|-------------|
| `aws-s3-003` | Low | S3 bucket without versioning |
| `aws-rds-003` | Medium | Single-AZ RDS instance (no automatic failover) |
| `aws-rds-004` | Low | RDS auto minor version upgrade disabled |
| `aws-ec2-005` | Low | EC2 instance without termination protection |

</details>

## Export fixes as a script

```bash
cloud-audit scan --export-fixes fixes.sh
```

The script is commented and uses `set -e` - review it, uncomment what you want to apply, and run.

## Reports

<p align="center">
  <img src="https://raw.githubusercontent.com/gebalamariusz/cloud-audit/main/assets/report-preview.png" alt="cloud-audit HTML report" width="700">
</p>

```bash
# HTML report (dark-mode, self-contained, client-ready)
cloud-audit scan --format html --output report.html

# JSON
cloud-audit scan --format json --output report.json

# SARIF (GitHub Code Scanning integration)
cloud-audit scan --format sarif --output results.sarif

# Markdown (for PR comments)
cloud-audit scan --format markdown --output report.md
```

Format is auto-detected from file extension when using `--output`.

## Installation

### pip (recommended)

```bash
pip install cloud-audit
```

### pipx (isolated environment)

```bash
pipx install cloud-audit
```

### Docker

```bash
docker run ghcr.io/gebalamariusz/cloud-audit scan
```

Mount your AWS credentials:

```bash
docker run -v ~/.aws:/home/cloudaudit/.aws:ro ghcr.io/gebalamariusz/cloud-audit scan
```

### From source

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e .
```

## Usage

```bash
# Scan all enabled regions
cloud-audit scan --regions all

# Filter by category
cloud-audit scan --categories security,cost

# Filter by minimum severity
cloud-audit scan --min-severity high

# Cross-account scanning via IAM role
cloud-audit scan --role-arn arn:aws:iam::987654321098:role/auditor

# Quiet mode (exit code only - for CI/CD)
cloud-audit scan --quiet

# List all available checks
cloud-audit list-checks
cloud-audit list-checks --categories security
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (after suppressions and severity filter) |
| 1 | Findings detected |
| 2 | Scan error (bad credentials, invalid config) |

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
  - aws-ec2-003
suppressions:
  - check_id: aws-vpc-001
    resource_id: vpc-abc123
    reason: "Legacy VPC, migration planned for Q3"
    accepted_by: "jane@example.com"
    expires: "2026-09-30"
```

Auto-detected from the current directory. Override with `--config path/to/.cloud-audit.yml`.

</details>

<details>
<summary>Environment variables</summary>

| Variable | Description | Example |
|----------|-------------|---------|
| `CLOUD_AUDIT_REGIONS` | Comma-separated regions | `eu-central-1,eu-west-1` |
| `CLOUD_AUDIT_MIN_SEVERITY` | Minimum severity filter | `high` |
| `CLOUD_AUDIT_EXCLUDE_CHECKS` | Comma-separated check IDs to skip | `aws-eip-001,aws-iam-001` |
| `CLOUD_AUDIT_ROLE_ARN` | IAM role ARN for cross-account | `arn:aws:iam::...:role/auditor` |

</details>

**Precedence:** CLI flags > environment variables > config file > defaults.

## CI/CD Integration

### GitHub Actions

```yaml
- run: pip install cloud-audit
- run: cloud-audit scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

This gives you findings in the GitHub Security tab (via SARIF). Add `--format markdown` for PR comments.

### Ready-to-use workflows

| Workflow | Use case |
|----------|----------|
| [github-actions.yml](examples/github-actions.yml) | Basic scan with SARIF upload and PR comments |
| [daily-scan-with-diff.yml](examples/daily-scan-with-diff.yml) | Scheduled daily scan + diff to catch drift |
| [post-deploy-scan.yml](examples/post-deploy-scan.yml) | Scan before and after `terraform apply` |

**Daily diff** is the most common setup - it catches ClickOps changes, manual console edits, and regressions that IaC scanning can't see (because IaC scans code, not live AWS).

## AWS Permissions

cloud-audit requires **read-only** access. Attach the AWS-managed `SecurityAudit` policy:

```bash
aws iam attach-role-policy \
  --role-name auditor-role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit never modifies your infrastructure. It only makes read API calls.

## Health Score

Starts at 100, decreases per finding:

| Severity | Points deducted |
|----------|----------------|
| Critical | -20 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

80+ is good, 50-79 needs attention, below 50 requires immediate action.

## Alternatives

There are mature tools in this space. Pick the right one for your use case:

- **[Prowler](https://github.com/prowler-cloud/prowler)** - 576+ checks across AWS/Azure/GCP, full CIS benchmark coverage, auto-remediation with `--fix`. The most comprehensive open-source scanner. Best for teams that need exhaustive compliance audits and don't mind longer scan times.
- **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** - Multi-cloud scanner with an interactive HTML report. No releases in over 12 months - effectively unmaintained.
- **[Trivy](https://github.com/aquasecurity/trivy)** - Container, IaC, and cloud scanner. Strong on containers, growing cloud coverage (~517 cloud checks).
- **[Steampipe](https://github.com/turbot/steampipe)** - SQL-based cloud querying. Very flexible, but requires writing or configuring queries.
- **[AWS Security Hub](https://aws.amazon.com/security-hub/)** - Native AWS service with continuous monitoring and ~223 checks. Free 30-day trial, then charges per check evaluation.

cloud-audit fills a specific niche: a focused audit with copy-paste remediation for each finding. If you need full CIS compliance coverage, Prowler is the better choice. If you need a quick scan that tells you exactly how to fix each issue, cloud-audit is built for that.

## What's next

- Enhanced HTML reports with executive summary
- GitHub Action for easier CI integration
- Azure provider

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
