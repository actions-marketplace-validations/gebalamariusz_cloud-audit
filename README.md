<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Open-source AWS security scanner. 45 checks, each with a ready-to-use fix.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/gebalamariusz/cloud-audit/main/assets/demo.gif" alt="cloud-audit terminal demo" width="700">
</p>

cloud-audit scans your AWS account for security misconfigurations and gives you a finding-by-finding remediation plan - AWS CLI commands, Terraform HCL, and documentation links you can copy-paste to fix each issue.

It runs 45 curated checks across 15 AWS services, mapped to 16 CIS AWS Foundations Benchmark controls.

## Try it without an AWS account

```bash
pip install cloud-audit
cloud-audit demo
```

The `demo` command runs a simulated scan with sample data. You can see the output format, health score, and remediation details without any AWS credentials.

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

## Who is this for

- **Small teams (1-10 people) without a dedicated security team** - get visibility into your AWS security posture without buying a platform
- **DevOps/SRE engineers running a pre-deploy check** - scan before shipping, catch misconfigurations early
- **Consultants doing client audits** - generate a professional HTML report you can hand to a client
- **Teams that need CIS compliance evidence without paying for Security Hub** - 16 CIS controls mapped and included in reports

## What it checks

45 checks across IAM, S3, EC2, VPC, RDS, Lambda, ECS, CloudTrail, GuardDuty, KMS, SSM, Secrets Manager, CloudWatch, and AWS Config.

**By severity:** 6 Critical, 13 High, 16 Medium, 10 Low.

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
| `aws-s3-001` | High | S3 bucket without public access block |
| `aws-s3-002` | Medium | S3 bucket without encryption at rest |
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

## Every finding includes a fix

This is what makes cloud-audit different from most scanners. Run with `-R` to see remediation for each finding:

```
$ cloud-audit scan -R

  CRITICAL  Root account without MFA enabled
  Resource:   arn:aws:iam::123456789012:root
  Compliance: CIS 1.5
  Effort:     LOW
  CLI:        aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa
  Terraform:  resource "aws_iam_virtual_mfa_device" "root" { ... }
  Docs:       https://docs.aws.amazon.com/IAM/latest/UserGuide/...

  CRITICAL  Security group open to 0.0.0.0/0 on port 22
  Resource:   sg-0a1b2c3d4e5f67890
  Compliance: CIS 5.2
  CLI:        aws ec2 revoke-security-group-ingress --group-id sg-... --port 22
  Terraform:  resource "aws_security_group_rule" "ssh_restricted" { ... }
```

Or export all fixes as a bash script:

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

### Configuration file

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

**Precedence:** CLI flags > environment variables > config file > defaults.

### Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CLOUD_AUDIT_REGIONS` | Comma-separated regions | `eu-central-1,eu-west-1` |
| `CLOUD_AUDIT_MIN_SEVERITY` | Minimum severity filter | `high` |
| `CLOUD_AUDIT_EXCLUDE_CHECKS` | Comma-separated check IDs to skip | `aws-eip-001,aws-iam-001` |
| `CLOUD_AUDIT_ROLE_ARN` | IAM role ARN for cross-account | `arn:aws:iam::...:role/auditor` |

## CI/CD Integration

### GitHub Actions

```yaml
name: Cloud Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write
  contents: read
  security-events: write
  actions: read
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install cloud-audit
        run: pip install cloud-audit

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/cloud-audit-github
          aws-region: eu-central-1

      - name: Scan (SARIF)
        continue-on-error: true
        run: cloud-audit scan --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: cloud-audit

      - name: Scan (Markdown)
        if: github.event_name == 'pull_request'
        continue-on-error: true
        run: cloud-audit scan --format markdown --output report.md

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: report.md
```

This gives you findings in the GitHub Security tab (via SARIF) and a Markdown summary on every PR.

The example uses **OIDC** - GitHub generates a short-lived token per workflow run, no static keys stored.

<details>
<summary>OIDC setup instructions</summary>

1. Create an [OIDC Identity Provider](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) in your AWS account with provider URL `https://token.actions.githubusercontent.com` and audience `sts.amazonaws.com`.

2. Create an IAM role with the `SecurityAudit` managed policy and this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/YOUR_REPO:*"
      }
    }
  }]
}
```

3. Replace `role-to-assume` in the workflow with your role ARN.

</details>

<details>
<summary>Static credentials fallback</summary>

```yaml
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: eu-central-1
```

</details>

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

## Roadmap

- ~~**v0.1.0** - 17 AWS checks, CLI, HTML/JSON reports~~
- ~~**v0.2.0** - Remediation engine (CLI + Terraform), CIS Benchmark mapping~~
- ~~**v0.3.0** - CloudTrail, GuardDuty, Config, KMS, CloudWatch checks (27 total)~~
- ~~**v0.4.0** - Lambda, ECS, SSM, Secrets Manager checks (42 total)~~
- ~~**v0.5.1** - SARIF output, config file, suppressions, Markdown reports (45 total)~~
- **v1.0.0** - Enhanced HTML reports, scan diff/compare

See [ROADMAP.md](ROADMAP.md) for details.

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
