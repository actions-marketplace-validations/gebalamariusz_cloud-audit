# Suppressions

Suppress known findings that are accepted risks. Suppressions are defined in `.cloud-audit.yml` and tracked in version control.

```yaml
suppressions:
  - check_id: aws-vpc-001
    resource_id: vpc-abc123
    reason: "Legacy VPC, migration planned for Q3"
    accepted_by: "jane@example.com"
    expires: "2026-09-30"
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `check_id` | Yes | Check ID to suppress (e.g., `aws-vpc-001`). Supports wildcards (`aws-iam-*`) |
| `resource_id` | No | Specific resource to suppress. Supports wildcards. Omit to suppress all resources |
| `reason` | Yes | Why this finding is accepted |
| `accepted_by` | No | Who approved the suppression |
| `expires` | No | Expiry date (YYYY-MM-DD). Finding reappears after this date |

## How It Works

Suppressed findings are filtered from results AFTER the scan completes. The scan still runs all checks - suppressions only affect the output. Suppressed count is shown in the scan summary.

Suppressions match on `check_id + resource_id` combination. Omit `resource_id` to suppress all findings for that check.

## Wildcard Patterns

Both `check_id` and `resource_id` support [fnmatch](https://docs.python.org/3/library/fnmatch.html) wildcard patterns:

```yaml
suppressions:
  # Suppress all CloudWatch alarm checks
  - check_id: "aws-cw-*"
    reason: "CloudWatch alarms managed by separate team"
    accepted_by: "ops@example.com"

  # Suppress specific IAM check for all deploy roles
  - check_id: aws-iam-005
    resource_id: "arn:aws:iam::*:role/deploy-*"
    reason: "Deploy roles reviewed separately"
    accepted_by: "security@example.com"

  # Suppress all checks for dev security groups
  - check_id: "aws-vpc-*"
    resource_id: "sg-dev-*"
    reason: "Dev environment, non-production"
    accepted_by: "team@example.com"
    expires: "2026-12-31"
```

Supported patterns: `*` (any characters), `?` (single character), `[seq]` (character set).
