"""EFS security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_efs_encryption(provider: AWSProvider) -> CheckResult:
    """Check if EFS file systems are encrypted at rest (CIS 2.4.1)."""
    result = CheckResult(check_id="aws-efs-001", check_name="EFS encryption at rest")

    try:
        for region in provider.regions:
            efs = provider.session.client("efs", region_name=region)
            paginator = efs.get_paginator("describe_file_systems")

            for page in paginator.paginate():
                for fs in page["FileSystems"]:
                    fs_id = fs["FileSystemId"]
                    name = fs.get("Name", fs_id)
                    result.resources_scanned += 1

                    if not fs.get("Encrypted", False):
                        result.findings.append(
                            Finding(
                                check_id="aws-efs-001",
                                title=f"EFS file system '{name}' is not encrypted",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::EFS::FileSystem",
                                resource_id=fs_id,
                                region=region,
                                description=(
                                    f"EFS file system '{name}' ({fs_id}) in {region} is not encrypted at rest. "
                                    f"Data stored on the file system can be accessed if the underlying "
                                    f"storage is compromised."
                                ),
                                recommendation=(
                                    "EFS encryption can only be enabled at creation time. "
                                    "Create a new encrypted EFS, migrate data, then delete the old one."
                                ),
                                remediation=Remediation(
                                    cli=(
                                        f"# Create a new encrypted EFS (encryption cannot be added to existing):\n"
                                        f"aws efs create-file-system --encrypted --region {region}\n"
                                        f"# Migrate data from {fs_id} to the new file system using AWS DataSync or rsync"
                                    ),
                                    terraform=(
                                        'resource "aws_efs_file_system" "encrypted" {\n'
                                        "  encrypted  = true\n"
                                        "  kms_key_id = aws_kms_key.efs.arn  # Optional: use custom KMS key\n"
                                        "}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html",
                                    effort=Effort.HIGH,
                                ),
                                compliance_refs=["CIS 2.4.1"],
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all EFS checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_efs_encryption, provider, check_id="aws-efs-001", category=Category.SECURITY),
    ]
