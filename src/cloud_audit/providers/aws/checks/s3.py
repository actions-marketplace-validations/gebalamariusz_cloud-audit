"""S3 security and cost checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def _s3_public_access_remediation(name: str) -> Remediation:
    return Remediation(
        cli=(
            f"aws s3api put-public-access-block --bucket {name} "
            f"--public-access-block-configuration "
            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
            f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        terraform=(
            f'resource "aws_s3_bucket_public_access_block" "{name}" {{\n'
            f'  bucket                  = "{name}"\n'
            f"  block_public_acls       = true\n"
            f"  ignore_public_acls      = true\n"
            f"  block_public_policy     = true\n"
            f"  restrict_public_buckets = true\n"
            f"}}"
        ),
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        effort=Effort.LOW,
    )


def check_public_buckets(provider: AWSProvider) -> CheckResult:
    """Check for S3 buckets with public access."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-001", check_name="Public S3 buckets")

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                public_access = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                all_blocked = all(
                    [
                        public_access.get("BlockPublicAcls", False),
                        public_access.get("IgnorePublicAcls", False),
                        public_access.get("BlockPublicPolicy", False),
                        public_access.get("RestrictPublicBuckets", False),
                    ]
                )
                if not all_blocked:
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-001",
                            title=f"S3 bucket '{name}' does not block all public access",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' has incomplete public access block configuration.",
                            recommendation="Enable all four public access block settings unless the bucket explicitly needs public access.",
                            remediation=_s3_public_access_remediation(name),
                            compliance_refs=["CIS 2.1.5"],
                        )
                    )
            except s3.exceptions.ClientError:
                # No public access block configured at all
                result.findings.append(
                    Finding(
                        check_id="aws-s3-001",
                        title=f"S3 bucket '{name}' has no public access block",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::S3::Bucket",
                        resource_id=name,
                        description=f"Bucket '{name}' does not have a public access block configuration.",
                        recommendation="Add a public access block to the bucket with all four settings enabled.",
                        remediation=_s3_public_access_remediation(name),
                        compliance_refs=["CIS 2.1.5"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_encryption(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have default encryption enabled."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-002", check_name="S3 bucket encryption")

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-002",
                            title=f"S3 bucket '{name}' has no default encryption",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' does not have default server-side encryption configured.",
                            recommendation="Enable default encryption with SSE-S3 (AES-256) or SSE-KMS.",
                            remediation=Remediation(
                                cli=(
                                    f"aws s3api put-bucket-encryption --bucket {name} "
                                    f"--server-side-encryption-configuration "
                                    f'\'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\''
                                ),
                                terraform=(
                                    f'resource "aws_s3_bucket_server_side_encryption_configuration" "{name}" {{\n'
                                    f'  bucket = "{name}"\n'
                                    f"  rule {{\n"
                                    f"    apply_server_side_encryption_by_default {{\n"
                                    f'      sse_algorithm = "AES256"\n'
                                    f"    }}\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 2.1.1"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_versioning(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have versioning enabled."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-003", check_name="S3 bucket versioning")

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")

            if status != "Enabled":
                result.findings.append(
                    Finding(
                        check_id="aws-s3-003",
                        title=f"S3 bucket '{name}' does not have versioning enabled",
                        severity=Severity.LOW,
                        category=Category.RELIABILITY,
                        resource_type="AWS::S3::Bucket",
                        resource_id=name,
                        description=f"Bucket '{name}' versioning is '{status}'. Without versioning, deleted or overwritten objects cannot be recovered.",
                        recommendation="Enable versioning to protect against accidental deletion or overwrites.",
                        remediation=Remediation(
                            cli=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                            terraform=(
                                f'resource "aws_s3_bucket_versioning" "{name}" {{\n'
                                f'  bucket = "{name}"\n'
                                f"  versioning_configuration {{\n"
                                f'    status = "Enabled"\n'
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                            effort=Effort.LOW,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all S3 checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_public_buckets, provider),
        partial(check_bucket_encryption, provider),
        partial(check_bucket_versioning, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    checks[2].category = Category.RELIABILITY
    return checks
