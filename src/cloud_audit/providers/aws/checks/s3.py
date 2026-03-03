"""S3 security and cost checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


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
