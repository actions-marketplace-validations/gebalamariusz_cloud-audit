"""RDS security and reliability checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_rds_public_access(provider: AWSProvider) -> CheckResult:
    """Check for RDS instances that are publicly accessible."""
    result = CheckResult(check_id="aws-rds-001", check_name="Public RDS instances")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if db.get("PubliclyAccessible", False):
                        result.findings.append(
                            Finding(
                                check_id="aws-rds-001",
                                title=f"RDS instance '{db_id}' is publicly accessible",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' ({db['Engine']}) has PubliclyAccessible=true.",
                                recommendation="Disable public access and use private subnets. Connect via VPN or bastion host.",
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_rds_encryption(provider: AWSProvider) -> CheckResult:
    """Check for RDS instances without encryption at rest."""
    result = CheckResult(check_id="aws-rds-002", check_name="RDS encryption at rest")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if not db.get("StorageEncrypted", False):
                        result.findings.append(
                            Finding(
                                check_id="aws-rds-002",
                                title=f"RDS instance '{db_id}' is not encrypted at rest",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                                recommendation="Enable encryption at rest. Note: existing instances must be migrated via snapshot restore.",
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_rds_multi_az(provider: AWSProvider) -> CheckResult:
    """Check for production RDS instances without Multi-AZ."""
    result = CheckResult(check_id="aws-rds-003", check_name="RDS Multi-AZ")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if not db.get("MultiAZ", False):
                        # Only flag non-micro/small instances (likely production)
                        instance_class = db.get("DBInstanceClass", "")
                        if "micro" in instance_class or "small" in instance_class:
                            continue

                        result.findings.append(
                            Finding(
                                check_id="aws-rds-003",
                                title=f"RDS instance '{db_id}' is not Multi-AZ",
                                severity=Severity.MEDIUM,
                                category=Category.RELIABILITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' ({instance_class}) does not have Multi-AZ failover enabled.",
                                recommendation="Enable Multi-AZ for production databases to provide automatic failover.",
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all RDS checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_rds_public_access, provider),
        partial(check_rds_encryption, provider),
        partial(check_rds_multi_az, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    checks[2].category = Category.RELIABILITY
    return checks
