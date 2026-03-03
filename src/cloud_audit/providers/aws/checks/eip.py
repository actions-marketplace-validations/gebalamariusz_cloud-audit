"""Elastic IP cost checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_unattached_eips(provider: AWSProvider) -> CheckResult:
    """Check for Elastic IPs that are not associated with any resource."""
    result = CheckResult(check_id="aws-eip-001", check_name="Unattached Elastic IPs")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            addresses = ec2.describe_addresses()["Addresses"]

            for addr in addresses:
                result.resources_scanned += 1
                if not addr.get("AssociationId"):
                    eip = addr.get("PublicIp", addr.get("AllocationId", "unknown"))
                    result.findings.append(
                        Finding(
                            check_id="aws-eip-001",
                            title=f"Elastic IP {eip} is not attached to any resource",
                            severity=Severity.LOW,
                            category=Category.COST,
                            resource_type="AWS::EC2::EIP",
                            resource_id=addr.get("AllocationId", eip),
                            region=region,
                            description=f"Elastic IP {eip} is allocated but not associated. Unattached EIPs cost ~$3.65/month.",
                            recommendation="Release the Elastic IP if no longer needed, or associate it with an instance/NAT gateway.",
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all EIP checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_unattached_eips, provider),
    ]
    for fn in checks:
        fn.category = Category.COST
    return checks
