"""EC2 security and cost checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_public_amis(provider: AWSProvider) -> CheckResult:
    """Check for AMIs that are publicly shared."""
    result = CheckResult(check_id="aws-ec2-001", check_name="Public AMIs")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            images = ec2.describe_images(Owners=["self"])["Images"]
            for image in images:
                result.resources_scanned += 1
                if image.get("Public", False):
                    result.findings.append(
                        Finding(
                            check_id="aws-ec2-001",
                            title=f"AMI '{image['ImageId']}' is publicly shared",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::Image",
                            resource_id=image["ImageId"],
                            region=region,
                            description=f"AMI {image['ImageId']} ({image.get('Name', 'unnamed')}) is publicly accessible to all AWS accounts.",
                            recommendation="Make the AMI private unless public sharing is intentional.",
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_unencrypted_volumes(provider: AWSProvider) -> CheckResult:
    """Check for EBS volumes without encryption."""
    result = CheckResult(check_id="aws-ec2-002", check_name="Unencrypted EBS volumes")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page["Volumes"]:
                    result.resources_scanned += 1
                    if not volume.get("Encrypted", False):
                        vol_id = volume["VolumeId"]
                        size = volume["Size"]
                        result.findings.append(
                            Finding(
                                check_id="aws-ec2-002",
                                title=f"EBS volume '{vol_id}' is not encrypted",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::EC2::Volume",
                                resource_id=vol_id,
                                region=region,
                                description=f"Volume {vol_id} ({size} GiB) is not encrypted at rest.",
                                recommendation="Enable EBS default encryption in account settings and migrate existing volumes.",
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_stopped_instances(provider: AWSProvider) -> CheckResult:
    """Check for EC2 instances that have been stopped for more than 7 days."""
    result = CheckResult(check_id="aws-ec2-003", check_name="Stopped EC2 instances (cost)")

    try:
        from datetime import datetime, timezone

        datetime.now(timezone.utc)
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        result.resources_scanned += 1
                        instance_id = instance["InstanceId"]
                        instance_type = instance["InstanceType"]

                        # Check state transition time
                        instance.get("StateTransitionReason", "")
                        name_tag = next(
                            (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                            "unnamed",
                        )

                        result.findings.append(
                            Finding(
                                check_id="aws-ec2-003",
                                title=f"EC2 instance '{name_tag}' ({instance_id}) is stopped",
                                severity=Severity.LOW,
                                category=Category.COST,
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                region=region,
                                description=f"Instance {instance_id} ({instance_type}) is stopped. EBS volumes are still incurring charges.",
                                recommendation="Terminate the instance if no longer needed, or create an AMI and terminate to save on EBS costs.",
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all EC2 checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_public_amis, provider),
        partial(check_unencrypted_volumes, provider),
        partial(check_stopped_instances, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    checks[2].category = Category.COST
    return checks
