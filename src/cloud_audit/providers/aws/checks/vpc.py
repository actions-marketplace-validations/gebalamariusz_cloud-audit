"""VPC security checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_default_vpc_in_use(provider: AWSProvider) -> CheckResult:
    """Check if the default VPC has any resources."""
    result = CheckResult(check_id="aws-vpc-001", check_name="Default VPC usage")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                result.resources_scanned += 1

                # Check if any ENIs exist in the default VPC (indicates resources are using it)
                enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
                    "NetworkInterfaces"
                ]

                if enis:
                    result.findings.append(
                        Finding(
                            check_id="aws-vpc-001",
                            title=f"Default VPC in {region} has {len(enis)} network interface(s)",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            description=f"The default VPC ({vpc_id}) in {region} has active resources. Default VPCs have overly permissive networking defaults.",
                            recommendation="Migrate resources to a custom VPC with proper network segmentation and security groups.",
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_open_security_groups(provider: AWSProvider) -> CheckResult:
    """Check for security groups with unrestricted inbound access (0.0.0.0/0)."""
    result = CheckResult(check_id="aws-vpc-002", check_name="Open security groups")

    # Ports that should never be open to the internet
    sensitive_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        5601: "Kibana",
    }

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    result.resources_scanned += 1

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)

                        for ip_range in rule.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp", "")
                            if cidr != "0.0.0.0/0":
                                continue

                            # Check if all traffic is allowed
                            if rule.get("IpProtocol") == "-1":
                                result.findings.append(
                                    Finding(
                                        check_id="aws-vpc-002",
                                        title=f"Security group '{sg_name}' allows ALL inbound traffic from internet",
                                        severity=Severity.CRITICAL,
                                        category=Category.SECURITY,
                                        resource_type="AWS::EC2::SecurityGroup",
                                        resource_id=sg_id,
                                        region=region,
                                        description=f"Security group {sg_id} ({sg_name}) allows all inbound traffic from 0.0.0.0/0.",
                                        recommendation="Restrict inbound rules to specific ports and source IP ranges.",
                                    )
                                )
                                break

                            # Check sensitive ports
                            for port, service in sensitive_ports.items():
                                if from_port <= port <= to_port:
                                    result.findings.append(
                                        Finding(
                                            check_id="aws-vpc-002",
                                            title=f"Security group '{sg_name}' exposes {service} (port {port}) to internet",
                                            severity=Severity.CRITICAL
                                            if port in (22, 3389, 3306, 5432)
                                            else Severity.HIGH,
                                            category=Category.SECURITY,
                                            resource_type="AWS::EC2::SecurityGroup",
                                            resource_id=sg_id,
                                            region=region,
                                            description=f"Security group {sg_id} ({sg_name}) allows inbound {service} (port {port}) from 0.0.0.0/0.",
                                            recommendation=f"Restrict {service} access to specific IP ranges. Use a bastion host or VPN for remote access.",
                                        )
                                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_vpc_flow_logs(provider: AWSProvider) -> CheckResult:
    """Check if VPC flow logs are enabled."""
    result = CheckResult(check_id="aws-vpc-003", check_name="VPC flow logs")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs()["Vpcs"]

            for vpc in vpcs:
                # Skip default VPC — it's a leftover, not user-managed infrastructure
                if vpc.get("IsDefault", False):
                    continue

                vpc_id = vpc["VpcId"]
                result.resources_scanned += 1

                flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]

                if not flow_logs:
                    name_tag = next(
                        (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                        vpc_id,
                    )
                    result.findings.append(
                        Finding(
                            check_id="aws-vpc-003",
                            title=f"VPC '{name_tag}' has no flow logs enabled",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            description=f"VPC {vpc_id} does not have flow logs configured. Network traffic is not being logged.",
                            recommendation="Enable VPC flow logs to CloudWatch Logs or S3 for network traffic monitoring and incident response.",
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all VPC checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_default_vpc_in_use, provider),
        partial(check_open_security_groups, provider),
        partial(check_vpc_flow_logs, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
