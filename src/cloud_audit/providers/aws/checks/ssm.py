"""SSM (Systems Manager) security checks."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn

_SECRET_PATTERNS = re.compile(
    r"(secret|password|api.?key|token|private.?key|credential|db.?pass)",
    re.IGNORECASE,
)


def check_ec2_not_managed(provider: AWSProvider) -> CheckResult:
    """Check for running EC2 instances not managed by SSM."""
    result = CheckResult(check_id="aws-ssm-001", check_name="EC2 not managed by SSM")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            ssm = provider.session.client("ssm", region_name=region)

            # Get all running instances
            running_ids: set[str] = set()
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        running_ids.add(inst["InstanceId"])

            if not running_ids:
                continue

            # Get SSM managed instances
            managed_ids: set[str] = set()
            ssm_paginator = ssm.get_paginator("describe_instance_information")
            for page in ssm_paginator.paginate():
                for info in page["InstanceInformationList"]:
                    managed_ids.add(info["InstanceId"])

            for instance_id in running_ids:
                result.resources_scanned += 1
                if instance_id not in managed_ids:
                    result.findings.append(
                        Finding(
                            check_id="aws-ssm-001",
                            title=f"EC2 instance '{instance_id}' is not managed by SSM",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::Instance",
                            resource_id=instance_id,
                            region=region,
                            description=f"Instance {instance_id} is running but not registered with AWS Systems Manager. You cannot patch, inventory, or manage it remotely.",
                            recommendation="Install the SSM Agent and attach the AmazonSSMManagedInstanceCore IAM policy to the instance role.",
                            remediation=Remediation(
                                cli=(
                                    "# Attach SSM managed policy to the instance role:\n"
                                    "aws iam attach-role-policy --role-name INSTANCE_ROLE "
                                    "--policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore\n"
                                    "# SSM Agent is pre-installed on Amazon Linux 2 and recent Ubuntu AMIs.\n"
                                    "# For other OS: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-install-ssm-agent.html"
                                ),
                                terraform=(
                                    'resource "aws_iam_role_policy_attachment" "ssm" {\n'
                                    "  role       = aws_iam_role.instance_role.name\n"
                                    '  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"\n'
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-setting-up.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_insecure_parameters(provider: AWSProvider) -> CheckResult:
    """Check for SSM parameters that look like secrets but are not SecureString."""
    result = CheckResult(check_id="aws-ssm-002", check_name="SSM insecure parameters")

    try:
        for region in provider.regions:
            ssm = provider.session.client("ssm", region_name=region)
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for param in page["Parameters"]:
                    result.resources_scanned += 1
                    name = param["Name"]
                    param_type = param.get("Type", "")

                    if param_type != "SecureString" and _SECRET_PATTERNS.search(name):
                        result.findings.append(
                            Finding(
                                check_id="aws-ssm-002",
                                title=f"SSM parameter '{name}' looks like a secret but is type '{param_type}'",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="AWS::SSM::Parameter",
                                resource_id=name,
                                region=region,
                                description=f"Parameter '{name}' matches secret-like naming patterns but is stored as '{param_type}' instead of SecureString. The value is not encrypted at rest.",
                                recommendation="Recreate the parameter as SecureString to encrypt the value with KMS.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Get current value, then recreate as SecureString:\n"
                                        f"VALUE=$(aws ssm get-parameter --name '{name}' --with-decryption --query 'Parameter.Value' --output text --region {region})\n"
                                        f"aws ssm put-parameter --name '{name}' --value \"$VALUE\" "
                                        f"--type SecureString --overwrite --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_ssm_parameter" "{name.replace("/", "_").lstrip("_")}" {{\n'
                                        f'  name  = "{name}"\n'
                                        f'  type  = "SecureString"  # Not String\n'
                                        f"  value = var.secret_value\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-securestring.html",
                                    effort=Effort.LOW,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_patch_compliance(provider: AWSProvider) -> CheckResult:
    """Check EC2 instances patch compliance via SSM."""
    result = CheckResult(check_id="aws-ssm-003", check_name="SSM patch compliance")

    try:
        for region in provider.regions:
            ssm = provider.session.client("ssm", region_name=region)
            ec2 = provider.session.client("ec2", region_name=region)

            # Get all running instances
            running_ids: set[str] = set()
            try:
                ec2_paginator = ec2.get_paginator("describe_instances")
                for page in ec2_paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                    for res in page["Reservations"]:
                        for inst in res["Instances"]:
                            running_ids.add(inst["InstanceId"])
            except Exception:
                continue

            if not running_ids:
                continue

            # Get patch states for instances
            patched_ids: set[str] = set()
            try:
                ssm_paginator = ssm.get_paginator("describe_instance_patch_states")
                for page in ssm_paginator.paginate():
                    for patch_state in page.get("InstancePatchStates", []):
                        instance_id = patch_state.get("InstanceId", "")
                        if instance_id not in running_ids:
                            continue

                        patched_ids.add(instance_id)
                        result.resources_scanned += 1

                        missing_count = patch_state.get("MissingCount", 0)
                        failed_count = patch_state.get("FailedCount", 0)

                        if missing_count > 0 or failed_count > 0:
                            issues = []
                            if missing_count > 0:
                                issues.append(f"{missing_count} missing")
                            if failed_count > 0:
                                issues.append(f"{failed_count} failed")
                            issue_str = ", ".join(issues)

                            result.findings.append(
                                Finding(
                                    check_id="aws-ssm-003",
                                    title=f"Instance '{instance_id}' has {issue_str} patch(es)",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="AWS::EC2::Instance",
                                    resource_id=instance_id,
                                    region=region,
                                    description=(
                                        f"Instance {instance_id} has {issue_str} patches. "
                                        "Unpatched instances are vulnerable to known exploits "
                                        "and may not meet compliance requirements."
                                    ),
                                    recommendation="Run the AWS-RunPatchBaseline document to apply missing patches.",
                                    remediation=Remediation(
                                        cli=(
                                            f"aws ssm send-command \\\n"
                                            f"  --document-name AWS-RunPatchBaseline \\\n"
                                            f"  --targets Key=InstanceIds,Values={instance_id} \\\n"
                                            f"  --parameters Operation=Install \\\n"
                                            f"  --region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_ssm_patch_baseline" "this" {\n'
                                            '  name             = "custom-patch-baseline"\n'
                                            '  operating_system = "AMAZON_LINUX_2"\n'
                                            "\n"
                                            "  approval_rule {\n"
                                            "    approve_after_days = 7\n"
                                            '    compliance_level   = "CRITICAL"\n'
                                            "\n"
                                            "    patch_filter {\n"
                                            '      key    = "CLASSIFICATION"\n'
                                            '      values = ["Security", "Bugfix"]\n'
                                            "    }\n"
                                            "  }\n"
                                            "}\n"
                                            "\n"
                                            'resource "aws_ssm_patch_group" "this" {\n'
                                            "  baseline_id = aws_ssm_patch_baseline.this.id\n"
                                            '  patch_group = "production"\n'
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html",
                                        effort=Effort.MEDIUM,
                                    ),
                                    compliance_refs=[],
                                )
                            )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException",):
                    continue
                raise

            # Flag running instances with no patch data at all
            unscanned_ids = running_ids - patched_ids
            for instance_id in unscanned_ids:
                result.resources_scanned += 1
                result.findings.append(
                    Finding(
                        check_id="aws-ssm-003",
                        title=f"Instance '{instance_id}' has no patch compliance data",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::EC2::Instance",
                        resource_id=instance_id,
                        region=region,
                        description=(
                            f"Instance {instance_id} has no patch compliance data in SSM. "
                            "Either the instance is not managed by SSM or patch scanning "
                            "has never been executed. Patch status is unknown."
                        ),
                        recommendation="Ensure the SSM Agent is installed, the instance has the SSM IAM policy, and run a patch scan.",
                        remediation=Remediation(
                            cli=(
                                f"# Scan patches (does not install):\n"
                                f"aws ssm send-command \\\n"
                                f"  --document-name AWS-RunPatchBaseline \\\n"
                                f"  --targets Key=InstanceIds,Values={instance_id} \\\n"
                                f"  --parameters Operation=Scan \\\n"
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_ssm_patch_baseline" "this" {\n'
                                '  name             = "custom-patch-baseline"\n'
                                '  operating_system = "AMAZON_LINUX_2"\n'
                                "\n"
                                "  approval_rule {\n"
                                "    approve_after_days = 7\n"
                                '    compliance_level   = "CRITICAL"\n'
                                "\n"
                                "    patch_filter {\n"
                                '      key    = "CLASSIFICATION"\n'
                                '      values = ["Security", "Bugfix"]\n'
                                "    }\n"
                                "  }\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all SSM checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_ec2_not_managed, provider, check_id="aws-ssm-001", category=Category.SECURITY),
        make_check(check_insecure_parameters, provider, check_id="aws-ssm-002", category=Category.SECURITY),
        make_check(check_patch_compliance, provider, check_id="aws-ssm-003", category=Category.SECURITY),
    ]
