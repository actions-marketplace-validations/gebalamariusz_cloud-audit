"""Amazon Inspector v2 checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_inspector_enabled(provider: AWSProvider) -> CheckResult:
    """Check if Amazon Inspector v2 is enabled."""
    result = CheckResult(check_id="aws-inspector-001", check_name="Inspector v2 enabled")

    try:
        for region in provider.regions:
            result.resources_scanned += 1

            try:
                inspector = provider.session.client("inspector2", region_name=region)
                response = inspector.batch_get_account_status(accountIds=[])
                accounts = response.get("accounts", [])

                if not accounts:
                    # No account status returned - Inspector not enabled
                    result.findings.append(
                        Finding(
                            check_id="aws-inspector-001",
                            title=f"Amazon Inspector v2 is not enabled in {region}",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::Inspector2::Enabler",
                            resource_id=f"inspector-{region}",
                            region=region,
                            description=(
                                f"Amazon Inspector v2 is not enabled in {region}. "
                                "Inspector automatically discovers and scans EC2 instances, "
                                "Lambda functions, and ECR container images for software "
                                "vulnerabilities and network exposure."
                            ),
                            recommendation="Enable Amazon Inspector v2 for EC2, ECR, and Lambda scanning.",
                            remediation=Remediation(
                                cli=(f"aws inspector2 enable --resource-types EC2 ECR LAMBDA --region {region}"),
                                terraform=(
                                    'resource "aws_inspector2_enabler" "this" {\n'
                                    "  account_ids    = [data.aws_caller_identity.current.account_id]\n"
                                    '  resource_types = ["EC2", "ECR", "LAMBDA"]\n'
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=[],
                        )
                    )
                    continue

                for account in accounts:
                    state = account.get("state", {})
                    status = state.get("status", "")

                    if status != "ENABLED":
                        # Check which resource types are enabled
                        resource_state = account.get("resourceState", {})
                        disabled_types = []
                        for rtype in ("ec2", "ecr", "lambda", "lambdaCode"):
                            rstate = resource_state.get(rtype, {})
                            if rstate.get("status", "") != "ENABLED":
                                disabled_types.append(rtype.upper())

                        if disabled_types:
                            result.findings.append(
                                Finding(
                                    check_id="aws-inspector-001",
                                    title=f"Amazon Inspector v2 not fully enabled in {region}",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="AWS::Inspector2::Enabler",
                                    resource_id=f"inspector-{region}",
                                    region=region,
                                    description=(
                                        f"Amazon Inspector v2 in {region} has status '{status}'. "
                                        f"Disabled resource types: {', '.join(disabled_types)}. "
                                        "Not all workloads are being scanned for vulnerabilities."
                                    ),
                                    recommendation="Enable Inspector v2 for all resource types (EC2, ECR, Lambda).",
                                    remediation=Remediation(
                                        cli=(
                                            f"aws inspector2 enable --resource-types EC2 ECR LAMBDA --region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_inspector2_enabler" "this" {\n'
                                            "  account_ids    = [data.aws_caller_identity.current.account_id]\n"
                                            '  resource_types = ["EC2", "ECR", "LAMBDA"]\n'
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html",
                                        effort=Effort.LOW,
                                    ),
                                    compliance_refs=[],
                                )
                            )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnauthorizedAccessException"):
                    continue
                # ResourceNotFoundException means Inspector is not enabled
                if error_code == "ResourceNotFoundException":
                    result.findings.append(
                        Finding(
                            check_id="aws-inspector-001",
                            title=f"Amazon Inspector v2 is not enabled in {region}",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::Inspector2::Enabler",
                            resource_id=f"inspector-{region}",
                            region=region,
                            description=(
                                f"Amazon Inspector v2 is not enabled in {region}. "
                                "Inspector automatically discovers and scans EC2 instances, "
                                "Lambda functions, and ECR container images for software "
                                "vulnerabilities and network exposure."
                            ),
                            recommendation="Enable Amazon Inspector v2 for EC2, ECR, and Lambda scanning.",
                            remediation=Remediation(
                                cli=(f"aws inspector2 enable --resource-types EC2 ECR LAMBDA --region {region}"),
                                terraform=(
                                    'resource "aws_inspector2_enabler" "this" {\n'
                                    "  account_ids    = [data.aws_caller_identity.current.account_id]\n"
                                    '  resource_types = ["EC2", "ECR", "LAMBDA"]\n'
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=[],
                        )
                    )
                    continue
                raise
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Inspector checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_inspector_enabled, provider, check_id="aws-inspector-001", category=Category.SECURITY),
    ]
