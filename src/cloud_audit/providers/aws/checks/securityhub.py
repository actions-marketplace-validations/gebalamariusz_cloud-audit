"""Security Hub checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_security_hub_enabled(provider: AWSProvider) -> CheckResult:
    """Check if AWS Security Hub is enabled (CIS 4.16)."""
    result = CheckResult(check_id="aws-sh-001", check_name="Security Hub enabled")

    try:
        for region in provider.regions:
            result.resources_scanned += 1
            try:
                sh = provider.session.client("securityhub", region_name=region)
                sh.describe_hub()
                # If no exception, Security Hub is enabled
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("InvalidAccessException", "ResourceNotFoundException"):
                    result.findings.append(
                        Finding(
                            check_id="aws-sh-001",
                            title=f"Security Hub is not enabled in {region}",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::SecurityHub::Hub",
                            resource_id=region,
                            region=region,
                            description=(
                                f"AWS Security Hub is not enabled in {region}. "
                                f"Security Hub provides a comprehensive view of security findings "
                                f"from multiple AWS services and third-party tools."
                            ),
                            recommendation=f"Enable Security Hub in {region} with CIS AWS Foundations standard.",
                            remediation=Remediation(
                                cli=(
                                    f"aws securityhub enable-security-hub --enable-default-standards --region {region}"
                                ),
                                terraform=(
                                    'resource "aws_securityhub_account" "main" {}\n\n'
                                    'resource "aws_securityhub_standards_subscription" "cis" {\n'
                                    '  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0"\n'
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 4.16"],
                        )
                    )
                # Other errors (throttling, etc.) - skip silently
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Security Hub checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_security_hub_enabled, provider, check_id="aws-sh-001", category=Category.SECURITY),
    ]
