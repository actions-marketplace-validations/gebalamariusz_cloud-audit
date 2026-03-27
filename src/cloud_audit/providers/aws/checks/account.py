"""AWS Account-level checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_security_contact(provider: AWSProvider) -> CheckResult:
    """Check if a security alternate contact is registered (CIS 1.2)."""
    result = CheckResult(check_id="aws-account-001", check_name="Security contact registered")

    try:
        account = provider.session.client("account")
        result.resources_scanned = 1

        try:
            account.get_alternate_contact(AlternateContactType="SECURITY")
            # If no exception, security contact exists
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                result.findings.append(
                    Finding(
                        check_id="aws-account-001",
                        title="No security alternate contact registered",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::Account",
                        resource_id="security-contact",
                        description=(
                            "No security alternate contact is configured for this AWS account. "
                            "AWS uses this contact to notify you about security-related issues. "
                            "Without it, critical security notifications may go to the wrong person."
                        ),
                        recommendation="Register a security alternate contact in Account Settings.",
                        remediation=Remediation(
                            cli=(
                                "aws account put-alternate-contact "
                                "--alternate-contact-type SECURITY "
                                '--name "Security Team" '
                                "--title Security "
                                "--email-address security@example.com "
                                '--phone-number "+1-555-0100"'
                            ),
                            terraform=(
                                'resource "aws_account_alternate_contact" "security" {\n'
                                '  alternate_contact_type = "SECURITY"\n'
                                '  name                   = "Security Team"\n'
                                '  title                  = "Security"\n'
                                '  email_address          = "security@example.com"\n'
                                '  phone_number           = "+1-555-0100"\n'
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 1.2"],
                    )
                )
            elif error_code == "AccessDeniedException":
                # Need account:GetAlternateContact permission
                result.error = "Missing permission: account:GetAlternateContact"
            # Other errors - skip
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Account checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_security_contact, provider, check_id="aws-account-001", category=Category.SECURITY),
    ]
