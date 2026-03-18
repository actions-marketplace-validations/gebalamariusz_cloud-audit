"""Tests for IAM security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.iam import (
    check_access_keys_rotation,
    check_oidc_trust_policy,
    check_overly_permissive_policy,
    check_root_mfa,
    check_unused_access_keys,
    check_users_mfa,
    check_weak_password_policy,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_root_mfa_runs_without_error(mock_aws_provider: AWSProvider) -> None:
    """Root MFA check runs without errors.

    Note: moto's default account has MFA disabled, so this doesn't test the "pass" path.
    It verifies the check executes correctly and returns a valid result.
    """
    result = check_root_mfa(mock_aws_provider)
    assert result.check_id == "aws-iam-001"
    assert result.resources_scanned == 1
    assert result.error is None


def test_root_mfa_fail(mock_aws_provider: AWSProvider) -> None:
    """Root MFA disabled - should produce CRITICAL finding."""
    result = check_root_mfa(mock_aws_provider)
    # moto's default: root MFA is disabled
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity.value == "critical"
    assert finding.remediation is not None
    assert finding.compliance_refs == ["CIS 1.5"]
    assert "console.aws.amazon.com" in finding.remediation.cli


def test_users_mfa_pass(mock_aws_provider: AWSProvider) -> None:
    """User without console access - no MFA required."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="api-user")
    # No login profile = no console access = no MFA needed
    result = check_users_mfa(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) == 0


def test_users_mfa_fail(mock_aws_provider: AWSProvider) -> None:
    """User with console access but no MFA - HIGH finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Test1234!@#$")  # noqa: S106
    result = check_users_mfa(mock_aws_provider)
    mfa_findings = [f for f in result.findings if f.check_id == "aws-iam-002"]
    assert len(mfa_findings) >= 1
    assert mfa_findings[0].severity.value == "high"
    assert mfa_findings[0].remediation is not None
    assert "console-user" in mfa_findings[0].remediation.cli
    assert mfa_findings[0].compliance_refs == ["CIS 1.4"]


def test_access_keys_rotation_pass(mock_aws_provider: AWSProvider) -> None:
    """Fresh access key - no finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="fresh-key-user")
    iam.create_access_key(UserName="fresh-key-user")
    result = check_access_keys_rotation(mock_aws_provider)
    rotation_findings = [f for f in result.findings if f.check_id == "aws-iam-003"]
    assert len(rotation_findings) == 0


def test_unused_access_keys_fail(mock_aws_provider: AWSProvider) -> None:
    """Access key never used - MEDIUM finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="unused-key-user")
    iam.create_access_key(UserName="unused-key-user")
    result = check_unused_access_keys(mock_aws_provider)
    unused_findings = [f for f in result.findings if f.check_id == "aws-iam-004"]
    assert len(unused_findings) >= 1
    assert unused_findings[0].remediation is not None
    assert unused_findings[0].compliance_refs == ["CIS 1.12"]


def test_overly_permissive_policy_pass(mock_aws_provider: AWSProvider) -> None:
    """Policy with specific actions - no finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}],
        }
    )
    iam.create_policy(PolicyName="specific-policy", PolicyDocument=policy_doc)
    result = check_overly_permissive_policy(mock_aws_provider)
    findings = [f for f in result.findings if "specific-policy" in f.title]
    assert len(findings) == 0


def test_overly_permissive_policy_fail(mock_aws_provider: AWSProvider) -> None:
    """Policy with Action: * and Resource: * - CRITICAL finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
    )
    iam.create_policy(PolicyName="admin-policy", PolicyDocument=policy_doc)
    result = check_overly_permissive_policy(mock_aws_provider)
    findings = [f for f in result.findings if "admin-policy" in f.title]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].remediation is not None


def test_weak_password_policy_no_policy(mock_aws_provider: AWSProvider) -> None:
    """No password policy set - MEDIUM finding."""
    result = check_weak_password_policy(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert result.findings[0].compliance_refs == ["CIS 1.8"]


def test_weak_password_policy_strong(mock_aws_provider: AWSProvider) -> None:
    """Strong password policy - no finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=24,
    )
    result = check_weak_password_policy(mock_aws_provider)
    assert len(result.findings) == 0


# --- OIDC trust policy checks (aws-iam-007) ---


def test_oidc_trust_policy_pass_with_sub(mock_aws_provider: AWSProvider) -> None:
    """Role with OIDC federation AND sub condition - no finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main",
                        }
                    },
                }
            ],
        }
    )
    iam.create_role(RoleName="github-actions-safe", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 0
    assert result.resources_scanned >= 1


def test_oidc_trust_policy_fail_no_sub(mock_aws_provider: AWSProvider) -> None:
    """Role with OIDC federation, aud but no sub - CRITICAL finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        }
                    },
                }
            ],
        }
    )
    iam.create_role(RoleName="github-actions-vulnerable", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].remediation is not None
    assert "sub" in findings[0].remediation.cli
    assert "GitHub Actions" in findings[0].title


def test_oidc_trust_policy_pass_non_oidc_role(mock_aws_provider: AWSProvider) -> None:
    """Regular service role (not OIDC) - no finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName="ec2-service-role", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 0


def test_oidc_trust_policy_fail_no_condition(mock_aws_provider: AWSProvider) -> None:
    """Role with OIDC federation but no Condition at all - CRITICAL finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ],
        }
    )
    iam.create_role(RoleName="github-actions-no-condition", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_oidc_trust_policy_pass_sub_in_string_like(mock_aws_provider: AWSProvider) -> None:
    """Role with sub in StringLike (wildcard pattern) - no finding."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        },
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub": "repo:myorg/*",
                        },
                    },
                }
            ],
        }
    )
    iam.create_role(RoleName="github-actions-wildcard-safe", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 0


def test_oidc_trust_policy_gitlab(mock_aws_provider: AWSProvider) -> None:
    """Role with GitLab OIDC without sub condition - CRITICAL."""
    import json

    iam = mock_aws_provider.session.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "gitlab.com:aud": "https://gitlab.com",
                        }
                    },
                }
            ],
        }
    )
    iam.create_role(RoleName="gitlab-ci-vulnerable", AssumeRolePolicyDocument=trust_policy)

    result = check_oidc_trust_policy(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-iam-007"]
    assert len(findings) == 1
    assert "GitLab" in findings[0].title
    assert findings[0].remediation is not None
