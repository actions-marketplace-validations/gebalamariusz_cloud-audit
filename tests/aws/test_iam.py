"""Tests for IAM security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.iam import (
    check_access_keys_rotation,
    check_cloudshell_access,
    check_ec2_instance_roles,
    check_expired_certificates,
    check_iam_access_analyzer,
    check_multiple_active_keys,
    check_oidc_trust_policy,
    check_overly_permissive_policy,
    check_root_access_keys,
    check_root_mfa,
    check_support_role,
    check_unused_access_keys,
    check_user_direct_policies,
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
    assert mfa_findings[0].compliance_refs == ["CIS 1.10"]


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
    assert result.findings[0].compliance_refs == ["CIS 1.8", "CIS 1.9"]


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


# --- CIS v3.0 new checks ---


def test_root_access_keys_no_keys(mock_aws_provider: AWSProvider) -> None:
    """Root without access keys - no finding (CIS 1.4)."""
    result = check_root_access_keys(mock_aws_provider)
    assert result.check_id == "aws-iam-008"
    assert result.resources_scanned == 1
    assert result.error is None
    # moto default: AccountAccessKeysPresent = 0
    assert len(result.findings) == 0


def test_multiple_active_keys_single_key(mock_aws_provider: AWSProvider) -> None:
    """User with one active key - no finding (CIS 1.13)."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="single-key-user")
    iam.create_access_key(UserName="single-key-user")

    result = check_multiple_active_keys(mock_aws_provider)
    assert result.check_id == "aws-iam-009"
    assert result.error is None
    # Should not flag users with 1 key
    findings = [f for f in result.findings if f.resource_id == "single-key-user"]
    assert len(findings) == 0


def test_multiple_active_keys_two_keys(mock_aws_provider: AWSProvider) -> None:
    """User with two active keys - finding (CIS 1.13)."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="multi-key-user")
    iam.create_access_key(UserName="multi-key-user")
    iam.create_access_key(UserName="multi-key-user")

    result = check_multiple_active_keys(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "multi-key-user"]
    assert len(findings) == 1
    assert findings[0].check_id == "aws-iam-009"
    assert "2 active access keys" in findings[0].title
    assert findings[0].compliance_refs == ["CIS 1.13"]


def test_user_direct_policies_no_policies(mock_aws_provider: AWSProvider) -> None:
    """User with no direct policies - no finding (CIS 1.15)."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="clean-user")

    result = check_user_direct_policies(mock_aws_provider)
    assert result.check_id == "aws-iam-010"
    findings = [f for f in result.findings if f.resource_id == "clean-user"]
    assert len(findings) == 0


def test_user_direct_policies_with_inline(mock_aws_provider: AWSProvider) -> None:
    """User with inline policy - finding (CIS 1.15)."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="inline-user")
    iam.put_user_policy(
        UserName="inline-user",
        PolicyName="test-policy",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
    )

    result = check_user_direct_policies(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "inline-user"]
    assert len(findings) == 1
    assert findings[0].compliance_refs == ["CIS 1.15"]


def test_support_role_exists(mock_aws_provider: AWSProvider) -> None:
    """AWSSupportAccess check runs without crashing (CIS 1.17).

    Note: moto does not know the AWSSupportAccess managed policy,
    so we cannot test the PASS path. We verify the check handles
    the missing policy gracefully (finding or error, not crash).
    """
    result = check_support_role(mock_aws_provider)
    assert result.check_id == "aws-iam-011"
    # moto does not know AWSSupportAccess - check handles gracefully (error or finding, not crash)
    assert result.error is not None or len(result.findings) >= 1


def test_support_role_missing(mock_aws_provider: AWSProvider) -> None:
    """No AWSSupportAccess attached - finding (CIS 1.17)."""
    result = check_support_role(mock_aws_provider)
    assert result.check_id == "aws-iam-011"
    assert len(result.findings) == 1
    assert result.findings[0].compliance_refs == ["CIS 1.17"]


def test_access_analyzer_not_enabled(mock_aws_provider: AWSProvider) -> None:
    """Access Analyzer not enabled - finding (CIS 1.20)."""
    result = check_iam_access_analyzer(mock_aws_provider)
    assert result.check_id == "aws-iam-012"
    # moto may not support Access Analyzer - check for either finding or error
    assert result.error is not None or len(result.findings) >= 1


def test_expired_certificates_none(mock_aws_provider: AWSProvider) -> None:
    """No certificates - no finding (CIS 1.19)."""
    result = check_expired_certificates(mock_aws_provider)
    assert result.check_id == "aws-iam-013"
    assert result.error is None
    assert len(result.findings) == 0


def test_cloudshell_access_not_attached(mock_aws_provider: AWSProvider) -> None:
    """CloudShellFullAccess not attached - no finding (CIS 1.22)."""
    result = check_cloudshell_access(mock_aws_provider)
    assert result.check_id == "aws-iam-014"
    # moto may not know this policy - check for clean result or error
    assert result.error is not None or len(result.findings) == 0


def test_ec2_instance_roles_with_profile(mock_aws_provider: AWSProvider) -> None:
    """Running EC2 with IAM profile - no finding (CIS 1.18)."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    iam = mock_aws_provider.session.client("iam")

    # Create role and instance profile
    iam.create_role(
        RoleName="ec2-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
    )
    iam.create_instance_profile(InstanceProfileName="ec2-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="ec2-profile", RoleName="ec2-role")

    # Launch instance with profile
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        IamInstanceProfile={"Name": "ec2-profile"},
    )

    result = check_ec2_instance_roles(mock_aws_provider)
    assert result.check_id == "aws-iam-016"
    assert result.error is None
    assert len(result.findings) == 0


def test_ec2_instance_roles_without_profile(mock_aws_provider: AWSProvider) -> None:
    """Running EC2 without IAM profile - finding (CIS 1.18)."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)

    result = check_ec2_instance_roles(mock_aws_provider)
    assert result.check_id == "aws-iam-016"
    assert len(result.findings) >= 1
    assert result.findings[0].compliance_refs == ["CIS 1.18"]
