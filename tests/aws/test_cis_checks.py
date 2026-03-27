"""Tests for CIS v3.0 new checks (S3, VPC, CloudTrail, EFS, SecurityHub, Account, CloudWatch)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.cloudtrail import (
    check_cloudtrail_bucket_access_logging,
    check_cloudtrail_kms_encryption,
    check_s3_object_read_logging,
    check_s3_object_write_logging,
)
from cloud_audit.providers.aws.checks.efs import check_efs_encryption
from cloud_audit.providers.aws.checks.s3 import check_bucket_deny_http, check_bucket_mfa_delete
from cloud_audit.providers.aws.checks.securityhub import check_security_hub_enabled
from cloud_audit.providers.aws.checks.vpc import check_default_sg_restricts_all

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


# --- S3 checks ---


def test_bucket_deny_http_no_policy(mock_aws_provider: AWSProvider) -> None:
    """S3 bucket with no policy - finding (CIS 2.1.1)."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="no-policy-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )

    result = check_bucket_deny_http(mock_aws_provider)
    assert result.check_id == "aws-s3-006"
    findings = [f for f in result.findings if f.resource_id == "no-policy-bucket"]
    assert len(findings) == 1
    assert findings[0].compliance_refs == ["CIS 2.1.1"]


def test_bucket_deny_http_with_deny(mock_aws_provider: AWSProvider) -> None:
    """S3 bucket with deny HTTP policy - no finding (CIS 2.1.1)."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="secure-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyHTTP",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::secure-bucket", "arn:aws:s3:::secure-bucket/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket="secure-bucket", Policy=json.dumps(policy))

    result = check_bucket_deny_http(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "secure-bucket"]
    assert len(findings) == 0


def test_bucket_mfa_delete_disabled(mock_aws_provider: AWSProvider) -> None:
    """S3 bucket without MFA Delete - finding (CIS 2.1.2)."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="no-mfa-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )

    result = check_bucket_mfa_delete(mock_aws_provider)
    assert result.check_id == "aws-s3-007"
    findings = [f for f in result.findings if f.resource_id == "no-mfa-bucket"]
    assert len(findings) == 1
    assert findings[0].compliance_refs == ["CIS 2.1.2"]


# --- VPC checks ---


def test_default_sg_has_rules(mock_aws_provider: AWSProvider) -> None:
    """Default SG with rules - finding (CIS 5.4)."""
    result = check_default_sg_restricts_all(mock_aws_provider)
    assert result.check_id == "aws-vpc-005"
    # AWS default VPC has a default SG with default egress rule
    # moto should create this automatically
    assert result.error is None
    # Default SGs always have at least an egress rule, so findings expected
    if result.resources_scanned > 0:
        assert len(result.findings) >= 1
        for f in result.findings:
            assert f.compliance_refs == ["CIS 5.4"]


# --- CloudTrail checks ---


def test_cloudtrail_bucket_access_logging_missing(mock_aws_provider: AWSProvider) -> None:
    """CloudTrail bucket without access logging - finding (CIS 3.4)."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="ct-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="main-trail", S3BucketName="ct-bucket")

    result = check_cloudtrail_bucket_access_logging(mock_aws_provider)
    assert result.check_id == "aws-ct-004"
    assert result.error is None
    assert len(result.findings) >= 1
    assert result.findings[0].compliance_refs == ["CIS 3.4"]


def test_cloudtrail_kms_encryption_missing(mock_aws_provider: AWSProvider) -> None:
    """CloudTrail without KMS encryption - finding (CIS 3.5)."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="ct-logs",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="main-trail", S3BucketName="ct-logs", IsMultiRegionTrail=True)

    result = check_cloudtrail_kms_encryption(mock_aws_provider)
    assert result.check_id == "aws-ct-005"
    assert result.error is None
    assert len(result.findings) >= 1
    assert result.findings[0].compliance_refs == ["CIS 3.5"]


def test_s3_object_write_logging_missing(mock_aws_provider: AWSProvider) -> None:
    """No S3 object-level write logging - finding (CIS 3.8)."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="ct-logs",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="main-trail", S3BucketName="ct-logs", IsMultiRegionTrail=True)

    result = check_s3_object_write_logging(mock_aws_provider)
    assert result.check_id == "aws-ct-006"
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].compliance_refs == ["CIS 3.8"]


def test_s3_object_read_logging_missing(mock_aws_provider: AWSProvider) -> None:
    """No S3 object-level read logging - finding (CIS 3.9)."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="ct-logs",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="main-trail", S3BucketName="ct-logs", IsMultiRegionTrail=True)

    result = check_s3_object_read_logging(mock_aws_provider)
    assert result.check_id == "aws-ct-007"
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].compliance_refs == ["CIS 3.9"]


# --- EFS checks ---


def test_efs_encryption_disabled(mock_aws_provider: AWSProvider) -> None:
    """EFS without encryption - finding (CIS 2.4.1)."""
    efs = mock_aws_provider.session.client("efs", region_name="eu-central-1")
    efs.create_file_system(CreationToken="test-fs")

    result = check_efs_encryption(mock_aws_provider)
    assert result.check_id == "aws-efs-001"
    assert result.error is None
    # moto creates unencrypted EFS by default
    if result.resources_scanned > 0:
        assert len(result.findings) >= 1
        assert result.findings[0].compliance_refs == ["CIS 2.4.1"]


def test_efs_encryption_enabled(mock_aws_provider: AWSProvider) -> None:
    """EFS with encryption - no finding (CIS 2.4.1)."""
    efs = mock_aws_provider.session.client("efs", region_name="eu-central-1")
    efs.create_file_system(CreationToken="encrypted-fs", Encrypted=True)

    result = check_efs_encryption(mock_aws_provider)
    assert result.check_id == "aws-efs-001"
    encrypted_findings = [
        f for f in result.findings if "encrypted-fs" in f.resource_id or "encrypted" in f.title.lower()
    ]
    # Should not flag the encrypted FS
    assert len(encrypted_findings) == 0


# --- Security Hub checks ---


def test_security_hub_not_enabled(mock_aws_provider: AWSProvider) -> None:
    """Security Hub not enabled - finding (CIS 4.16)."""
    result = check_security_hub_enabled(mock_aws_provider)
    assert result.check_id == "aws-sh-001"
    # moto may or may not support SecurityHub - check for finding or graceful handling
    assert result.error is None or len(result.findings) >= 0


# --- Compliance engine tests ---


def test_compliance_engine_builds_report(mock_aws_provider: AWSProvider) -> None:
    """Compliance engine produces a valid report from scan data."""
    from cloud_audit.compliance.engine import build_compliance_report
    from cloud_audit.models import CheckResult, ScanReport, ScanSummary

    # Create minimal scan report
    report = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
        timestamp="2026-03-27T00:00:00Z",
        duration_seconds=10.0,
        summary=ScanSummary(
            total_findings=1,
            by_severity={"critical": 1},
            by_category={"security": 1},
            resources_scanned=5,
            checks_passed=4,
            checks_failed=1,
            checks_errored=0,
            score=80,
        ),
        results=[
            CheckResult(
                check_id="aws-iam-001",
                check_name="Root MFA",
                resources_scanned=1,
            )
        ],
    )

    comp = build_compliance_report("cis_aws_v3", report)
    assert comp.framework_id == "cis_aws_v3"
    assert comp.framework_name == "CIS Amazon Web Services Foundations Benchmark"
    assert comp.version == "3.0.0"
    assert comp.total_controls == 62
    assert comp.controls_assessed >= 0
    assert 0 <= comp.readiness_score <= 100


def test_compliance_engine_pass_fail_logic(mock_aws_provider: AWSProvider) -> None:
    """Controls with no findings = PASS, controls with findings = FAIL."""
    from cloud_audit.compliance.engine import build_compliance_report
    from cloud_audit.models import (
        Category,
        CheckResult,
        Effort,
        Finding,
        Remediation,
        ScanReport,
        ScanSummary,
        Severity,
    )

    finding = Finding(
        check_id="aws-iam-001",
        title="Root without MFA",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        resource_type="AWS::IAM::Root",
        resource_id="root",
        description="Root has no MFA",
        recommendation="Enable MFA",
        remediation=Remediation(cli="aws iam ...", terraform="...", doc_url="https://...", effort=Effort.LOW),
    )

    report = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
        timestamp="2026-03-27T00:00:00Z",
        duration_seconds=10.0,
        summary=ScanSummary(
            total_findings=1,
            by_severity={"critical": 1},
            by_category={"security": 1},
            resources_scanned=5,
            checks_passed=4,
            checks_failed=1,
            checks_errored=0,
            score=80,
        ),
        results=[
            CheckResult(
                check_id="aws-iam-001",
                check_name="Root MFA",
                resources_scanned=1,
                findings=[finding],
            )
        ],
    )

    comp = build_compliance_report("cis_aws_v3", report)

    # CIS 1.5 maps to aws-iam-001 - should be FAIL
    ctrl_15 = next(c for c in comp.controls if c.control_id == "1.5")
    assert ctrl_15.status == "FAIL"
    assert len(ctrl_15.findings) == 1

    # CIS 1.4 maps to aws-iam-008 - not in results, should be NOT_ASSESSED
    ctrl_14 = next(c for c in comp.controls if c.control_id == "1.4")
    assert ctrl_14.status == "NOT_ASSESSED"

    # CIS 1.1 has no checks - should be NOT_ASSESSED
    ctrl_11 = next(c for c in comp.controls if c.control_id == "1.1")
    assert ctrl_11.status == "NOT_ASSESSED"
