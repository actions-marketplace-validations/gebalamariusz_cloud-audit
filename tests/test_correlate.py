"""Tests for attack chain detection engine."""

from __future__ import annotations

from cloud_audit.correlate import (
    ResourceRelationships,
    detect_attack_chains,
)
from cloud_audit.models import Category, Finding, Severity


def _make_finding(
    check_id: str,
    resource_id: str = "test-resource",
    region: str = "eu-central-1",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test finding {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=resource_id,
        region=region,
        description="Test",
        recommendation="Test",
    )


# ---------------------------------------------------------------------------
# Simple rules (no relationships needed)
# ---------------------------------------------------------------------------


def test_no_findings_no_chains():
    assert detect_attack_chains([]) == []


def test_unmonitored_admin():
    """AC-09: iam-001 + ct-001 - CRITICAL."""
    findings = [
        _make_finding("aws-iam-001", resource_id="root"),
        _make_finding("aws-ct-001", resource_id="cloudtrail"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-09"
    assert chains[0].severity == Severity.CRITICAL


def test_blind_admin_supersedes():
    """AC-10 supersedes AC-09: iam-001 + ct-001 + gd-001 - only AC-10."""
    findings = [
        _make_finding("aws-iam-001", resource_id="root"),
        _make_finding("aws-ct-001", resource_id="cloudtrail"),
        _make_finding("aws-gd-001", resource_id="guardduty"),
    ]
    chains = detect_attack_chains(findings)
    chain_ids = {c.chain_id for c in chains}
    assert "AC-10" in chain_ids
    assert "AC-09" not in chain_ids


def test_zero_visibility():
    """AC-11: ct-001 + gd-001 + cfg-001 same region - HIGH."""
    findings = [
        _make_finding("aws-ct-001", resource_id="ct", region="eu-central-1"),
        _make_finding("aws-gd-001", resource_id="gd", region="eu-central-1"),
        _make_finding("aws-cfg-001", resource_id="cfg", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-11"
    assert chains[0].severity == Severity.HIGH


def test_admin_no_mfa():
    """AC-12: iam-005 + iam-002 - CRITICAL."""
    findings = [
        _make_finding("aws-iam-005", resource_id="AdminPolicy"),
        _make_finding("aws-iam-002", resource_id="user-no-mfa"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-12"
    assert chains[0].severity == Severity.CRITICAL


def test_open_unmonitored_network():
    """AC-13: vpc-002 CRITICAL + vpc-003 same region - HIGH."""
    findings = [
        _make_finding("aws-vpc-002", resource_id="sg-open", region="eu-central-1", severity=Severity.CRITICAL),
        _make_finding("aws-vpc-003", resource_id="vpc-123", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-13"
    assert chains[0].severity == Severity.HIGH


def test_exposed_db_no_trail():
    """AC-17: rds-001 + rds-002 + ct-001 - CRITICAL (multi-service)."""
    findings = [
        _make_finding("aws-rds-001", resource_id="my-db"),
        _make_finding("aws-rds-002", resource_id="my-db"),
        _make_finding("aws-ct-001", resource_id="cloudtrail"),
    ]
    chains = detect_attack_chains(findings)
    ac17 = [c for c in chains if c.chain_id == "AC-17"]
    assert len(ac17) == 1
    assert ac17[0].severity == Severity.CRITICAL
    assert len(ac17[0].findings) == 3


def test_container_breakout():
    """AC-19: ecs-001 + ecs-003 same region - CRITICAL."""
    findings = [
        _make_finding("aws-ecs-001", resource_id="task-def-1", region="eu-central-1"),
        _make_finding("aws-ecs-003", resource_id="svc-1", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-19"
    assert chains[0].severity == Severity.CRITICAL


def test_unmonitored_containers():
    """AC-20: ecs-002 + ecs-003 same region - HIGH."""
    findings = [
        _make_finding("aws-ecs-002", resource_id="task-no-log", region="eu-central-1"),
        _make_finding("aws-ecs-003", resource_id="svc-exec", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-20"
    assert chains[0].severity == Severity.HIGH


def test_plaintext_secrets():
    """AC-21: ssm-002 + lambda-003 same region - HIGH."""
    findings = [
        _make_finding("aws-ssm-002", resource_id="param/secret", region="eu-central-1"),
        _make_finding("aws-lambda-003", resource_id="my-func", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "AC-21"
    assert chains[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Relationship rules
# ---------------------------------------------------------------------------


def test_exposed_admin_instance():
    """AC-01: vpc-002 finding + EC2 with admin role via relationships."""
    findings = [
        _make_finding("aws-vpc-002", resource_id="sg-open", severity=Severity.CRITICAL),
    ]
    rels = ResourceRelationships()
    rels.ec2_sgs = {"i-abc123": ["sg-open"]}
    rels.ec2_roles = {"i-abc123": "admin-role"}
    rels.role_policies = {"admin-role": {"arn:aws:iam::aws:policy/AdministratorAccess"}}

    chains = detect_attack_chains(findings, relationships=rels)
    ac01 = [c for c in chains if c.chain_id == "AC-01"]
    assert len(ac01) == 1
    assert ac01[0].severity == Severity.CRITICAL
    assert "i-abc123" in ac01[0].resources


def test_ssrf_credential_theft():
    """AC-02: vpc-002 + ec2-004 + EC2 SG mapping."""
    findings = [
        _make_finding("aws-vpc-002", resource_id="sg-open", severity=Severity.CRITICAL),
        _make_finding("aws-ec2-004", resource_id="i-abc123"),
    ]
    rels = ResourceRelationships()
    rels.ec2_sgs = {"i-abc123": ["sg-open"]}

    chains = detect_attack_chains(findings, relationships=rels)
    ac02 = [c for c in chains if c.chain_id == "AC-02"]
    assert len(ac02) == 1
    assert ac02[0].severity == Severity.CRITICAL
    assert len(ac02[0].findings) == 2


def test_cicd_admin_takeover():
    """AC-07: iam-007 + admin policy via relationships."""
    findings = [
        _make_finding("aws-iam-007", resource_id="arn:aws:iam::123456789012:role/deploy-role"),
    ]
    rels = ResourceRelationships()
    rels.role_policies = {"deploy-role": {"arn:aws:iam::aws:policy/AdministratorAccess"}}

    chains = detect_attack_chains(findings, relationships=rels)
    ac07 = [c for c in chains if c.chain_id == "AC-07"]
    assert len(ac07) == 1
    assert ac07[0].severity == Severity.CRITICAL


def test_cicd_data_exfil():
    """AC-23: iam-007 + S3 access (not admin)."""
    findings = [
        _make_finding("aws-iam-007", resource_id="arn:aws:iam::123456789012:role/s3-role"),
    ]
    rels = ResourceRelationships()
    rels.role_policies = {"s3-role": {"arn:aws:iam::aws:policy/AmazonS3FullAccess"}}

    chains = detect_attack_chains(findings, relationships=rels)
    ac23 = [c for c in chains if c.chain_id == "AC-23"]
    assert len(ac23) == 1
    assert ac23[0].severity == Severity.HIGH


def test_public_lambda_admin():
    """AC-05: Public Lambda URL + admin IAM role via relationships."""
    findings = [
        _make_finding("aws-lambda-001", resource_id="admin-func"),
    ]
    rels = ResourceRelationships()
    rels.lambda_roles = {"admin-func": "arn:aws:iam::123456789012:role/lambda-admin"}
    rels.role_policies = {"lambda-admin": {"arn:aws:iam::aws:policy/AdministratorAccess"}}

    chains = detect_attack_chains(findings, relationships=rels)
    ac05 = [c for c in chains if c.chain_id == "AC-05"]
    assert len(ac05) == 1
    assert ac05[0].severity == Severity.CRITICAL


def test_no_network_layers():
    """AC-14: NACL + open SG + no flow logs in same region."""
    findings = [
        _make_finding("aws-vpc-004", resource_id="acl-123", region="eu-central-1"),
        _make_finding("aws-vpc-002", resource_id="sg-open", region="eu-central-1", severity=Severity.CRITICAL),
        _make_finding("aws-vpc-003", resource_id="vpc-123", region="eu-central-1"),
    ]
    chains = detect_attack_chains(findings)
    ac14 = [c for c in chains if c.chain_id == "AC-14"]
    assert len(ac14) == 1
    assert ac14[0].severity == Severity.HIGH


def test_cicd_lateral_movement():
    """AC-24: OIDC no sub + role with EC2 access (not admin)."""
    findings = [
        _make_finding("aws-iam-007", resource_id="arn:aws:iam::123456789012:role/ec2-role"),
    ]
    rels = ResourceRelationships()
    rels.role_policies = {"ec2-role": {"arn:aws:iam::aws:policy/AmazonEC2FullAccess"}}

    chains = detect_attack_chains(findings, relationships=rels)
    ac24 = [c for c in chains if c.chain_id == "AC-24"]
    assert len(ac24) == 1
    assert ac24[0].severity == Severity.HIGH


def test_no_chain_without_relationships():
    """Relationship rules don't fire when relationships=None."""
    findings = [
        _make_finding("aws-vpc-002", resource_id="sg-open", severity=Severity.CRITICAL),
        _make_finding("aws-ec2-004", resource_id="i-abc123"),
        _make_finding("aws-iam-007", resource_id="arn:aws:iam::123456789012:role/deploy-role"),
    ]
    chains = detect_attack_chains(findings, relationships=None)
    rel_chain_ids = {"AC-01", "AC-02", "AC-05", "AC-07", "AC-23", "AC-24"}
    for c in chains:
        assert c.chain_id not in rel_chain_ids


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_chains_sorted_by_severity():
    """CRITICAL chains before HIGH."""
    findings = [
        # AC-13 - HIGH (open SG + no flow logs)
        _make_finding("aws-vpc-002", resource_id="sg-open", region="eu-central-1", severity=Severity.CRITICAL),
        _make_finding("aws-vpc-003", resource_id="vpc-123", region="eu-central-1"),
        # AC-09 - CRITICAL (root no MFA + no CloudTrail)
        _make_finding("aws-iam-001", resource_id="root"),
        _make_finding("aws-ct-001", resource_id="cloudtrail"),
    ]
    chains = detect_attack_chains(findings)
    severities = [c.severity for c in chains]
    # CRITICAL should come before HIGH
    assert severities.index(Severity.CRITICAL) < severities.index(Severity.HIGH)


def test_single_finding_no_chain():
    """Only one check_id present - no chain possible."""
    findings = [_make_finding("aws-rds-001", resource_id="db-1")]
    chains = detect_attack_chains(findings)
    assert len(chains) == 0


def test_different_regions_no_chain():
    """Findings in different regions don't form a chain (AC-13)."""
    findings = [
        _make_finding("aws-vpc-002", resource_id="sg-open", region="eu-central-1", severity=Severity.CRITICAL),
        _make_finding("aws-vpc-003", resource_id="vpc-123", region="us-east-1"),
    ]
    chains = detect_attack_chains(findings)
    ac13 = [c for c in chains if c.chain_id == "AC-13"]
    assert len(ac13) == 0
