"""Attack chain detection - correlate findings into exploitable attack paths.

Analyzes individual scan findings to detect compound risk patterns where multiple
misconfigurations create an actually exploitable attack surface. Based on published
attack research from MITRE ATT&CK, Datadog pathfinding.cloud, and AWS CIRT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_audit.models import AttackChain, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


# ---------------------------------------------------------------------------
# Resource relationship data (collected with lightweight API calls)
# ---------------------------------------------------------------------------


@dataclass
class ResourceRelationships:
    """Lightweight resource relationships needed for attack chain detection."""

    # EC2 instance_id -> IAM role name (from IamInstanceProfile)
    ec2_roles: dict[str, str] = field(default_factory=dict)
    # EC2 instance_id -> list of security group IDs
    ec2_sgs: dict[str, list[str]] = field(default_factory=dict)
    # Lambda function name -> IAM role ARN
    lambda_roles: dict[str, str] = field(default_factory=dict)
    # IAM role name -> set of attached managed policy ARNs
    role_policies: dict[str, set[str]] = field(default_factory=dict)


# Well-known AWS managed policy ARNs for permission classification
_ADMIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}
_S3_POLICIES = {
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
}
_EC2_POLICIES = {
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
}


def _role_is_admin(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & _ADMIN_POLICIES)


def _role_has_s3(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & (_ADMIN_POLICIES | _S3_POLICIES))


def _role_has_ec2(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & (_ADMIN_POLICIES | _EC2_POLICIES))


def _role_name_from_arn(arn: str) -> str:
    """Extract role name from instance profile ARN or role ARN."""
    # arn:aws:iam::123456789012:instance-profile/role-name
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn


# ---------------------------------------------------------------------------
# Relationship collectors (only called when relevant findings exist)
# ---------------------------------------------------------------------------


def collect_relationships(
    provider: AWSProvider,
    findings: list[Finding],
) -> ResourceRelationships:
    """Collect resource relationships needed for attack chain detection.

    Only makes API calls when relevant findings are present in the scan.
    """
    rels = ResourceRelationships()
    check_ids = {f.check_id for f in findings}

    # EC2 relationships: needed when we have public SG or IMDSv1 findings
    needs_ec2 = bool(check_ids & {"aws-vpc-002", "aws-ec2-004"})
    if needs_ec2:
        _collect_ec2_rels(provider, rels)

    # Lambda relationships: needed when we have public lambda findings
    needs_lambda = bool(check_ids & {"aws-lambda-001"})
    if needs_lambda:
        _collect_lambda_rels(provider, rels)

    # IAM role policies: needed for admin detection on EC2/Lambda/OIDC roles
    role_names: set[str] = set()
    if needs_ec2:
        role_names.update(rels.ec2_roles.values())
    if needs_lambda:
        for arn in rels.lambda_roles.values():
            role_names.add(_role_name_from_arn(arn))
    if "aws-iam-007" in check_ids:
        # OIDC roles - extract role name from finding resource_id (ARN)
        for f in findings:
            if f.check_id == "aws-iam-007":
                role_names.add(_role_name_from_arn(f.resource_id))

    if role_names:
        _collect_role_policies(provider, role_names, rels)

    return rels


def _collect_ec2_rels(provider: AWSProvider, rels: ResourceRelationships) -> None:
    """Collect EC2 instance -> IAM role and -> security group mappings."""
    for region in provider.regions:
        try:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        iid = inst["InstanceId"]
                        rels.ec2_sgs[iid] = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                        profile = inst.get("IamInstanceProfile")
                        if profile:
                            rels.ec2_roles[iid] = _role_name_from_arn(profile.get("Arn", ""))
        except Exception:  # noqa: S112
            continue


def _collect_lambda_rels(provider: AWSProvider, rels: ResourceRelationships) -> None:
    """Collect Lambda function -> IAM role mappings."""
    for region in provider.regions:
        try:
            lam = provider.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    name = fn["FunctionName"]
                    rels.lambda_roles[name] = fn.get("Role", "")
        except Exception:  # noqa: S112
            continue


def _collect_role_policies(
    provider: AWSProvider,
    role_names: set[str],
    rels: ResourceRelationships,
) -> None:
    """Collect attached managed policies for the given IAM roles."""
    iam = provider.session.client("iam")
    for role_name in role_names:
        try:
            paginator = iam.get_paginator("list_attached_role_policies")
            policies: set[str] = set()
            for page in paginator.paginate(RoleName=role_name):
                policies.update(p["PolicyArn"] for p in page.get("AttachedPolicies", []))
            rels.role_policies[role_name] = policies
        except Exception:  # noqa: S112
            continue


# ---------------------------------------------------------------------------
# Helper: index findings by check_id and region
# ---------------------------------------------------------------------------


def _findings_by_check(findings: list[Finding]) -> dict[str, list[Finding]]:
    idx: dict[str, list[Finding]] = {}
    for f in findings:
        idx.setdefault(f.check_id, []).append(f)
    return idx


# ---------------------------------------------------------------------------
# ATTACK CHAIN RULES
# ---------------------------------------------------------------------------

# --- Tier 1: Internet Exposure + Privilege ---


def _detect_exposed_admin_instance(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-01: Public SG + EC2 with admin IAM role."""
    chains: list[AttackChain] = []
    sg_findings = by_check.get("aws-vpc-002", [])
    if not sg_findings or not rels.ec2_sgs:
        return chains

    open_sgs = {f.resource_id for f in sg_findings}

    for instance_id, sgs in rels.ec2_sgs.items():
        exposed_sgs = set(sgs) & open_sgs
        if not exposed_sgs:
            continue
        role_name = rels.ec2_roles.get(instance_id, "")
        if not role_name or not _role_is_admin(rels, role_name):
            continue
        sg_finding = next(f for f in sg_findings if f.resource_id in exposed_sgs)
        chains.append(
            AttackChain(
                chain_id="AC-01",
                name="Internet-Exposed Admin Instance",
                severity=Severity.CRITICAL,
                findings=[sg_finding],
                attack_narrative=(
                    f"Instance {instance_id} is reachable from the internet via "
                    f"open security group and has admin IAM role '{role_name}'. "
                    f"An attacker can reach the instance, access IMDS credentials, "
                    f"and gain full admin access to the AWS account."
                ),
                priority_fix=f"Restrict security group {sg_finding.resource_id} to specific IPs (effort: LOW).",
                mitre_refs=["T1190", "T1552.005", "T1078.004"],
                resources=[instance_id, sg_finding.resource_id],
            )
        )
    return chains


def _detect_ssrf_credential_theft(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-02: Public SG + IMDSv1 on same instance."""
    chains: list[AttackChain] = []
    sg_findings = by_check.get("aws-vpc-002", [])
    imds_findings = by_check.get("aws-ec2-004", [])
    if not sg_findings or not imds_findings:
        return chains

    open_sgs = {f.resource_id for f in sg_findings}
    imds_instances = {f.resource_id for f in imds_findings}

    for instance_id in imds_instances:
        instance_sgs = set(rels.ec2_sgs.get(instance_id, []))
        if not instance_sgs & open_sgs:
            continue
        sg_f = next(f for f in sg_findings if f.resource_id in instance_sgs)
        imds_f = next(f for f in imds_findings if f.resource_id == instance_id)
        chains.append(
            AttackChain(
                chain_id="AC-02",
                name="SSRF to Credential Theft",
                severity=Severity.CRITICAL,
                findings=[sg_f, imds_f],
                attack_narrative=(
                    f"Instance {instance_id} is internet-facing and uses IMDSv1. "
                    f"An attacker can exploit SSRF to query the metadata service "
                    f"at 169.254.169.254 and steal IAM role credentials."
                ),
                priority_fix=f"Enforce IMDSv2 on {instance_id} (effort: LOW).",
                mitre_refs=["T1190", "T1552.005"],
                resources=[instance_id, sg_f.resource_id],
            )
        )
    return chains


def _detect_public_lambda_admin(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-05: Public Lambda function URL + admin IAM role."""
    chains: list[AttackChain] = []
    public_lambdas = by_check.get("aws-lambda-001", [])
    if not public_lambdas:
        return chains

    for f in public_lambdas:
        fn_name = f.resource_id
        role_arn = rels.lambda_roles.get(fn_name, "")
        role_name = _role_name_from_arn(role_arn)
        if role_name and _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-05",
                    name="Public Lambda with Admin Access",
                    severity=Severity.CRITICAL,
                    findings=[f],
                    attack_narrative=(
                        f"Lambda function '{fn_name}' has a public URL (no auth) "
                        f"and executes with admin IAM role '{role_name}'. "
                        f"Anyone on the internet can invoke this function and "
                        f"leverage admin credentials."
                    ),
                    priority_fix="Add IAM or Cognito auth to the function URL (effort: MEDIUM).",
                    mitre_refs=["T1190", "T1078.004"],
                    resources=[fn_name],
                )
            )
    return chains


def _detect_cicd_admin_takeover(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-07: OIDC trust without sub + admin policy on role."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-07",
                    name="CI/CD to Admin Takeover",
                    severity=Severity.CRITICAL,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"restricting the 'sub' claim AND has admin permissions. "
                        f"Any repository on the CI/CD platform can assume this role "
                        f"and gain full AWS admin access. Google's UNC6426 used "
                        f"this exact pattern."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1550.001"],
                    resources=[f.resource_id],
                )
            )
    return chains


# --- Tier 2: Missing Controls ---


def _detect_unmonitored_admin(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-09: No root MFA + no CloudTrail."""
    chains: list[AttackChain] = []
    root_mfa = by_check.get("aws-iam-001", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not root_mfa or not no_ct:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-09",
            name="Unmonitored Admin Access",
            severity=Severity.CRITICAL,
            findings=[root_mfa[0], no_ct[0]],
            attack_narrative=(
                "Root account has no MFA and CloudTrail is disabled. "
                "An attacker with root credentials operates with full admin "
                "access and zero audit trail."
            ),
            priority_fix="Enable CloudTrail first (immediate visibility), then add root MFA.",
            mitre_refs=["T1078.004", "T1562.008"],
            resources=["root", "cloudtrail"],
        )
    )
    return chains


def _detect_blind_admin(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-10: No root MFA + no CloudTrail + no GuardDuty."""
    chains: list[AttackChain] = []
    root_mfa = by_check.get("aws-iam-001", [])
    no_ct = by_check.get("aws-ct-001", [])
    no_gd = by_check.get("aws-gd-001", [])
    if not root_mfa or not no_ct or not no_gd:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-10",
            name="Completely Blind Admin",
            severity=Severity.CRITICAL,
            findings=[root_mfa[0], no_ct[0], no_gd[0]],
            attack_narrative=(
                "Root account has no MFA, CloudTrail is off, and GuardDuty "
                "is disabled. The account has zero detection capability - "
                "any compromise will go completely unnoticed."
            ),
            priority_fix="Enable CloudTrail (effort: LOW) - detection before prevention.",
            mitre_refs=["T1078.004", "T1562.008", "T1562.001"],
            resources=["root", "cloudtrail", "guardduty"],
        )
    )
    return chains


def _detect_zero_visibility(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-11: No CloudTrail + no GuardDuty + no Config (same region)."""
    chains: list[AttackChain] = []
    no_ct = by_check.get("aws-ct-001", [])
    no_gd = by_check.get("aws-gd-001", [])
    no_cfg = by_check.get("aws-cfg-001", [])
    if not no_ct or not no_gd or not no_cfg:
        return chains

    # Match by region
    gd_regions = {f.region for f in no_gd}
    cfg_regions = {f.region for f in no_cfg}

    for ct_f in no_ct:
        r = ct_f.region
        if r in gd_regions and r in cfg_regions:
            gd_f = next(f for f in no_gd if f.region == r)
            cfg_f = next(f for f in no_cfg if f.region == r)
            chains.append(
                AttackChain(
                    chain_id="AC-11",
                    name="Zero Security Visibility",
                    severity=Severity.HIGH,
                    findings=[ct_f, gd_f, cfg_f],
                    attack_narrative=(
                        f"Region {r} has no CloudTrail, no GuardDuty, and no "
                        f"AWS Config. All three detection services are disabled - "
                        f"attackers can operate with zero chance of detection."
                    ),
                    priority_fix=f"Enable CloudTrail in {r} (effort: LOW).",
                    mitre_refs=["T1562.008", "T1562.001"],
                    resources=["cloudtrail", "guardduty", "config"],
                )
            )
            break  # One chain per account is enough
    return chains


def _detect_admin_no_mfa(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-12: Admin policy exists + users without MFA."""
    chains: list[AttackChain] = []
    admin = by_check.get("aws-iam-005", [])
    no_mfa = by_check.get("aws-iam-002", [])
    if not admin or not no_mfa:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-12",
            name="Admin Without MFA",
            severity=Severity.CRITICAL,
            findings=[admin[0], no_mfa[0]],
            attack_narrative=(
                f"Admin-level IAM policy '{admin[0].resource_id}' exists and "
                f"user '{no_mfa[0].resource_id}' has console access without MFA. "
                f"If the unprotected user has admin access, a single password "
                f"compromise gives full account control."
            ),
            priority_fix=f"Enable MFA for '{no_mfa[0].resource_id}' (effort: LOW).",
            mitre_refs=["T1078.004", "T1110"],
            resources=[admin[0].resource_id, no_mfa[0].resource_id],
        )
    )
    return chains


def _detect_open_unmonitored_network(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-13: Open SG (all traffic) + no VPC flow logs in same region."""
    chains: list[AttackChain] = []
    open_sg = [f for f in by_check.get("aws-vpc-002", []) if f.severity == Severity.CRITICAL]
    no_flow = by_check.get("aws-vpc-003", [])
    if not open_sg or not no_flow:
        return chains

    flow_regions = {f.region for f in no_flow}
    for f in open_sg:
        if f.region in flow_regions:
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-13",
                    name="Wide Open and Unmonitored Network",
                    severity=Severity.HIGH,
                    findings=[f, flow_f],
                    attack_narrative=(
                        f"Security group {f.resource_id} allows all inbound "
                        f"traffic from the internet AND VPC flow logs are "
                        f"disabled in {f.region}. Network intrusions will "
                        f"not be logged."
                    ),
                    priority_fix=f"Restrict {f.resource_id} to specific ports (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, flow_f.resource_id],
                )
            )
            break  # One per region is enough
    return chains


def _detect_no_network_layers(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-14: Unrestricted NACL + open SG + no flow logs in same region."""
    chains: list[AttackChain] = []
    nacl = by_check.get("aws-vpc-004", [])
    sg = by_check.get("aws-vpc-002", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not nacl or not sg or not no_flow:
        return chains

    sg_regions = {f.region for f in sg}
    flow_regions = {f.region for f in no_flow}

    for f in nacl:
        if f.region in sg_regions and f.region in flow_regions:
            sg_f = next(s for s in sg if s.region == f.region)
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-14",
                    name="No Network Security Layers",
                    severity=Severity.HIGH,
                    findings=[f, sg_f, flow_f],
                    attack_narrative=(
                        f"Region {f.region} has unrestricted NACLs, open "
                        f"security groups, and no flow logs. All three network "
                        f"defense layers are effectively bypassed."
                    ),
                    priority_fix=f"Restrict security group {sg_f.resource_id} (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, sg_f.resource_id],
                )
            )
            break
    return chains


# --- Tier 3: Data Protection Failures ---


def _detect_exposed_db_no_trail(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-17: Public RDS + no encryption + no CloudTrail."""
    chains: list[AttackChain] = []
    public = by_check.get("aws-rds-001", [])
    unenc = by_check.get("aws-rds-002", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not public or not unenc or not no_ct:
        return chains

    unenc_ids = {f.resource_id for f in unenc}
    for f in public:
        if f.resource_id in unenc_ids:
            enc_f = next(e for e in unenc if e.resource_id == f.resource_id)
            chains.append(
                AttackChain(
                    chain_id="AC-17",
                    name="Exposed Database Without Audit Trail",
                    severity=Severity.CRITICAL,
                    findings=[f, enc_f, no_ct[0]],
                    attack_narrative=(
                        f"RDS '{f.resource_id}' is publicly accessible and "
                        f"unencrypted, with no CloudTrail logging. An attacker "
                        f"can access the database from the internet, exfiltrate "
                        f"plaintext data, and leave no API audit trail."
                    ),
                    priority_fix=f"Disable public access on '{f.resource_id}' (effort: LOW).",
                    mitre_refs=["T1190", "T1530", "T1562.008"],
                    resources=[f.resource_id],
                )
            )
    return chains


# --- Tier 4: Container & Secrets ---


def _detect_container_breakout(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-19: ECS privileged mode + exec enabled."""
    chains: list[AttackChain] = []
    priv = by_check.get("aws-ecs-001", [])
    exec_ = by_check.get("aws-ecs-003", [])
    if not priv or not exec_:
        return chains

    exec_regions = {f.region for f in exec_}
    for f in priv:
        if f.region in exec_regions:
            exec_f = next(e for e in exec_ if e.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-19",
                    name="Container Breakout Path",
                    severity=Severity.CRITICAL,
                    findings=[f, exec_f],
                    attack_narrative=(
                        f"ECS tasks run in privileged mode and ECS Exec is "
                        f"enabled in {f.region}. An attacker with exec access "
                        f"can break out of the container to the host."
                    ),
                    priority_fix="Disable privileged mode on task definitions (effort: MEDIUM).",
                    mitre_refs=["T1611", "T1059"],
                    resources=[f.resource_id, exec_f.resource_id],
                )
            )
            break
    return chains


def _detect_unmonitored_containers(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-20: ECS no logging + exec enabled."""
    chains: list[AttackChain] = []
    no_log = by_check.get("aws-ecs-002", [])
    exec_ = by_check.get("aws-ecs-003", [])
    if not no_log or not exec_:
        return chains

    exec_regions = {f.region for f in exec_}
    for f in no_log:
        if f.region in exec_regions:
            exec_f = next(e for e in exec_ if e.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-20",
                    name="Unmonitored Container Access",
                    severity=Severity.HIGH,
                    findings=[f, exec_f],
                    attack_narrative=(
                        f"ECS Exec is enabled but container logging is "
                        f"disabled in {f.region}. Interactive shell sessions "
                        f"leave no trace."
                    ),
                    priority_fix="Enable CloudWatch logging on task definitions (effort: LOW).",
                    mitre_refs=["T1059", "T1562.008"],
                    resources=[f.resource_id, exec_f.resource_id],
                )
            )
            break
    return chains


def _detect_plaintext_secrets(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-21: SSM insecure params + Lambda env secrets in same region."""
    chains: list[AttackChain] = []
    ssm = by_check.get("aws-ssm-002", [])
    lam = by_check.get("aws-lambda-003", [])
    if not ssm or not lam:
        return chains

    lam_regions = {f.region for f in lam}
    for f in ssm:
        if f.region in lam_regions:
            lam_f = next(lf for lf in lam if lf.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-21",
                    name="Secrets in Plaintext Across Services",
                    severity=Severity.HIGH,
                    findings=[f, lam_f],
                    attack_narrative=(
                        f"SSM parameters store secrets as plaintext String "
                        f"and Lambda functions have secrets in environment "
                        f"variables in {f.region}. Multiple services expose "
                        f"credentials without encryption."
                    ),
                    priority_fix="Migrate SSM parameters to SecureString (effort: LOW).",
                    mitre_refs=["T1552.001"],
                    resources=[f.resource_id, lam_f.resource_id],
                )
            )
            break
    return chains


# --- Tier 5: OIDC Specific ---


def _detect_cicd_data_exfil(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-23: OIDC no sub + role with S3 access."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_has_s3(rels, role_name) and not _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-23",
                    name="CI/CD Data Exfiltration",
                    severity=Severity.HIGH,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"'sub' restriction and has S3 access. Any repository "
                        f"can assume this role and read/write S3 data."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1530"],
                    resources=[f.resource_id],
                )
            )
    return chains


def _detect_cicd_lateral_movement(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-24: OIDC no sub + role with EC2/ECS access."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_has_ec2(rels, role_name) and not _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-24",
                    name="CI/CD Lateral Movement",
                    severity=Severity.HIGH,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"'sub' restriction and has EC2/ECS access. Any "
                        f"repository can assume this role and launch or access "
                        f"compute resources for lateral movement."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1021"],
                    resources=[f.resource_id],
                )
            )
    return chains


# --- Tier 6: CIS-driven chains (new checks) ---


def _detect_root_keys_no_trail(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-25: Root access keys exist + no CloudTrail."""
    chains: list[AttackChain] = []
    root_keys = by_check.get("aws-iam-008", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not root_keys or not no_ct:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-25",
            name="Root Access Keys Without Audit Trail",
            severity=Severity.CRITICAL,
            findings=[root_keys[0], no_ct[0]],
            attack_narrative=(
                "Root account has active access keys and CloudTrail is disabled. "
                "An attacker with root keys has unrestricted access to all AWS "
                "resources with zero audit trail. Root key usage cannot be "
                "restricted by IAM policies."
            ),
            priority_fix="Delete root access keys immediately (effort: LOW).",
            mitre_refs=["T1078.004", "T1562.008"],
            resources=["root", "cloudtrail"],
        )
    )
    return chains


def _detect_admin_no_mfa_no_alarm(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-26: Admin policy + users without MFA + no root usage alarm."""
    chains: list[AttackChain] = []
    admin = by_check.get("aws-iam-005", [])
    no_mfa = by_check.get("aws-iam-002", [])
    no_alarm = by_check.get("aws-cw-001", [])
    if not admin or not no_mfa or not no_alarm:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-26",
            name="Unmonitored Admin Escalation Path",
            severity=Severity.CRITICAL,
            findings=[admin[0], no_mfa[0], no_alarm[0]],
            attack_narrative=(
                f"Admin-level IAM policy exists, user '{no_mfa[0].resource_id}' "
                f"has console access without MFA, and root account usage is not "
                f"monitored. An attacker can compromise the unprotected user, "
                f"escalate to admin, and operate undetected."
            ),
            priority_fix=f"Enable MFA for '{no_mfa[0].resource_id}' (effort: LOW).",
            mitre_refs=["T1078.004", "T1110", "T1562.008"],
            resources=[admin[0].resource_id, no_mfa[0].resource_id],
        )
    )
    return chains


def _detect_default_sg_no_flow_logs(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-27: Default SG has rules + no VPC flow logs in same region."""
    chains: list[AttackChain] = []
    default_sg = by_check.get("aws-vpc-005", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not default_sg or not no_flow:
        return chains

    flow_regions = {f.region for f in no_flow}
    for f in default_sg:
        if f.region in flow_regions:
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-27",
                    name="Default Network Access Without Logging",
                    severity=Severity.HIGH,
                    findings=[f, flow_f],
                    attack_narrative=(
                        f"Default security group in {f.region} allows traffic and "
                        f"VPC flow logs are disabled. Resources launched without "
                        f"explicit SG assignment get network access that is not logged."
                    ),
                    priority_fix=f"Remove rules from default SG {f.resource_id} (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, flow_f.resource_id],
                )
            )
            break
    return chains


def _detect_oidc_no_analyzer(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-28: OIDC trust without sub + no Access Analyzer."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    no_aa = by_check.get("aws-iam-012", [])
    if not oidc or not no_aa:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-28",
            name="External Access Without Analysis",
            severity=Severity.HIGH,
            findings=[oidc[0], no_aa[0]],
            attack_narrative=(
                f"Role '{_role_name_from_arn(oidc[0].resource_id)}' trusts an "
                f"OIDC provider without 'sub' restriction, and IAM Access "
                f"Analyzer is not enabled. External access paths exist but "
                f"the tool that detects them is not running."
            ),
            priority_fix="Enable IAM Access Analyzer and add 'sub' condition (effort: LOW).",
            mitre_refs=["T1078.004", "T1550.001"],
            resources=[oidc[0].resource_id],
        )
    )
    return chains


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

# All rule functions in execution order
_SIMPLE_RULES = [
    _detect_unmonitored_admin,  # AC-09
    _detect_blind_admin,  # AC-10
    _detect_zero_visibility,  # AC-11
    _detect_admin_no_mfa,  # AC-12
    _detect_open_unmonitored_network,  # AC-13
    _detect_no_network_layers,  # AC-14
    _detect_exposed_db_no_trail,  # AC-17
    _detect_container_breakout,  # AC-19
    _detect_unmonitored_containers,  # AC-20
    _detect_plaintext_secrets,  # AC-21
    _detect_root_keys_no_trail,  # AC-25
    _detect_admin_no_mfa_no_alarm,  # AC-26
    _detect_default_sg_no_flow_logs,  # AC-27
    _detect_oidc_no_analyzer,  # AC-28
]

_RELATIONSHIP_RULES = [
    _detect_exposed_admin_instance,  # AC-01
    _detect_ssrf_credential_theft,  # AC-02
    _detect_public_lambda_admin,  # AC-05
    _detect_cicd_admin_takeover,  # AC-07
    _detect_cicd_data_exfil,  # AC-23
    _detect_cicd_lateral_movement,  # AC-24
]


def detect_attack_chains(
    findings: list[Finding],
    relationships: ResourceRelationships | None = None,
) -> list[AttackChain]:
    """Detect attack chains by correlating findings and resource relationships.

    Args:
        findings: All findings from the scan.
        relationships: Resource relationship data (EC2->role, Lambda->role, etc.).
                      If None, only simple correlation rules run.

    Returns:
        List of detected attack chains, sorted by severity.
    """
    if not findings:
        return []

    by_check = _findings_by_check(findings)
    chains: list[AttackChain] = []

    # Run simple rules (no relationship data needed)
    for simple_fn in _SIMPLE_RULES:
        chains.extend(simple_fn(by_check))

    # Run relationship rules (need EC2/Lambda/IAM data)
    if relationships:
        for rel_fn in _RELATIONSHIP_RULES:
            chains.extend(rel_fn(by_check, relationships))

    # Deduplicate: if AC-10 fires, suppress AC-09 (AC-10 is a superset)
    chain_ids = {c.chain_id for c in chains}
    suppress_map = {
        "AC-09": "AC-10",  # Blind Admin supersedes Unmonitored Admin
        "AC-12": "AC-26",  # Unmonitored Admin Escalation supersedes Admin No MFA
    }
    chains = [c for c in chains if c.chain_id not in suppress_map or suppress_map[c.chain_id] not in chain_ids]

    # Sort by severity
    severity_order = list(Severity)
    chains.sort(key=lambda c: severity_order.index(c.severity))

    return chains
