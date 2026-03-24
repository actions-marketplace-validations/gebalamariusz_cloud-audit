"""Tests for the breach cost estimation module."""

from __future__ import annotations

from cloud_audit.cost_model import (
    CostEstimate,
    _format_usd,
    estimate_chain_cost,
    estimate_finding_cost,
    estimate_total_exposure,
)
from cloud_audit.models import (
    AttackChain,
    Category,
    CheckResult,
    Finding,
    ScanReport,
    Severity,
)


def _make_finding(check_id: str, resource_id: str = "test-resource", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test finding {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=resource_id,
        description="Test description",
        recommendation="Fix it",
    )


# ---------------------------------------------------------------------------
# _format_usd
# ---------------------------------------------------------------------------


class TestFormatUsd:
    def test_millions(self) -> None:
        assert _format_usd(4_880_000) == "$4.9M"

    def test_millions_exact(self) -> None:
        assert _format_usd(1_000_000) == "$1.0M"

    def test_thousands(self) -> None:
        assert _format_usd(50_000) == "$50K"

    def test_thousands_small(self) -> None:
        assert _format_usd(5_000) == "$5K"

    def test_hundreds(self) -> None:
        assert _format_usd(500) == "$500"

    def test_zero(self) -> None:
        assert _format_usd(0) == "$0"


# ---------------------------------------------------------------------------
# CostEstimate
# ---------------------------------------------------------------------------


class TestCostEstimate:
    def test_display(self) -> None:
        est = CostEstimate(low=50_000, high=500_000, rationale="test")
        assert est.display == "$50K - $500K"

    def test_display_millions(self) -> None:
        est = CostEstimate(low=100_000, high=5_000_000, rationale="test")
        assert est.display == "$100K - $5.0M"

    def test_to_dict(self) -> None:
        est = CostEstimate(low=10_000, high=100_000, rationale="test rationale")
        d = est.to_dict()
        assert d["low_usd"] == 10_000
        assert d["high_usd"] == 100_000
        assert d["display"] == "$10K - $100K"
        assert d["rationale"] == "test rationale"


# ---------------------------------------------------------------------------
# estimate_finding_cost
# ---------------------------------------------------------------------------


class TestEstimateFindingCost:
    def test_known_check(self) -> None:
        f = _make_finding("aws-iam-001")
        est = estimate_finding_cost(f)
        assert est is not None
        assert est.low > 0
        assert est.high > est.low
        assert "Root" in est.rationale

    def test_s3_public_bucket(self) -> None:
        f = _make_finding("aws-s3-001")
        est = estimate_finding_cost(f)
        assert est is not None
        assert est.high >= 1_000_000  # S3 public = high impact

    def test_unknown_check(self) -> None:
        f = _make_finding("aws-unknown-999")
        est = estimate_finding_cost(f)
        assert est is None

    def test_low_severity_low_cost(self) -> None:
        f = _make_finding("aws-eip-001", severity=Severity.LOW)
        est = estimate_finding_cost(f)
        assert est is not None
        assert est.high <= 1_000  # EIP = very low risk

    def test_known_check_has_source_url(self) -> None:
        f = _make_finding("aws-ct-001")
        est = estimate_finding_cost(f)
        assert est is not None
        assert est.source_url.startswith("https://")
        assert "ibm.com" in est.source_url

    def test_all_checks_have_costs(self) -> None:
        """Verify that all cost entries have valid structure and source URLs."""
        from cloud_audit.cost_model import _COST_TABLE

        for check_id, (low, high, rationale, source_url) in _COST_TABLE.items():
            assert low >= 0, f"{check_id}: low must be >= 0"
            assert high > low, f"{check_id}: high must be > low"
            assert len(rationale) > 0, f"{check_id}: rationale must not be empty"
            assert check_id.startswith("aws-"), f"{check_id}: must start with 'aws-'"
            assert source_url.startswith("https://"), f"{check_id}: source_url must be https"


# ---------------------------------------------------------------------------
# estimate_chain_cost
# ---------------------------------------------------------------------------


class TestEstimateChainCost:
    def test_basic_chain(self) -> None:
        chain = AttackChain(
            chain_id="AC-01",
            name="Test Chain",
            severity=Severity.CRITICAL,
            findings=[
                _make_finding("aws-vpc-002"),
                _make_finding("aws-iam-005"),
            ],
            attack_narrative="Test",
            priority_fix="Test fix",
        )
        est = estimate_chain_cost(chain)
        assert est.low > 0
        assert est.high > est.low
        assert "Compound risk" in est.rationale

    def test_chain_multiplier(self) -> None:
        """Chain cost should be higher than sum of individual finding costs."""
        f1 = _make_finding("aws-vpc-002")
        f2 = _make_finding("aws-ec2-004")
        chain = AttackChain(
            chain_id="AC-02",
            name="SSRF Chain",
            severity=Severity.CRITICAL,
            findings=[f1, f2],
            attack_narrative="Test",
            priority_fix="Test fix",
        )
        chain_cost = estimate_chain_cost(chain)

        individual_1 = estimate_finding_cost(f1)
        individual_2 = estimate_finding_cost(f2)
        assert individual_1 is not None
        assert individual_2 is not None

        sum_low = individual_1.low + individual_2.low
        assert chain_cost.low > sum_low  # Multiplier applied

    def test_chain_cost_capped(self) -> None:
        """Chain cost high end should not exceed $10M cap."""
        # Create a chain with very expensive findings
        chain = AttackChain(
            chain_id="AC-TEST",
            name="Expensive Chain",
            severity=Severity.CRITICAL,
            findings=[
                _make_finding("aws-s3-001"),
                _make_finding("aws-rds-001"),
                _make_finding("aws-iam-001"),
                _make_finding("aws-iam-005"),
            ],
            attack_narrative="Test",
            priority_fix="Test fix",
        )
        est = estimate_chain_cost(chain)
        assert est.high <= 10_000_000

    def test_duplicate_check_ids_not_double_counted(self) -> None:
        """Multiple findings from same check should not be counted twice."""
        chain = AttackChain(
            chain_id="AC-TEST",
            name="Test",
            severity=Severity.HIGH,
            findings=[
                _make_finding("aws-vpc-002", resource_id="sg-1"),
                _make_finding("aws-vpc-002", resource_id="sg-2"),
            ],
            attack_narrative="Test",
            priority_fix="Test",
        )
        est = estimate_chain_cost(chain)
        single = estimate_finding_cost(_make_finding("aws-vpc-002"))
        assert single is not None
        # Should be multiplied once, not twice
        assert est.low == int(single.low * 2.5)


# ---------------------------------------------------------------------------
# estimate_total_exposure
# ---------------------------------------------------------------------------


class TestEstimateTotalExposure:
    def test_empty_report(self) -> None:
        report = ScanReport(provider="aws")
        report.compute_summary()
        est = estimate_total_exposure(report)
        assert est.low == 0
        assert est.high == 0
        assert "No quantifiable" in est.rationale

    def test_findings_only(self) -> None:
        report = ScanReport(
            provider="aws",
            results=[
                CheckResult(
                    check_id="aws-iam-001",
                    check_name="Root MFA",
                    findings=[_make_finding("aws-iam-001")],
                    resources_scanned=1,
                ),
            ],
        )
        report.compute_summary()
        est = estimate_total_exposure(report)
        assert est.low > 0
        assert est.high > est.low
        assert "IBM" in est.rationale

    def test_no_double_counting_chain_findings(self) -> None:
        """Findings in chains should not be counted again individually."""
        sg_finding = _make_finding("aws-vpc-002", resource_id="sg-123")
        report = ScanReport(
            provider="aws",
            results=[
                CheckResult(
                    check_id="aws-vpc-002",
                    check_name="Open SG",
                    findings=[sg_finding],
                    resources_scanned=1,
                ),
            ],
            attack_chains=[
                AttackChain(
                    chain_id="AC-01",
                    name="Test Chain",
                    severity=Severity.CRITICAL,
                    findings=[sg_finding],
                    attack_narrative="Test",
                    priority_fix="Test",
                ),
            ],
        )
        report.compute_summary()
        est = estimate_total_exposure(report)

        # Should only have chain cost, not chain + individual
        chain_only = estimate_chain_cost(report.attack_chains[0])
        assert est.low == chain_only.low
        assert est.high == chain_only.high


# ---------------------------------------------------------------------------
# Integration: scanner adds cost data to report
# ---------------------------------------------------------------------------


class TestScannerIntegration:
    def test_cost_estimate_serializes_to_json(self) -> None:
        """Verify CostEstimateData is properly serialized in report JSON."""
        from cloud_audit.models import CostEstimateData

        finding = _make_finding("aws-iam-001")
        finding.cost_estimate = CostEstimateData(
            low_usd=50_000, high_usd=500_000, display="$50K - $500K", rationale="test"
        )
        report = ScanReport(
            provider="aws",
            results=[
                CheckResult(check_id="aws-iam-001", check_name="Root MFA", findings=[finding], resources_scanned=1),
            ],
        )
        report.compute_summary()

        json_str = report.model_dump_json()
        assert "cost_estimate" in json_str
        assert "50000" in json_str
        assert "500000" in json_str
        assert "$50K - $500K" in json_str
