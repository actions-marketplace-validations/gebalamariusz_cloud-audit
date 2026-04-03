"""Tests for SOC 2 Type II compliance framework mapping."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cloud_audit.compliance import list_frameworks, load_framework
from cloud_audit.compliance.engine import build_compliance_report
from cloud_audit.models import CheckResult, ScanReport

FRAMEWORK_ID = "soc2_type2"


@pytest.fixture()
def soc2_framework() -> dict:
    """Load the SOC 2 framework."""
    return load_framework(FRAMEWORK_ID)


class TestFrameworkLoading:
    """Test that the SOC 2 framework JSON loads correctly."""

    def test_framework_discoverable(self) -> None:
        """SOC 2 appears in list_frameworks."""
        ids = [fw["id"] for fw in list_frameworks()]
        assert FRAMEWORK_ID in ids

    def test_framework_loads(self, soc2_framework: dict) -> None:
        """Framework loads without error."""
        assert soc2_framework["framework_id"] == FRAMEWORK_ID
        assert soc2_framework["framework_name"] == "SOC 2 Type II - Trust Services Criteria"
        assert soc2_framework["version"] == "2017 (Revised 2022)"

    def test_source_url_present(self, soc2_framework: dict) -> None:
        """Source URL points to AICPA."""
        assert "aicpa" in soc2_framework["source_url"].lower()

    def test_disclaimer_present(self, soc2_framework: dict) -> None:
        """Disclaimer clearly states this is not an audit."""
        disclaimer = soc2_framework["disclaimer"]
        assert "does not constitute" in disclaimer
        assert "CPA" in disclaimer


class TestControlStructure:
    """Test the structure of all 43 controls."""

    def test_total_control_count(self, soc2_framework: dict) -> None:
        """Exactly 43 controls (33 CC + 3 A + 2 C + 5 PI)."""
        assert len(soc2_framework["controls"]) == 43

    def test_control_id_format(self, soc2_framework: dict) -> None:
        """All control IDs match SOC 2 naming convention."""
        pattern = re.compile(r"^(CC[1-9]\.\d|A1\.\d|C1\.\d|PI1\.\d)$")
        for cid in soc2_framework["controls"]:
            assert pattern.match(cid), f"Invalid control ID format: {cid}"

    def test_required_fields_present(self, soc2_framework: dict) -> None:
        """Every control has all required fields."""
        required = [
            "title",
            "section",
            "level",
            "assessment",
            "description",
            "checks",
            "manual_steps",
            "evidence_template",
        ]
        for cid, ctrl in soc2_framework["controls"].items():
            for field in required:
                assert field in ctrl, f"{cid} missing field: {field}"

    def test_assessment_values_valid(self, soc2_framework: dict) -> None:
        """Assessment is one of Automated/Manual/Partial."""
        valid = {"Automated", "Manual", "Partial"}
        for cid, ctrl in soc2_framework["controls"].items():
            assert ctrl["assessment"] in valid, f"{cid} has invalid assessment: {ctrl['assessment']}"

    def test_manual_controls_have_no_checks(self, soc2_framework: dict) -> None:
        """Manual-only controls have empty checks list."""
        for cid, ctrl in soc2_framework["controls"].items():
            if ctrl["assessment"] == "Manual":
                assert not ctrl["checks"], f"{cid} is Manual but has checks: {ctrl['checks']}"

    def test_automated_controls_have_checks(self, soc2_framework: dict) -> None:
        """Automated/Partial controls have at least one check."""
        for cid, ctrl in soc2_framework["controls"].items():
            if ctrl["assessment"] in ("Automated", "Partial"):
                assert ctrl["checks"], f"{cid} is {ctrl['assessment']} but has no checks"

    def test_no_duplicate_checks_within_control(self, soc2_framework: dict) -> None:
        """No control has the same check listed twice."""
        for cid, ctrl in soc2_framework["controls"].items():
            checks = ctrl.get("checks", [])
            assert len(checks) == len(set(checks)), f"{cid} has duplicate checks"


class TestSections:
    """Test section coverage matches SOC 2 categories."""

    EXPECTED_SECTIONS: frozenset[str] = frozenset(
        {
            "CC1 - Control Environment",
            "CC2 - Communication and Information",
            "CC3 - Risk Assessment",
            "CC4 - Monitoring Activities",
            "CC5 - Control Activities",
            "CC6 - Logical and Physical Access Controls",
            "CC7 - System Operations",
            "CC8 - Change Management",
            "CC9 - Risk Mitigation",
            "A1 - Availability",
            "C1 - Confidentiality",
            "PI1 - Processing Integrity",
        }
    )

    def test_all_sections_present(self, soc2_framework: dict) -> None:
        """All 12 SOC 2 sections are represented."""
        sections = {ctrl["section"] for ctrl in soc2_framework["controls"].values()}
        assert sections == self.EXPECTED_SECTIONS

    def test_cc_section_counts(self, soc2_framework: dict) -> None:
        """Common Criteria section has correct control counts."""
        counts = {}
        for ctrl in soc2_framework["controls"].values():
            s = ctrl["section"]
            counts[s] = counts.get(s, 0) + 1
        assert counts["CC1 - Control Environment"] == 5
        assert counts["CC2 - Communication and Information"] == 3
        assert counts["CC3 - Risk Assessment"] == 4
        assert counts["CC4 - Monitoring Activities"] == 2
        assert counts["CC5 - Control Activities"] == 3
        assert counts["CC6 - Logical and Physical Access Controls"] == 8
        assert counts["CC7 - System Operations"] == 5
        assert counts["CC8 - Change Management"] == 1
        assert counts["CC9 - Risk Mitigation"] == 2

    def test_optional_category_counts(self, soc2_framework: dict) -> None:
        """Optional categories have correct control counts."""
        counts = {}
        for ctrl in soc2_framework["controls"].values():
            s = ctrl["section"]
            counts[s] = counts.get(s, 0) + 1
        assert counts["A1 - Availability"] == 3
        assert counts["C1 - Confidentiality"] == 2
        assert counts["PI1 - Processing Integrity"] == 5


class TestCheckMappings:
    """Test check ID validity and mapping quality."""

    def test_mapped_check_count(self, soc2_framework: dict) -> None:
        """At least 75 unique checks are mapped (of 80 total)."""
        all_checks = set()
        for ctrl in soc2_framework["controls"].values():
            all_checks.update(ctrl.get("checks", []))
        assert len(all_checks) >= 75, f"Only {len(all_checks)} checks mapped"

    def test_check_id_format(self, soc2_framework: dict) -> None:
        """All check IDs follow aws-service-NNN pattern."""
        pattern = re.compile(r"^aws-[a-z0-9]+-\d{3}$")
        for cid, ctrl in soc2_framework["controls"].items():
            for check_id in ctrl.get("checks", []):
                assert pattern.match(check_id), f"{cid} has invalid check_id: {check_id}"

    def test_cc6_has_most_checks(self, soc2_framework: dict) -> None:
        """CC6 (Logical Access) has the highest check density - core of SOC 2 for AWS."""
        cc6_checks = set()
        for cid, ctrl in soc2_framework["controls"].items():
            if cid.startswith("CC6"):
                cc6_checks.update(ctrl.get("checks", []))
        assert len(cc6_checks) >= 30, f"CC6 only has {len(cc6_checks)} unique checks"

    def test_cc7_monitoring_checks(self, soc2_framework: dict) -> None:
        """CC7.2 (anomaly monitoring) maps CloudWatch alarms."""
        cc72 = soc2_framework["controls"]["CC7.2"]
        cw_checks = [c for c in cc72["checks"] if c.startswith("aws-cw-")]
        assert len(cw_checks) >= 14, f"CC7.2 only has {len(cw_checks)} CloudWatch checks"

    def test_encryption_checks_in_cc6_7(self, soc2_framework: dict) -> None:
        """CC6.7 (data protection) maps encryption checks."""
        cc67 = soc2_framework["controls"]["CC6.7"]
        encryption_checks = {"aws-s3-002", "aws-rds-002", "aws-ec2-002", "aws-ec2-006", "aws-efs-001", "aws-kms-001"}
        mapped = set(cc67["checks"])
        assert encryption_checks.issubset(mapped), f"Missing encryption checks: {encryption_checks - mapped}"


class TestAttackChainMappings:
    """Test attack chain to SOC 2 control mappings."""

    def test_all_chains_mapped(self, soc2_framework: dict) -> None:
        """All 20 attack chains have SOC 2 mappings."""
        chains = soc2_framework.get("attack_chain_mappings", {})
        assert len(chains) == 25

    def test_chain_ids_valid(self, soc2_framework: dict) -> None:
        """All chain IDs follow AC-NN format."""
        chains = soc2_framework.get("attack_chain_mappings", {})
        for chain_id in chains:
            assert re.match(r"^AC-\d{2}$", chain_id), f"Invalid chain ID: {chain_id}"

    def test_chain_refs_valid_controls(self, soc2_framework: dict) -> None:
        """All chain references point to existing controls."""
        chains = soc2_framework.get("attack_chain_mappings", {})
        ctrl_ids = set(soc2_framework["controls"].keys())
        for chain_id, refs in chains.items():
            for ref in refs:
                assert ref in ctrl_ids, f"{chain_id} references non-existent control: {ref}"

    def test_chains_map_to_cc6_cc7(self, soc2_framework: dict) -> None:
        """Most attack chains map to CC6 (access) or CC7 (operations)."""
        chains = soc2_framework.get("attack_chain_mappings", {})
        cc6_cc7_count = 0
        for refs in chains.values():
            if any(r.startswith(("CC6", "CC7")) for r in refs):
                cc6_cc7_count += 1
        assert cc6_cc7_count >= 18, f"Only {cc6_cc7_count}/20 chains map to CC6/CC7"


class TestComplianceEngine:
    """Test that the compliance engine processes SOC 2 correctly."""

    def test_empty_scan_all_not_assessed(self) -> None:
        """An empty scan results in all controls NOT_ASSESSED."""
        scan = ScanReport(
            provider="aws",
            account_id="123456789012",
            regions=["eu-central-1"],
            results=[],
            duration_seconds=1.0,
            timestamp="2026-03-31T00:00:00Z",
        )
        scan.compute_summary()
        report = build_compliance_report(FRAMEWORK_ID, scan)
        assert report.controls_not_assessed == 43
        assert report.controls_passing == 0
        assert report.readiness_score == 0.0

    def test_passing_checks_yield_pass(self) -> None:
        """Controls with all mapped checks passing are PASS."""
        results = [
            CheckResult(check_id="aws-iam-003", check_name="Key rotation", findings=[]),
            CheckResult(check_id="aws-iam-004", check_name="Unused keys", findings=[]),
            CheckResult(check_id="aws-iam-009", check_name="Multiple keys", findings=[]),
            CheckResult(check_id="aws-iam-013", check_name="Expired certs", findings=[]),
        ]
        scan = ScanReport(
            provider="aws",
            account_id="123456789012",
            regions=["eu-central-1"],
            results=results,
            duration_seconds=1.0,
            timestamp="2026-03-31T00:00:00Z",
        )
        scan.compute_summary()
        report = build_compliance_report(FRAMEWORK_ID, scan)
        cc62 = next(c for c in report.controls if c.control_id == "CC6.2")
        assert cc62.status == "PASS"

    def test_readiness_score_calculation(self) -> None:
        """Readiness score is percentage of assessed controls passing."""
        # 2 controls will be assessed: CC6.2 (PASS) and CC6.3 (has checks but not all executed)
        results = [
            CheckResult(check_id="aws-iam-003", check_name="Key rotation", findings=[]),
            CheckResult(check_id="aws-iam-004", check_name="Unused keys", findings=[]),
            CheckResult(check_id="aws-iam-009", check_name="Multiple keys", findings=[]),
            CheckResult(check_id="aws-iam-013", check_name="Expired certs", findings=[]),
        ]
        scan = ScanReport(
            provider="aws",
            account_id="123456789012",
            regions=["eu-central-1"],
            results=results,
            duration_seconds=1.0,
            timestamp="2026-03-31T00:00:00Z",
        )
        scan.compute_summary()
        report = build_compliance_report(FRAMEWORK_ID, scan)
        assert report.readiness_score > 0.0

    def test_framework_metadata_in_report(self) -> None:
        """Report contains correct framework metadata."""
        scan = ScanReport(
            provider="aws",
            account_id="123456789012",
            regions=["eu-central-1"],
            results=[],
            duration_seconds=1.0,
            timestamp="2026-03-31T00:00:00Z",
        )
        scan.compute_summary()
        report = build_compliance_report(FRAMEWORK_ID, scan)
        assert report.framework_id == FRAMEWORK_ID
        assert "SOC 2" in report.framework_name
        assert report.total_controls == 43


class TestJSONIntegrity:
    """Test the JSON file directly for structural integrity."""

    def test_valid_json(self) -> None:
        """File is valid JSON."""
        path = Path(__file__).parent.parent / "src" / "cloud_audit" / "compliance" / "frameworks" / "soc2_type2.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "controls" in data

    def test_no_empty_strings_in_titles(self, soc2_framework: dict) -> None:
        """No control has an empty title."""
        for cid, ctrl in soc2_framework["controls"].items():
            assert ctrl["title"].strip(), f"{cid} has empty title"

    def test_no_empty_descriptions(self, soc2_framework: dict) -> None:
        """No control has an empty description."""
        for cid, ctrl in soc2_framework["controls"].items():
            assert ctrl["description"].strip(), f"{cid} has empty description"

    def test_evidence_templates_have_placeholders(self, soc2_framework: dict) -> None:
        """Automated controls have evidence templates with format placeholders."""
        for cid, ctrl in soc2_framework["controls"].items():
            if ctrl["checks"]:
                tpl = ctrl["evidence_template"]
                has_placeholders = "{pass_count}" in tpl or "requires manual" in tpl.lower()
                assert has_placeholders, f"{cid} evidence template missing placeholders"

    def test_manual_controls_have_manual_steps(self, soc2_framework: dict) -> None:
        """Manual controls have non-empty manual_steps."""
        for cid, ctrl in soc2_framework["controls"].items():
            if ctrl["assessment"] == "Manual":
                assert ctrl["manual_steps"].strip(), f"{cid} is Manual but has empty manual_steps"
