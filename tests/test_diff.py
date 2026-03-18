"""Tests for diff engine - compare two scan reports."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from cloud_audit.cli import app
from cloud_audit.diff import compute_diff, load_report
from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)
from cloud_audit.reports.diff_markdown import generate_diff_markdown

runner = CliRunner()


def _make_finding(
    check_id: str = "aws-iam-001",
    resource_id: str = "root",
    severity: Severity = Severity.CRITICAL,
    title: str = "Root account without MFA",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::IAM::User",
        resource_id=resource_id,
        description="Test finding.",
        recommendation="Fix it.",
        remediation=Remediation(
            cli="aws iam do-something",
            terraform='resource "aws_iam" "x" {}',
            doc_url="https://docs.aws.amazon.com",
            effort=Effort.LOW,
        ),
    )


def _make_report(findings: list[Finding], score: int | None = None) -> ScanReport:
    report = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
    )
    report.results.append(
        CheckResult(
            check_id="test",
            check_name="Test",
            findings=findings,
            resources_scanned=len(findings),
        )
    )
    report.compute_summary()
    if score is not None:
        report.summary.score = score
    return report


# --- Core diff logic ---


def test_no_changes() -> None:
    """Identical reports produce empty diff."""
    f = _make_finding()
    old = _make_report([f])
    new = _make_report([f])
    diff = compute_diff(old, new)
    assert diff.new_findings == []
    assert diff.fixed_findings == []
    assert diff.changed_findings == []
    assert len(diff.unchanged_findings) == 1
    assert diff.has_regression is False


def test_new_finding_detected() -> None:
    """Finding in new scan but not old is flagged as new."""
    f1 = _make_finding(check_id="aws-iam-001", resource_id="root")
    f2 = _make_finding(check_id="aws-s3-001", resource_id="my-bucket", severity=Severity.HIGH, title="Public bucket")
    old = _make_report([f1])
    new = _make_report([f1, f2])
    diff = compute_diff(old, new)
    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].check_id == "aws-s3-001"
    assert diff.has_regression is True


def test_fixed_finding_detected() -> None:
    """Finding in old scan but not new is flagged as fixed."""
    f1 = _make_finding(check_id="aws-iam-001", resource_id="root")
    f2 = _make_finding(check_id="aws-s3-001", resource_id="my-bucket", severity=Severity.HIGH)
    old = _make_report([f1, f2])
    new = _make_report([f1])
    diff = compute_diff(old, new)
    assert len(diff.fixed_findings) == 1
    assert diff.fixed_findings[0].check_id == "aws-s3-001"
    assert diff.has_regression is False


def test_severity_change_detected() -> None:
    """Same finding with different severity is flagged as changed."""
    f_old = _make_finding(severity=Severity.CRITICAL)
    f_new = _make_finding(severity=Severity.HIGH)
    old = _make_report([f_old])
    new = _make_report([f_new])
    diff = compute_diff(old, new)
    assert diff.changed_findings[0].severity == Severity.HIGH
    assert diff.changed_findings[0].old_severity == Severity.CRITICAL
    assert len(diff.unchanged_findings) == 0
    assert diff.has_regression is False


def test_score_change() -> None:
    """Score change is correctly computed."""
    old = _make_report([], score=62)
    new = _make_report([], score=78)
    diff = compute_diff(old, new)
    assert diff.old_score == 62
    assert diff.new_score == 78
    assert diff.score_change == 16


def test_score_decrease() -> None:
    """Negative score change works."""
    old = _make_report([], score=80)
    new = _make_report([], score=60)
    diff = compute_diff(old, new)
    assert diff.score_change == -20


def test_empty_reports() -> None:
    """Two empty reports produce clean diff."""
    old = _make_report([])
    new = _make_report([])
    diff = compute_diff(old, new)
    assert diff.new_findings == []
    assert diff.fixed_findings == []
    assert len(diff.unchanged_findings) == 0
    assert diff.has_regression is False


def test_scope_warning_regions() -> None:
    """Different regions trigger a scope warning."""
    old = _make_report([])
    new = _make_report([])
    old.regions = ["eu-central-1"]
    new.regions = ["eu-central-1", "eu-west-1"]
    diff = compute_diff(old, new)
    assert len(diff.scope_warnings) == 1
    assert "eu-west-1" in diff.scope_warnings[0]


def test_scope_warning_account() -> None:
    """Different account IDs trigger a scope warning."""
    old = _make_report([])
    new = _make_report([])
    old.account_id = "111111111111"
    new.account_id = "222222222222"
    diff = compute_diff(old, new)
    assert any("Account" in w for w in diff.scope_warnings)


def test_scope_warning_provider() -> None:
    """Different providers trigger a scope warning."""
    old = _make_report([])
    new = _make_report([])
    old_raw = old.model_dump()
    old_raw["provider"] = "aws"
    new_raw = new.model_dump()
    new_raw["provider"] = "azure"
    old2 = ScanReport.model_validate(old_raw)
    new2 = ScanReport.model_validate(new_raw)
    old2.compute_summary()
    new2.compute_summary()
    diff = compute_diff(old2, new2)
    assert any("Provider" in w for w in diff.scope_warnings)


def test_no_scope_warning_same_scope() -> None:
    """Same scope produces no warnings."""
    old = _make_report([])
    new = _make_report([])
    diff = compute_diff(old, new)
    assert diff.scope_warnings == []


def test_multiple_new_and_fixed() -> None:
    """Multiple findings can be new and fixed simultaneously."""
    f1 = _make_finding(check_id="aws-iam-001", resource_id="root")
    f2 = _make_finding(check_id="aws-s3-001", resource_id="bucket-a", severity=Severity.HIGH)
    f3 = _make_finding(check_id="aws-vpc-002", resource_id="sg-123", severity=Severity.CRITICAL)
    f4 = _make_finding(check_id="aws-rds-001", resource_id="db-prod", severity=Severity.HIGH)

    old = _make_report([f1, f2])  # root MFA + public bucket
    new = _make_report([f1, f3, f4])  # root MFA + open SG + public RDS

    diff = compute_diff(old, new)
    assert len(diff.new_findings) == 2  # sg-123, db-prod
    assert len(diff.fixed_findings) == 1  # bucket-a
    assert len(diff.unchanged_findings) == 1  # root
    assert diff.has_regression is True


def test_findings_sorted_by_severity() -> None:
    """New/fixed findings are sorted by severity (most severe first)."""
    f1 = _make_finding(check_id="c1", resource_id="r1", severity=Severity.LOW)
    f2 = _make_finding(check_id="c2", resource_id="r2", severity=Severity.CRITICAL)
    f3 = _make_finding(check_id="c3", resource_id="r3", severity=Severity.MEDIUM)
    old = _make_report([])
    new = _make_report([f1, f2, f3])
    diff = compute_diff(old, new)
    severities = [f.severity for f in diff.new_findings]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_identical_finding_is_unchanged() -> None:
    """Same finding in both reports is counted as unchanged."""
    f = _make_finding()
    old = _make_report([f])
    new = _make_report([f])
    diff = compute_diff(old, new)
    assert len(diff.unchanged_findings) == 1


def test_duplicate_key_last_wins() -> None:
    """When two findings share a key in same report, last one wins in dict."""
    f1 = _make_finding(severity=Severity.CRITICAL)
    f2 = _make_finding(severity=Severity.LOW)  # same check_id + resource_id
    old = _make_report([f1])
    new = _make_report([f1, f2])  # f2 overwrites f1 in the dict
    diff = compute_diff(old, new)
    assert len(diff.changed_findings) == 1
    assert diff.changed_findings[0].severity == Severity.LOW


# --- JSON serialization ---


def test_diff_result_json() -> None:
    """DiffResult serializes to valid JSON."""
    diff = compute_diff(_make_report([]), _make_report([]))
    data = diff.model_dump_json()
    assert "old_score" in data
    assert "has_regression" in data


# --- Load report ---


def test_load_report_from_json(tmp_path: Path) -> None:
    """load_report reads a JSON file into ScanReport."""
    report = _make_report([_make_finding()])
    json_path = tmp_path / "scan.json"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    loaded = load_report(json_path)
    assert loaded.provider == "aws"
    assert loaded.summary.total_findings == 1


def test_load_report_invalid_json(tmp_path: Path) -> None:
    """load_report raises on malformed JSON."""
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not valid json", encoding="utf-8")
    with pytest.raises((ValueError, ValidationError)):
        load_report(bad_path)


def test_load_report_not_a_file(tmp_path: Path) -> None:
    """load_report raises on directory path."""
    with pytest.raises(FileNotFoundError):
        load_report(tmp_path)  # tmp_path is a directory, not a file


# --- Markdown output ---


def test_diff_markdown_no_changes() -> None:
    """Markdown for clean diff."""
    diff = compute_diff(_make_report([]), _make_report([]))
    md = generate_diff_markdown(diff)
    assert "## cloud-audit diff" in md
    assert "No new findings" in md


def test_diff_markdown_new_findings() -> None:
    """Markdown includes new findings table."""
    f = _make_finding(check_id="aws-s3-001", resource_id="bad-bucket", severity=Severity.HIGH, title="Public bucket")
    diff = compute_diff(_make_report([]), _make_report([f]))
    md = generate_diff_markdown(diff)
    assert "### New findings" in md
    assert "aws-s3-001" in md
    assert "bad-bucket" in md


def test_diff_markdown_fixed_findings() -> None:
    """Markdown includes fixed findings table."""
    f = _make_finding()
    diff = compute_diff(_make_report([f]), _make_report([]))
    md = generate_diff_markdown(diff)
    assert "### Fixed" in md
    assert "aws-iam-001" in md


def test_diff_markdown_changed_severity() -> None:
    """Markdown includes changed severity table."""
    f_old = _make_finding(severity=Severity.CRITICAL)
    f_new = _make_finding(severity=Severity.HIGH)
    diff = compute_diff(_make_report([f_old]), _make_report([f_new]))
    md = generate_diff_markdown(diff)
    assert "Changed severity" in md
    assert "CRITICAL" in md
    assert "HIGH" in md


def test_diff_markdown_scope_warning() -> None:
    """Markdown includes scope warnings."""
    old = _make_report([])
    new = _make_report([])
    old.regions = ["eu-central-1"]
    new.regions = ["eu-central-1", "us-east-1"]
    diff = compute_diff(old, new)
    md = generate_diff_markdown(diff)
    assert "Warning" in md
    assert "us-east-1" in md


def test_diff_markdown_score() -> None:
    """Markdown shows score change."""
    old = _make_report([], score=60)
    new = _make_report([], score=80)
    diff = compute_diff(old, new)
    md = generate_diff_markdown(diff)
    assert "60" in md
    assert "80" in md
    assert "+20" in md


# --- CLI integration tests ---


def _write_report(path: Path, findings: list[Finding], score: int | None = None) -> None:
    """Write a ScanReport JSON to disk."""
    report = _make_report(findings, score=score)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def test_cli_diff_no_regression(tmp_path: Path) -> None:
    """CLI diff exits 0 when no new findings."""
    f = _make_finding()
    _write_report(tmp_path / "old.json", [f])
    _write_report(tmp_path / "new.json", [f])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json")])
    assert result.exit_code == 0


def test_cli_diff_regression_exits_1(tmp_path: Path) -> None:
    """CLI diff exits 1 when new findings detected."""
    f1 = _make_finding()
    f2 = _make_finding(check_id="aws-s3-001", resource_id="bucket", severity=Severity.HIGH)
    _write_report(tmp_path / "old.json", [f1])
    _write_report(tmp_path / "new.json", [f1, f2])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json")])
    assert result.exit_code == 1


def test_cli_diff_file_not_found(tmp_path: Path) -> None:
    """CLI diff exits 2 when file does not exist."""
    _write_report(tmp_path / "old.json", [])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "missing.json")])
    assert result.exit_code == 2
    assert "not found" in result.output.lower()


def test_cli_diff_invalid_json(tmp_path: Path) -> None:
    """CLI diff exits 2 on malformed JSON."""
    (tmp_path / "old.json").write_text("not valid json", encoding="utf-8")
    _write_report(tmp_path / "new.json", [])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json")])
    assert result.exit_code == 2
    assert "failed to load" in result.output.lower()


def test_cli_diff_unknown_format(tmp_path: Path) -> None:
    """CLI diff exits 2 on unknown format."""
    _write_report(tmp_path / "old.json", [])
    _write_report(tmp_path / "new.json", [])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--format", "xml"])
    assert result.exit_code == 2
    assert "unknown format" in result.output.lower()


def test_cli_diff_quiet_no_output(tmp_path: Path) -> None:
    """CLI diff --quiet produces no console output."""
    f = _make_finding()
    _write_report(tmp_path / "old.json", [f])
    _write_report(tmp_path / "new.json", [f])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--quiet"])
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_cli_diff_json_format(tmp_path: Path) -> None:
    """CLI diff --format json outputs valid JSON."""
    import json

    f = _make_finding()
    _write_report(tmp_path / "old.json", [f])
    _write_report(tmp_path / "new.json", [f])
    result = runner.invoke(app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--format", "json"])
    data = json.loads(result.output)
    assert data["has_regression"] is False
    assert len(data["unchanged_findings"]) == 1


def test_cli_diff_markdown_format(tmp_path: Path) -> None:
    """CLI diff --format markdown outputs valid markdown."""
    f = _make_finding()
    f2 = _make_finding(check_id="aws-rds-001", resource_id="db", severity=Severity.HIGH)
    _write_report(tmp_path / "old.json", [f])
    _write_report(tmp_path / "new.json", [f, f2])
    result = runner.invoke(
        app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--format", "markdown"]
    )
    assert "## cloud-audit diff" in result.output
    assert "aws-rds-001" in result.output


def test_cli_diff_output_to_file(tmp_path: Path) -> None:
    """CLI diff --output writes to file."""
    f = _make_finding()
    _write_report(tmp_path / "old.json", [f])
    _write_report(tmp_path / "new.json", [f])
    out = tmp_path / "diff.json"
    result = runner.invoke(
        app, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "old_score" in out.read_text(encoding="utf-8")
