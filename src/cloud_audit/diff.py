"""Diff engine - compare two scan reports and produce a structured diff."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from cloud_audit.models import Finding, ScanReport, Severity

# Maximum report file size (50 MB). Prevents OOM on malicious/accidental large files.
_MAX_REPORT_SIZE = 50 * 1024 * 1024


class FindingChange(BaseModel):
    """A single finding that appeared, disappeared, or changed between scans."""

    check_id: str
    resource_id: str
    region: str = "global"
    title: str
    severity: Severity
    old_severity: Severity | None = None  # only for "changed" findings
    category: str = ""
    resource_type: str = ""


class DiffResult(BaseModel):
    """Result of comparing two scan reports."""

    old_score: int
    new_score: int
    score_change: int
    old_total: int
    new_total: int
    new_findings: list[FindingChange] = Field(default_factory=list)
    fixed_findings: list[FindingChange] = Field(default_factory=list)
    changed_findings: list[FindingChange] = Field(default_factory=list)
    unchanged_findings: list[FindingChange] = Field(default_factory=list)
    scope_warnings: list[str] = Field(default_factory=list)
    has_regression: bool = False


def _finding_key(f: Finding) -> str:
    """Unique identity for a finding: check_id + resource_id."""
    return f"{f.check_id}:{f.resource_id}"


def _to_change(f: Finding, *, old_severity: Severity | None = None) -> FindingChange:
    return FindingChange(
        check_id=f.check_id,
        resource_id=f.resource_id,
        region=f.region,
        title=f.title,
        severity=f.severity,
        old_severity=old_severity,
        category=f.category.value,
        resource_type=f.resource_type,
    )


def _check_scope(old: ScanReport, new: ScanReport) -> list[str]:
    """Detect scope differences between two reports and return warnings."""
    warnings: list[str] = []
    if old.provider != new.provider:
        warnings.append(f"Provider changed: {old.provider} -> {new.provider}")
    if old.account_id and new.account_id and old.account_id != new.account_id:
        warnings.append(f"Account changed: {old.account_id} -> {new.account_id}")
    old_regions = set(old.regions)
    new_regions = set(new.regions)
    if old_regions != new_regions:
        added = new_regions - old_regions
        removed = old_regions - new_regions
        parts = []
        if added:
            parts.append(f"added {', '.join(sorted(added))}")
        if removed:
            parts.append(f"removed {', '.join(sorted(removed))}")
        warnings.append(f"Regions changed: {'; '.join(parts)}")
    return warnings


def compute_diff(old: ScanReport, new: ScanReport) -> DiffResult:
    """Compare two ScanReports and return a structured diff.

    Findings are matched by (check_id, resource_id). Categories:
    - new: in new scan, not in old
    - fixed: in old scan, not in new
    - changed: same key, different severity
    - unchanged: same key, same severity
    """
    severity_order = list(Severity)

    # Build lookup dicts by (check_id, resource_id) key.
    # If multiple findings share the same key (unlikely - each check produces
    # at most one finding per resource), only the last one is retained.
    old_findings: dict[str, Finding] = {}
    for f in old.all_findings:
        old_findings[_finding_key(f)] = f

    new_findings_map: dict[str, Finding] = {}
    for f in new.all_findings:
        new_findings_map[_finding_key(f)] = f

    result_new: list[FindingChange] = []
    result_fixed: list[FindingChange] = []
    result_changed: list[FindingChange] = []
    result_unchanged: list[FindingChange] = []

    # Findings in new but not in old → NEW
    # Findings in both → UNCHANGED or CHANGED
    for key, f in new_findings_map.items():
        if key not in old_findings:
            result_new.append(_to_change(f))
        else:
            old_f = old_findings[key]
            if f.severity != old_f.severity:
                result_changed.append(_to_change(f, old_severity=old_f.severity))
            else:
                result_unchanged.append(_to_change(f))

    # Findings in old but not in new → FIXED
    for key, f in old_findings.items():
        if key not in new_findings_map:
            result_fixed.append(_to_change(f))

    # Sort by severity (most severe first)
    result_new.sort(key=lambda c: severity_order.index(c.severity))
    result_fixed.sort(key=lambda c: severity_order.index(c.severity))
    result_changed.sort(key=lambda c: severity_order.index(c.severity))
    result_unchanged.sort(key=lambda c: severity_order.index(c.severity))

    old_score = old.summary.score
    new_score = new.summary.score

    return DiffResult(
        old_score=old_score,
        new_score=new_score,
        score_change=new_score - old_score,
        old_total=old.summary.total_findings,
        new_total=new.summary.total_findings,
        new_findings=result_new,
        fixed_findings=result_fixed,
        changed_findings=result_changed,
        unchanged_findings=result_unchanged,
        scope_warnings=_check_scope(old, new),
        has_regression=len(result_new) > 0,
    )


def load_report(path: str | Path) -> ScanReport:
    """Load a ScanReport from a JSON file."""
    p = Path(path)
    if not p.is_file():
        msg = f"Not a regular file: {p}"
        raise FileNotFoundError(msg)
    if p.stat().st_size > _MAX_REPORT_SIZE:
        msg = f"Report file too large ({p.stat().st_size} bytes, max {_MAX_REPORT_SIZE})"
        raise ValueError(msg)
    content = p.read_text(encoding="utf-8")
    return ScanReport.model_validate_json(content)
