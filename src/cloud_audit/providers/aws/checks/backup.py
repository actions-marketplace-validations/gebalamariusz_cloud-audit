"""AWS Backup checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_backup_vault_exists(provider: AWSProvider) -> CheckResult:
    """Check if AWS Backup vault exists with at least one backup plan."""
    result = CheckResult(check_id="aws-backup-001", check_name="AWS Backup vault and plan")

    try:
        for region in provider.regions:
            backup = provider.session.client("backup", region_name=region)
            result.resources_scanned += 1

            # List backup vaults
            try:
                vaults = backup.list_backup_vaults().get("BackupVaultList", [])
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnauthorizedAccessException"):
                    continue
                raise

            if not vaults:
                result.findings.append(
                    Finding(
                        check_id="aws-backup-001",
                        title=f"No AWS Backup vault exists in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.RELIABILITY,
                        resource_type="AWS::Backup::BackupVault",
                        resource_id=f"backup-{region}",
                        region=region,
                        description=(
                            f"No AWS Backup vault exists in {region}. "
                            "Without a backup vault, automated backups cannot be stored. "
                            "Critical data may be unrecoverable after accidental deletion or ransomware."
                        ),
                        recommendation="Create an AWS Backup vault and configure a backup plan for critical resources.",
                        remediation=Remediation(
                            cli=(
                                f"# Create a backup vault:\n"
                                f"aws backup create-backup-vault "
                                f"--backup-vault-name default-vault "
                                f"--region {region}\n"
                                f"# Create a backup plan:\n"
                                f"aws backup create-backup-plan "
                                f'--backup-plan \'{{"BackupPlanName":"daily-backup",'
                                f'"Rules":[{{"RuleName":"daily",'
                                f'"TargetBackupVaultName":"default-vault",'
                                f'"ScheduleExpression":"cron(0 5 ? * * *)",'
                                f'"Lifecycle":{{"DeleteAfterDays":35}}}}]}}\' '
                                f"--region {region}"
                            ),
                            terraform=(
                                'resource "aws_backup_vault" "default" {\n'
                                '  name = "default-vault"\n'
                                "}\n"
                                "\n"
                                'resource "aws_backup_plan" "daily" {\n'
                                '  name = "daily-backup"\n'
                                "\n"
                                "  rule {\n"
                                '    rule_name         = "daily"\n'
                                "    target_vault_name = aws_backup_vault.default.name\n"
                                '    schedule          = "cron(0 5 ? * * *)"\n'
                                "\n"
                                "    lifecycle {\n"
                                "      delete_after = 35\n"
                                "    }\n"
                                "  }\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-backup-plan.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[],
                    )
                )
                continue

            # Vaults exist - check if at least one backup plan is configured
            try:
                plans = backup.list_backup_plans().get("BackupPlansList", [])
            except Exception:
                plans = []

            if not plans:
                result.findings.append(
                    Finding(
                        check_id="aws-backup-001",
                        title=f"No AWS Backup plan configured in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.RELIABILITY,
                        resource_type="AWS::Backup::BackupPlan",
                        resource_id=f"backup-plan-{region}",
                        region=region,
                        description=(
                            f"AWS Backup vault(s) exist in {region} but no backup plan is configured. "
                            "Without a backup plan, no automated backups are being created."
                        ),
                        recommendation="Create an AWS Backup plan with a schedule and assign resources to it.",
                        remediation=Remediation(
                            cli=(
                                f"aws backup create-backup-plan "
                                f'--backup-plan \'{{"BackupPlanName":"daily-backup",'
                                f'"Rules":[{{"RuleName":"daily",'
                                f'"TargetBackupVaultName":"{vaults[0].get("BackupVaultName", "default-vault")}",'
                                f'"ScheduleExpression":"cron(0 5 ? * * *)",'
                                f'"Lifecycle":{{"DeleteAfterDays":35}}}}]}}\' '
                                f"--region {region}"
                            ),
                            terraform=(
                                'resource "aws_backup_plan" "daily" {\n'
                                '  name = "daily-backup"\n'
                                "\n"
                                "  rule {\n"
                                '    rule_name         = "daily"\n'
                                "    target_vault_name = aws_backup_vault.default.name\n"
                                '    schedule          = "cron(0 5 ? * * *)"\n'
                                "\n"
                                "    lifecycle {\n"
                                "      delete_after = 35\n"
                                "    }\n"
                                "  }\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-backup-plan.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all AWS Backup checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_backup_vault_exists, provider, check_id="aws-backup-001", category=Category.RELIABILITY),
    ]
