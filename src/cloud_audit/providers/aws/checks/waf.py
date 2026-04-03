"""WAFv2 checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_waf_web_acl_exists(provider: AWSProvider) -> CheckResult:
    """Check if WAFv2 regional WebACL exists."""
    result = CheckResult(check_id="aws-waf-001", check_name="WAFv2 regional WebACL exists")

    try:
        for region in provider.regions:
            result.resources_scanned += 1

            try:
                wafv2 = provider.session.client("wafv2", region_name=region)
                response = wafv2.list_web_acls(Scope="REGIONAL")
                web_acls = response.get("WebACLs", [])
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "WAFNonexistentItemException"):
                    continue
                raise

            if not web_acls:
                result.findings.append(
                    Finding(
                        check_id="aws-waf-001",
                        title=f"No WAFv2 WebACL exists in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::WAFv2::WebACL",
                        resource_id=f"waf-{region}",
                        region=region,
                        description=(
                            f"No WAFv2 regional WebACL exists in {region}. "
                            "Without a Web Application Firewall, ALBs, API Gateways, "
                            "and other regional resources have no protection against "
                            "common web exploits (SQLi, XSS, bad bots)."
                        ),
                        recommendation="Create a WAFv2 WebACL with AWS Managed Rules and associate it with your ALB or API Gateway.",
                        remediation=Remediation(
                            cli=(
                                f"aws wafv2 create-web-acl \\\n"
                                f"  --name default-web-acl \\\n"
                                f"  --scope REGIONAL \\\n"
                                f"  --default-action '{{\"Allow\": {{}}}}' \\\n"
                                f"  --visibility-config "
                                f"SampledRequestsEnabled=true,"
                                f"CloudWatchMetricsEnabled=true,"
                                f"MetricName=default-web-acl \\\n"
                                f'  --rules \'[{{"Name":"AWS-AWSManagedRulesCommonRuleSet",'
                                f'"Priority":1,'
                                f'"Statement":{{"ManagedRuleGroupStatement":'
                                f'{{"VendorName":"AWS",'
                                f'"Name":"AWSManagedRulesCommonRuleSet"}}}},'
                                f'"OverrideAction":{{"None":{{}}}},'
                                f'"VisibilityConfig":{{"SampledRequestsEnabled":true,'
                                f'"CloudWatchMetricsEnabled":true,'
                                f'"MetricName":"CommonRuleSet"}}}}]\' \\\n'
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_wafv2_web_acl" "default" {\n'
                                '  name  = "default-web-acl"\n'
                                '  scope = "REGIONAL"\n'
                                "\n"
                                "  default_action {\n"
                                "    allow {}\n"
                                "  }\n"
                                "\n"
                                "  rule {\n"
                                '    name     = "AWSManagedRulesCommonRuleSet"\n'
                                "    priority = 1\n"
                                "\n"
                                "    override_action {\n"
                                "      none {}\n"
                                "    }\n"
                                "\n"
                                "    statement {\n"
                                "      managed_rule_group_statement {\n"
                                '        vendor_name = "AWS"\n'
                                '        name        = "AWSManagedRulesCommonRuleSet"\n'
                                "      }\n"
                                "    }\n"
                                "\n"
                                "    visibility_config {\n"
                                "      sampled_requests_enabled   = true\n"
                                "      cloudwatch_metrics_enabled = true\n"
                                '      metric_name                = "CommonRuleSet"\n'
                                "    }\n"
                                "  }\n"
                                "\n"
                                "  visibility_config {\n"
                                "    sampled_requests_enabled   = true\n"
                                "    cloudwatch_metrics_enabled = true\n"
                                '    metric_name                = "default-web-acl"\n'
                                "  }\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/waf/latest/developerguide/getting-started.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all WAF checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_waf_web_acl_exists, provider, check_id="aws-waf-001", category=Category.SECURITY),
    ]
