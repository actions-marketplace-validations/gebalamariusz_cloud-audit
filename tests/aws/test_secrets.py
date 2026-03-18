"""Tests for Secrets Manager checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

from cloud_audit.providers.aws.checks.secrets import (
    check_secret_rotation,
    check_unused_secret,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_secret_rotation_fail(mock_aws_provider: AWSProvider) -> None:
    """Secret without rotation - MEDIUM finding."""
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="db-credentials", SecretString='{"user":"admin","pass":"secret"}')
    result = check_secret_rotation(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-sm-001"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "db-credentials" in findings[0].title


def test_secret_rotation_pass_no_secrets(mock_aws_provider: AWSProvider) -> None:
    """No secrets - no findings."""
    result = check_secret_rotation(mock_aws_provider)
    assert len(result.findings) == 0


def test_unused_secret_pass(mock_aws_provider: AWSProvider) -> None:
    """Recently created secret - no finding (moto doesn't set LastAccessedDate initially)."""
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="fresh-secret", SecretString="value")
    result = check_unused_secret(mock_aws_provider)
    # moto doesn't set LastAccessedDate by default, so no finding expected
    findings = [f for f in result.findings if f.check_id == "aws-sm-002"]
    assert len(findings) == 0


def test_unused_secret_no_secrets(mock_aws_provider: AWSProvider) -> None:
    """No secrets - no findings."""
    result = check_unused_secret(mock_aws_provider)
    assert len(result.findings) == 0


def test_unused_secret_old_access_mocked(mock_aws_provider: AWSProvider) -> None:
    """Secret with LastAccessedDate older than 90 days - LOW finding.

    moto does not set LastAccessedDate on secrets, so we create the secret via
    moto then wrap session.client to return a secretsmanager client whose
    list_secrets paginator injects a stale LastAccessedDate.
    """
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="old-secret", SecretString="value")

    stale_date = datetime.now(timezone.utc) - timedelta(days=120)

    original_client = mock_aws_provider.session.client

    def wrapped_client(*args, **kwargs):
        client = original_client(*args, **kwargs)
        service_name = args[0] if args else kwargs.get("service_name", "")
        if service_name == "secretsmanager":
            real_get_paginator = client.get_paginator

            def patched_get_paginator(operation_name):
                paginator = real_get_paginator(operation_name)
                if operation_name == "list_secrets":
                    real_paginate = paginator.paginate

                    def patched_paginate(**kw):
                        for page in real_paginate(**kw):
                            for secret in page.get("SecretList", []):
                                secret["LastAccessedDate"] = stale_date
                            yield page

                    paginator.paginate = patched_paginate
                return paginator

            client.get_paginator = patched_get_paginator
        return client

    with patch.object(mock_aws_provider.session, "client", side_effect=wrapped_client):
        result = check_unused_secret(mock_aws_provider)

    findings = [f for f in result.findings if f.check_id == "aws-sm-002"]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert "old-secret" in findings[0].title
