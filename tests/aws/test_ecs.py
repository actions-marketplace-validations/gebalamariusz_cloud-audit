"""Tests for ECS security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from cloud_audit.providers.aws.checks.ecs import (
    check_ecs_exec,
    check_privileged_task,
    check_task_logging,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_privileged_task_fail(mock_aws_provider: AWSProvider) -> None:
    """Task definition with privileged container - CRITICAL finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="priv-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "privileged": True,
                "memory": 256,
            }
        ],
    )
    result = check_privileged_task(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-001"]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert "priv-task" in findings[0].title


def test_privileged_task_pass(mock_aws_provider: AWSProvider) -> None:
    """Task definition without privileged - no finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="safe-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "privileged": False,
                "memory": 256,
            }
        ],
    )
    result = check_privileged_task(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-001"]
    assert len(findings) == 0


def test_task_logging_fail(mock_aws_provider: AWSProvider) -> None:
    """Task definition without logging - HIGH finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="nolog-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "memory": 256,
            }
        ],
    )
    result = check_task_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-002"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_task_logging_pass(mock_aws_provider: AWSProvider) -> None:
    """Task definition with logging - no finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="logged-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "memory": 256,
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/logged-task",
                        "awslogs-region": "eu-central-1",
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
    )
    result = check_task_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-002"]
    assert len(findings) == 0


def test_ecs_exec_no_services(mock_aws_provider: AWSProvider) -> None:
    """No ECS services - no findings."""
    result = check_ecs_exec(mock_aws_provider)
    assert result.error is None
    assert len(result.findings) == 0


def test_ecs_exec_runs_without_error(mock_aws_provider: AWSProvider) -> None:
    """ECS exec check runs without error when services exist.

    MOTO LIMITATION: moto does not persist enableExecuteCommand on ECS services.
    Even when passed to create_service, describe_services returns it as False.
    Therefore this test only verifies the check runs cleanly without errors and
    scans at least one resource. It does NOT verify finding detection.
    The actual enableExecuteCommand detection logic is tested below via
    test_ecs_exec_fail_mocked which patches describe_services directly.
    """
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.create_cluster(clusterName="test-cluster")
    ecs.register_task_definition(
        family="exec-task",
        containerDefinitions=[{"name": "app", "image": "nginx:latest", "memory": 256}],
    )
    ecs.create_service(
        cluster="test-cluster",
        serviceName="exec-svc",
        taskDefinition="exec-task",
        desiredCount=1,
    )
    result = check_ecs_exec(mock_aws_provider)
    assert result.error is None
    assert result.resources_scanned >= 1


def test_ecs_exec_fail_mocked(mock_aws_provider: AWSProvider) -> None:
    """ECS service with enableExecuteCommand=True - MEDIUM finding.

    moto does not persist enableExecuteCommand, so we create the cluster/service
    via moto (for list_clusters / list_services) then wrap the session.client
    to return a client whose describe_services injects enableExecuteCommand=True.
    """
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.create_cluster(clusterName="exec-cluster")
    ecs.register_task_definition(
        family="exec-task",
        containerDefinitions=[{"name": "app", "image": "nginx:latest", "memory": 256}],
    )
    ecs.create_service(
        cluster="exec-cluster",
        serviceName="exec-svc",
        taskDefinition="exec-task",
        desiredCount=1,
    )

    # Wrap session.client so the ECS client returned inside check_ecs_exec
    # has describe_services patched to inject enableExecuteCommand=True.
    original_client = mock_aws_provider.session.client

    def wrapped_client(*args, **kwargs):
        client = original_client(*args, **kwargs)
        service_name = args[0] if args else kwargs.get("service_name", "")
        if service_name == "ecs":
            real_describe = client.describe_services

            def patched_describe_services(**kw):
                response = real_describe(**kw)
                for svc in response.get("services", []):
                    svc["enableExecuteCommand"] = True
                return response

            client.describe_services = patched_describe_services
        return client

    with patch.object(mock_aws_provider.session, "client", side_effect=wrapped_client):
        result = check_ecs_exec(mock_aws_provider)

    findings = [f for f in result.findings if f.check_id == "aws-ecs-003"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "exec-svc" in findings[0].title
    assert "ECS Exec" in findings[0].title
