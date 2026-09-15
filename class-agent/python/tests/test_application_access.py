"""Application sharing is an explicit UUID allowlist, independent of applicant claims."""

import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

import pytest
from test_course_resources import authenticated_principal, public_principal

from course_server.application_access import ApplicationAccessPolicy


@pytest.mark.parametrize("role", ["ta", "admin"])
def test_nonstudent_roles_cannot_use_shared_applications(role: Literal["ta", "admin"]) -> None:
    with pytest.raises(PermissionError):
        ApplicationAccessPolicy().scope(authenticated_principal(role))


def test_registry_fails_closed_and_revocation_is_immediate(tmp_path: Path) -> None:
    path = tmp_path / "access.json"
    policy = ApplicationAccessPolicy(path)
    student = authenticated_principal("student")
    instructor = authenticated_principal("instructor")
    accepted = uuid4()
    assert policy.scope(student) == frozenset()
    with pytest.raises(PermissionError):
        policy.require(student, accepted)
    with pytest.raises(PermissionError):
        policy.scope(public_principal())
    path.write_text(json.dumps({"schema_version": 1, "application_ids": [str(accepted)]}))
    policy.require(student, accepted)
    with pytest.raises(PermissionError):
        policy.require(student, uuid4())
    for malformed in [
        "invalid",
        "[]",
        '{"schema_version": 2, "application_ids": []}',
        '{"schema_version": 1, "application_ids": ["Ada Applicant"]}',
    ]:
        path.write_text(malformed)
        with pytest.raises(PermissionError):
            policy.require(student, accepted)
        assert policy.scope(instructor) is None
    path.unlink()
    with pytest.raises(PermissionError):
        policy.require(student, accepted)


def test_student_listing_never_enumerates_unshared_applications(tmp_path: Path) -> None:
    import asyncio
    from unittest.mock import AsyncMock

    from test_course_resources import execution_context

    from course_server.agent.capabilities import (
        ApplicantStore,
        InstructorListApplicationsTool,
        InstructorReadApplicationTool,
    )

    async def scenario() -> None:
        accepted, unshared = uuid4(), uuid4()
        path = tmp_path / "access.json"
        path.write_text(json.dumps({"schema_version": 1, "application_ids": [str(accepted)]}))
        store = AsyncMock(spec=ApplicantStore)
        # An unshared submission can claim the same name; its UUID still denies access.
        store.read_application.return_value = {
            "submitted_at": "2026-09-14T12:00:00Z",
            "application": {"name": "Same Name"},
        }
        access = ApplicationAccessPolicy(path)
        context = execution_context(principal=authenticated_principal("student"))
        result = await InstructorListApplicationsTool(store, access).execute({}, context)
        assert isinstance(result.content, list)
        assert len(result.content) == 1
        store.list_applications.assert_not_called()
        store.read_application.assert_awaited_once_with(accepted)
        with pytest.raises(PermissionError):
            await InstructorReadApplicationTool(store, access).execute(
                {"application_id": str(unshared)}, context
            )
        store.read_application.assert_awaited_once_with(accepted)

    asyncio.run(scenario())
