"""Unit tests — core.security.log_permissions"""

import pytest
from fastapi import HTTPException

from core.security.log_permissions import can_access_system_logs, get_permitted_user_uuids


class TestCanAccessSystemLogs:
    def test_superadmin_can_access_system_logs(self):
        assert can_access_system_logs({"user_role": "superadmin"}) is True

    def test_songlist_editor_cannot_access_system_logs(self):
        assert can_access_system_logs({"user_role": "songlist_editor"}) is False

    def test_normal_user_cannot_access_system_logs(self):
        assert can_access_system_logs({"user_role": "normal-user"}) is False

    def test_unknown_role_cannot_access_system_logs(self):
        assert can_access_system_logs({"user_role": "hacker"}) is False


class TestGetPermittedUserUuids:
    def test_normal_user_can_only_query_self(self):
        uuids = get_permitted_user_uuids(
            {"uuid": "user-1", "user_role": "normal-user"},
            requested_user_uuid=None,
        )
        assert uuids == ["user-1"]

    def test_normal_user_cannot_query_others(self):
        with pytest.raises(HTTPException) as exc_info:
            get_permitted_user_uuids(
                {"uuid": "user-1", "user_role": "normal-user"},
                requested_user_uuid="user-2",
            )
        assert exc_info.value.status_code == 403

    def test_songlist_editor_can_only_query_self(self):
        uuids = get_permitted_user_uuids(
            {"uuid": "editor-1", "user_role": "songlist_editor"},
            requested_user_uuid=None,
        )
        assert uuids == ["editor-1"]

    def test_superadmin_can_query_all(self):
        uuids = get_permitted_user_uuids(
            {"uuid": "admin-1", "user_role": "superadmin"},
            requested_user_uuid=None,
        )
        assert uuids is None

    def test_superadmin_can_query_specific_user(self):
        uuids = get_permitted_user_uuids(
            {"uuid": "admin-1", "user_role": "superadmin"},
            requested_user_uuid="user-2",
        )
        assert uuids == ["user-2"]

    def test_missing_self_uuid_raises_403(self):
        with pytest.raises(HTTPException) as exc_info:
            get_permitted_user_uuids(
                {"uuid": None, "user_role": "normal-user"},
                requested_user_uuid=None,
            )
        assert exc_info.value.status_code == 403
