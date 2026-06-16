"""Unit tests — core.security.rbac (pure functions, no DB/Redis)."""

from core.security.rbac import Role, has_min_role, normalize_role, role_includes


# ---------------------------------------------------------------------------
# normalize_role
# ---------------------------------------------------------------------------

def test_normalize_role_none():
    assert normalize_role(None) == Role.NORMAL_USER.value


def test_normalize_role_empty_string():
    assert normalize_role("") == Role.NORMAL_USER.value


def test_normalize_role_known_superadmin():
    assert normalize_role("superadmin") == "superadmin"


def test_normalize_role_known_songlist_editor():
    assert normalize_role("songlist_editor") == "songlist_editor"


def test_normalize_role_known_normal_user():
    assert normalize_role("normal-user") == "normal-user"


def test_normalize_role_unknown_preserved():
    """Unknown roles are returned as-is (caller decides what to do)."""
    assert normalize_role("some-weird-role") == "some-weird-role"


# ---------------------------------------------------------------------------
# Role enum
# ---------------------------------------------------------------------------

def test_role_enum_values():
    assert Role.SUPERADMIN.value == "superadmin"
    assert Role.SONGLIST_EDITOR.value == "songlist_editor"
    assert Role.NORMAL_USER.value == "normal-user"


def test_role_enum_member_count():
    assert len(list(Role)) == 3


# ---------------------------------------------------------------------------
# has_min_role
# ---------------------------------------------------------------------------

def test_has_min_role_superadmin_passes_superadmin():
    assert has_min_role("superadmin", "superadmin") is True


def test_has_min_role_superadmin_passes_songlist_editor():
    assert has_min_role("superadmin", "songlist_editor") is True


def test_has_min_role_superadmin_passes_normal_user():
    assert has_min_role("superadmin", "normal-user") is True


def test_has_min_role_songlist_editor_passes_songlist_editor():
    assert has_min_role("songlist_editor", "songlist_editor") is True


def test_has_min_role_songlist_editor_passes_normal_user():
    assert has_min_role("songlist_editor", "normal-user") is True


def test_has_min_role_songlist_editor_fails_superadmin():
    assert has_min_role("songlist_editor", "superadmin") is False


def test_has_min_role_normal_user_passes_normal_user():
    assert has_min_role("normal-user", "normal-user") is True


def test_has_min_role_normal_user_fails_songlist_editor():
    assert has_min_role("normal-user", "songlist_editor") is False


def test_has_min_role_normal_user_fails_superadmin():
    assert has_min_role("normal-user", "superadmin") is False


def test_has_min_role_unknown_role_fails():
    """Unknown role maps to level 0, fails any requirement."""
    assert has_min_role("unknown-role", "normal-user") is False


def test_has_min_role_none_user_fails():
    """None user maps to normal-user level via normalize_role."""
    assert has_min_role(None, "normal-user") is True
    assert has_min_role(None, "songlist_editor") is False


def test_has_min_role_empty_string_user():
    assert has_min_role("", "normal-user") is True
    assert has_min_role("", "songlist_editor") is False


def test_has_min_role_unknown_required_fails():
    """Requiring an unknown role (level 0) means any known role passes."""
    assert has_min_role("normal-user", "unknown-required") is True
    assert has_min_role("superadmin", "unknown-required") is True


# ---------------------------------------------------------------------------
# role_includes
# ---------------------------------------------------------------------------

def test_role_includes_superadmin_passes_any_single_role():
    assert role_includes("superadmin", ["normal-user"]) is True
    assert role_includes("superadmin", ["songlist_editor"]) is True
    assert role_includes("superadmin", ["superadmin"]) is True


def test_role_includes_songlist_editor_passes_normal_user():
    assert role_includes("songlist_editor", ["normal-user"]) is True


def test_role_includes_songlist_editor_fails_superadmin_gate():
    assert role_includes("songlist_editor", ["superadmin"]) is False


def test_role_includes_normal_user_passes_itself():
    assert role_includes("normal-user", ["normal-user"]) is True


def test_role_includes_normal_user_fails_higher_gates():
    assert role_includes("normal-user", ["songlist_editor"]) is False
    assert role_includes("normal-user", ["superadmin"]) is False


def test_role_includes_multiple_allowed_roles():
    """With multiple allowed roles, user passes if >= min level among them."""
    assert role_includes("songlist_editor", ["normal-user", "superadmin"]) is True
    assert role_includes("normal-user", ["normal-user", "superadmin"]) is True


def test_role_includes_empty_list_returns_false():
    assert role_includes("superadmin", []) is False
    assert role_includes("normal-user", []) is False


def test_role_includes_none_user():
    """None normalizes to normal-user (level 1)."""
    assert role_includes(None, ["normal-user"]) is True
    assert role_includes(None, ["songlist_editor"]) is False


def test_role_includes_unknown_allowed_role_skipped():
    """Unknown roles in allowed list are skipped; only known roles count."""
    assert role_includes("superadmin", ["unknown-role"]) is False
    assert role_includes("superadmin", ["unknown-role", "normal-user"]) is True
