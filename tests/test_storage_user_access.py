"""Phase A3.4 Verification Test Suite: User & Access-Control Storage Engine.

Tests:
- lookup by user_id
- lookup by email
- lookup by google_sub
- normalized email lookup
- create authorized user
- duplicate email protection
- duplicate google_sub protection
- google_sub binding
- conflicting google_sub binding
- successful login timestamp update
- role update
- status update
- atomic role + status update
- disabled user remains stored
- user listing and counting
- root admin seed idempotency
"""

import os
import sys
import tempfile
import pytest

# Ensure backend and workspace root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage import (
    AnalysisStore,
    UserRecord,
    UserRole,
    UserStatus,
    normalize_email,
)


@pytest.fixture
def temp_store():
    """Fixture providing an isolated AnalysisStore with a temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    yield store

    # Cleanup temp file
    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 1. Email Normalization
# ---------------------------------------------------------------------------
def test_normalize_email():
    assert normalize_email("  Alice@Example.COM  ") == "alice@example.com"
    assert normalize_email("bob.smith+test@codesentinel.dev") == "bob.smith+test@codesentinel.dev"

    with pytest.raises(ValueError):
        normalize_email("")

    with pytest.raises(ValueError):
        normalize_email("notanemail")

    with pytest.raises(ValueError):
        normalize_email("@example.com")


# ---------------------------------------------------------------------------
# 2. User Creation & Pre-Authorization
# ---------------------------------------------------------------------------
def test_create_authorized_user(temp_store):
    user = temp_store.create_authorized_user(
        email="dev@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Jane Dev",
        created_by="usr_admin_root"
    )

    assert user is not None
    assert user.user_id.startswith("usr_")
    assert user.email == "dev@codesentinel.dev"
    assert user.full_name == "Jane Dev"
    assert user.role == UserRole.USER.value
    assert user.status == UserStatus.ACTIVE.value
    assert user.google_sub is None  # Unbound during pre-authorization
    assert user.created_by == "usr_admin_root"
    assert user.last_login is None
    assert user.is_active() is True
    assert user.is_admin() is False


def test_duplicate_email_protection(temp_store):
    temp_store.create_authorized_user(email="alice@company.com")

    # Second creation with identical email must raise ValueError
    with pytest.raises(ValueError) as excinfo:
        temp_store.create_authorized_user(email="Alice@Company.COM")
    assert "already exists" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. Lookups (user_id, email, google_sub)
# ---------------------------------------------------------------------------
def test_user_lookups(temp_store):
    created = temp_store.create_authorized_user(
        email="bob@corp.com",
        role=UserRole.ADMIN.value,
        full_name="Bob Admin"
    )

    # Lookup by user_id
    by_id = temp_store.get_user_by_id(created.user_id)
    assert by_id is not None
    assert by_id.user_id == created.user_id
    assert by_id.email == "bob@corp.com"
    assert by_id.is_admin() is True

    # Lookup by email (case-insensitive)
    by_email = temp_store.get_user_by_email("BOB@CORP.COM")
    assert by_email is not None
    assert by_email.user_id == created.user_id

    # Non-existent lookups
    assert temp_store.get_user_by_id("nonexistent_id") is None
    assert temp_store.get_user_by_email("unknown@corp.com") is None
    assert temp_store.get_user_by_google_sub("nonexistent_sub") is None


# ---------------------------------------------------------------------------
# 4. Google Identity Binding
# ---------------------------------------------------------------------------
def test_bind_google_identity(temp_store):
    user = temp_store.create_authorized_user(email="charlie@gmail.com")
    assert user.google_sub is None

    bound = temp_store.bind_google_identity(
        user_id=user.user_id,
        google_sub="goog_109283019283",
        full_name="Charlie RealName",
        profile_picture="https://lh3.googleusercontent.com/avatar.jpg"
    )

    assert bound.google_sub == "goog_109283019283"
    assert bound.full_name == "Charlie RealName"
    assert bound.profile_picture == "https://lh3.googleusercontent.com/avatar.jpg"
    assert bound.role == UserRole.USER.value
    assert bound.status == UserStatus.ACTIVE.value

    # Fast indexed lookup by google_sub
    by_sub = temp_store.get_user_by_google_sub("goog_109283019283")
    assert by_sub is not None
    assert by_sub.user_id == user.user_id


def test_conflicting_google_sub_protection(temp_store):
    user1 = temp_store.create_authorized_user(email="user1@corp.com")
    user2 = temp_store.create_authorized_user(email="user2@corp.com")

    # Bind google_sub to user1
    temp_store.bind_google_identity(user1.user_id, "sub_shared_123")

    # Binding identical google_sub to user2 must raise ValueError
    with pytest.raises(ValueError) as excinfo:
        temp_store.bind_google_identity(user2.user_id, "sub_shared_123")
    assert "already linked to another account" in str(excinfo.value)

    # Attempting to re-bind user1 to a different google_sub must raise ValueError
    with pytest.raises(ValueError) as excinfo2:
        temp_store.bind_google_identity(user1.user_id, "sub_different_456")
    assert "already bound to a different Google identity" in str(excinfo2.value)


# ---------------------------------------------------------------------------
# 5. Successful Login Updates
# ---------------------------------------------------------------------------
def test_record_successful_login(temp_store):
    user = temp_store.create_authorized_user(email="dave@corp.com")
    assert user.last_login is None

    updated = temp_store.record_successful_login(user.user_id, "2026-09-17T20:00:00+00:00")
    assert updated is not None
    assert updated.last_login == "2026-09-17T20:00:00+00:00"
    assert updated.role == UserRole.USER.value
    assert updated.status == UserStatus.ACTIVE.value
    assert updated.created_at == user.created_at
    assert updated.created_by == user.created_by


# ---------------------------------------------------------------------------
# 6. Role and Status Mutations
# ---------------------------------------------------------------------------
def test_role_and_status_mutations(temp_store):
    user = temp_store.create_authorized_user(email="eve@corp.com")
    assert user.role == UserRole.USER.value
    assert user.status == UserStatus.ACTIVE.value

    # Update role to ADMIN
    promoted = temp_store.update_user_role(user.user_id, UserRole.ADMIN.value)
    assert promoted.role == UserRole.ADMIN.value
    assert promoted.is_admin() is True

    # Update status to DISABLED
    disabled = temp_store.update_user_status(user.user_id, UserStatus.DISABLED.value)
    assert disabled.status == UserStatus.DISABLED.value
    assert disabled.is_active() is False

    # Disabled user remains stored accurately
    retrieved = temp_store.get_user_by_id(user.user_id)
    assert retrieved is not None
    assert retrieved.status == UserStatus.DISABLED.value

    # Atomic update of both role and status
    reaffirmed = temp_store.update_user_role_and_status(
        user.user_id,
        UserRole.USER.value,
        UserStatus.ACTIVE.value
    )
    assert reaffirmed.role == UserRole.USER.value
    assert reaffirmed.status == UserStatus.ACTIVE.value
    assert reaffirmed.is_active() is True


def test_invalid_role_status_rejection(temp_store):
    user = temp_store.create_authorized_user(email="frank@corp.com")

    with pytest.raises(ValueError):
        temp_store.update_user_role(user.user_id, "SUPERUSER")

    with pytest.raises(ValueError):
        temp_store.update_user_status(user.user_id, "DELETED")


# ---------------------------------------------------------------------------
# 7. Listing and Counting
# ---------------------------------------------------------------------------
def test_list_and_count_users(temp_store):
    assert temp_store.count_users() == 0

    temp_store.create_authorized_user(email="u1@test.com", role=UserRole.ADMIN.value)
    temp_store.create_authorized_user(email="u2@test.com", role=UserRole.USER.value)
    u3 = temp_store.create_authorized_user(email="u3@test.com", role=UserRole.USER.value)
    temp_store.update_user_status(u3.user_id, UserStatus.DISABLED.value)

    assert temp_store.count_users() == 3
    assert temp_store.count_users(role=UserRole.ADMIN.value) == 1
    assert temp_store.count_users(role=UserRole.USER.value) == 2
    assert temp_store.count_users(status=UserStatus.DISABLED.value) == 1
    assert temp_store.count_users(status=UserStatus.ACTIVE.value) == 2

    # Listing with pagination and filter
    all_users = temp_store.list_users(limit=10)
    assert len(all_users) == 3

    admin_users = temp_store.list_users(role=UserRole.ADMIN.value)
    assert len(admin_users) == 1
    assert admin_users[0].email == "u1@test.com"

    disabled_users = temp_store.list_users(status=UserStatus.DISABLED.value)
    assert len(disabled_users) == 1
    assert disabled_users[0].email == "u3@test.com"


# ---------------------------------------------------------------------------
# 8. Root Admin Seeding Idempotency
# ---------------------------------------------------------------------------
def test_seed_initial_admin_idempotency(temp_store):
    # Empty email safely skips
    assert temp_store.seed_initial_admin(None) is None
    assert temp_store.seed_initial_admin("") is None

    # First seed creates the root admin
    admin = temp_store.seed_initial_admin("Admin@CodeSentinel.DEV", "Platform Administrator")
    assert admin is not None
    assert admin.email == "admin@codesentinel.dev"
    assert admin.role == UserRole.ADMIN.value
    assert admin.status == UserStatus.ACTIVE.value
    assert admin.created_by == "SYSTEM_SEED"
    assert admin.google_sub is None

    # Bind google identity to the seeded admin
    temp_store.bind_google_identity(admin.user_id, "goog_admin_sub_999", profile_picture="https://lh3.google/pic.png")
    temp_store.record_successful_login(admin.user_id, "2026-09-17T20:30:00+00:00")

    # Second seed on startup: MUST preserve google_sub, profile picture, and last_login!
    re_seeded = temp_store.seed_initial_admin("admin@codesentinel.dev")
    assert re_seeded is not None
    assert re_seeded.user_id == admin.user_id
    assert re_seeded.google_sub == "goog_admin_sub_999"
    assert re_seeded.profile_picture == "https://lh3.google/pic.png"
    assert re_seeded.last_login == "2026-09-17T20:30:00+00:00"
    assert re_seeded.role == UserRole.ADMIN.value
    assert re_seeded.status == UserStatus.ACTIVE.value
