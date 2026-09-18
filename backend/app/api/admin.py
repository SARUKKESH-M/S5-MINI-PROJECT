"""FastAPI Router for CodeSentinel Admin Access Management APIs.

Authoritative endpoints for managing authorized users:
- GET    /admin/users              - Paginated list of authorized users.
- POST   /admin/users              - Pre-authorize a Google account by email.
- GET    /admin/users/{user_id}     - Retrieve details for a specific user.
- PATCH  /admin/users/{user_id}/status - Activate or disable a user account.
- PATCH  /admin/users/{user_id}/role   - Change role (USER / ADMIN).
- DELETE /admin/users/{user_id}     - Revoke access and remove user record.

All endpoints strictly enforce ADMIN authorization via require_admin_user().
Enforces self-protection and last-admin preservation invariants.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

try:
    from backend.analysis.storage.models import (
        UserAdminDetailResponse,
        UserListResponse,
        UserPreAuthorizeRequest,
        UserRecord,
        UserRole,
        UserRoleUpdateRequest,
        UserStatus,
        UserStatusUpdateRequest,
        normalize_email,
    )
    from backend.analysis.storage.store import AnalysisStore
    from backend.app.core.auth import get_store, require_admin_user
except ImportError:
    from analysis.storage.models import (
        UserAdminDetailResponse,
        UserListResponse,
        UserPreAuthorizeRequest,
        UserRecord,
        UserRole,
        UserRoleUpdateRequest,
        UserStatus,
        UserStatusUpdateRequest,
        normalize_email,
    )
    from analysis.storage.store import AnalysisStore
    from app.core.auth import get_store, require_admin_user

router = APIRouter(prefix="/admin", tags=["Admin Access Management"])


def user_to_admin_detail(user: UserRecord) -> UserAdminDetailResponse:
    """Convert internal UserRecord to safe administrative representation.
    
    Excludes session tokens, secret keys, or passwords.
    """
    return UserAdminDetailResponse(
        user_id=user.user_id,
        google_sub=user.google_sub,
        email=user.email,
        full_name=user.full_name,
        profile_picture=user.profile_picture,
        role=user.role,
        status=user.status,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
        created_by=user.created_by,
    )


@router.get("/users", response_model=UserListResponse)
def list_authorized_users(
    limit: int = Query(50, ge=1, le=200, description="Max records to retrieve"),
    offset: int = Query(0, ge=0, description="Records offset for pagination"),
    role: Optional[str] = Query(None, description="Filter by role: ADMIN or USER"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: ACTIVE or DISABLED"),
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Retrieve a paginated listing of authorized users.
    
    Permission: ADMIN only.
    """
    store = get_store()
    users = store.list_users(limit=limit, offset=offset, role=role, status=status_filter)
    total_count = store.count_users(role=role, status=status_filter)

    return UserListResponse(
        users=[user_to_admin_detail(u) for u in users],
        total_count=total_count,
    )


@router.post("/users", response_model=UserAdminDetailResponse, status_code=status.HTTP_201_CREATED)
def pre_authorize_user(
    req: UserPreAuthorizeRequest,
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Pre-authorize a new Google account by email address.
    
    Lifecycle:
    1. Normalize email.
    2. Check duplicate (HTTP 409 Conflict).
    3. Create authorized record with google_sub=None, role=req.role, status=ACTIVE.
    4. created_by recorded from currently authenticated administrator.
    
    Permission: ADMIN only.
    """
    try:
        clean_email = normalize_email(req.email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    store = get_store()
    existing = store.get_user_by_email(clean_email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{clean_email}' is already authorized.",
        )

    try:
        new_user = store.create_authorized_user(
            email=clean_email,
            role=req.role,
            full_name=req.full_name,
            created_by=current_admin.email,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    return user_to_admin_detail(new_user)


@router.get("/users/{user_id}", response_model=UserAdminDetailResponse)
def get_user_detail(
    user_id: str,
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Retrieve detailed administrative view for a specific user.
    
    Permission: ADMIN only.
    """
    store = get_store()
    user = store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )
    return user_to_admin_detail(user)


@router.patch("/users/{user_id}/status", response_model=UserAdminDetailResponse)
def update_user_status(
    user_id: str,
    req: UserStatusUpdateRequest,
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Activate or disable a user account.
    
    Invariants:
    1. Administrator cannot disable their own account.
    2. System cannot disable the last active administrator.
    3. Disabling an account immediately revokes all active server-side sessions.
    
    Permission: ADMIN only.
    """
    store = get_store()
    target = store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )

    clean_status = req.status.strip().upper()

    # Self-protection invariant
    if target.user_id == current_admin.user_id and clean_status == UserStatus.DISABLED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot disable their own account.",
        )

    # Last active admin protection invariant
    if target.is_admin() and target.is_active() and clean_status == UserStatus.DISABLED.value:
        active_admin_count = store.count_users(role=UserRole.ADMIN.value, status=UserStatus.ACTIVE.value)
        if active_admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable the last active administrator.",
            )

    updated = store.update_user_status(user_id=target.user_id, status=clean_status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user status.",
        )

    return user_to_admin_detail(updated)


@router.patch("/users/{user_id}/role", response_model=UserAdminDetailResponse)
def update_user_role(
    user_id: str,
    req: UserRoleUpdateRequest,
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Change a user's role (ADMIN or USER).
    
    Invariants:
    1. Administrator cannot demote their own account from ADMIN to USER.
    2. System cannot demote the last active administrator.
    
    Permission: ADMIN only.
    """
    store = get_store()
    target = store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )

    clean_role = req.role.strip().upper()

    # Self-protection invariant
    if target.user_id == current_admin.user_id and clean_role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot demote their own role.",
        )

    # Last active admin protection invariant
    if target.is_admin() and target.is_active() and clean_role != UserRole.ADMIN.value:
        active_admin_count = store.count_users(role=UserRole.ADMIN.value, status=UserStatus.ACTIVE.value)
        if active_admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last active administrator.",
            )

    updated = store.update_user_role(user_id=target.user_id, role=clean_role)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user role.",
        )

    return user_to_admin_detail(updated)


@router.delete("/users/{user_id}")
def revoke_user_access(
    user_id: str,
    current_admin: UserRecord = Depends(require_admin_user),
):
    """Revoke user authorization and remove user record.
    
    Invariants:
    1. Administrator cannot remove their own account.
    2. System cannot remove the last active administrator.
    3. Immediately revokes all active sessions.
    4. Underlying analysis history and security findings remain completely intact.
    
    Permission: ADMIN only.
    """
    store = get_store()
    target = store.get_user_by_id(user_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )

    # Self-protection invariant
    if target.user_id == current_admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot revoke their own account.",
        )

    # Last active admin protection invariant
    if target.is_admin() and target.is_active():
        active_admin_count = store.count_users(role=UserRole.ADMIN.value, status=UserStatus.ACTIVE.value)
        if active_admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot revoke the last active administrator.",
            )

    # Revoke sessions first
    store.revoke_user_sessions(target.user_id)

    # Delete user record (cascades to user_sessions)
    success = store.delete_user(target.user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove user record.",
        )

    return {
        "status": "success",
        "message": f"User '{target.email}' ({target.user_id}) authorization revoked and record removed.",
    }
