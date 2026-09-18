from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

try:
    from backend.app.api.health import router as health_router
    from backend.app.api.analyze import router as analyze_router
    from backend.app.api.history import router as history_router
    from backend.app.api.repository import router as repository_router
    from backend.app.api.repository_analysis import router as repository_analysis_router
    from backend.app.api.github_webhooks import router as github_webhooks_router
    from backend.app.api.platform import router as platform_router
    from backend.app.api.analytics import router as analytics_router
    from backend.app.api.auth import router as auth_router
    from backend.app.api.admin import router as admin_router
    from backend.analysis.storage.store import AnalysisStore
    from backend.app.core.config import settings
    from backend.app.core.auth import require_active_user, require_admin_user
    from backend.app.core.security import (
        RequestSizeLimitMiddleware,
        SecurityHeadersMiddleware,
        global_exception_handler
    )
except ImportError:
    from app.api.health import router as health_router
    from app.api.analyze import router as analyze_router
    from app.api.history import router as history_router
    from app.api.repository import router as repository_router
    from app.api.repository_analysis import router as repository_analysis_router
    from app.api.github_webhooks import router as github_webhooks_router
    from app.api.platform import router as platform_router
    from app.api.analytics import router as analytics_router
    from app.api.auth import router as auth_router
    from app.api.admin import router as admin_router
    from analysis.storage.store import AnalysisStore
    from app.core.config import settings
    from app.core.auth import require_active_user, require_admin_user
    from app.core.security import (
        RequestSizeLimitMiddleware,
        SecurityHeadersMiddleware,
        global_exception_handler
    )

app = FastAPI(
    title="CodeSentinel API",
    description=f"CodeSentinel DevSecOps Backend ({settings.APP_ENV})"
)

# 1. Configure Hardened CORS Origins
raw_origins = getattr(settings, "ALLOWED_ORIGINS", "") or ""
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
if not allowed_origins:
    allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# 2. Add Request Payload Size Limit Middleware
app.add_middleware(RequestSizeLimitMiddleware)

# 3. Add HTTP Security Headers Middleware
if getattr(settings, "ENABLE_SECURITY_HEADERS", True):
    app.add_middleware(SecurityHeadersMiddleware)

# 4. Register Global Error Exception Handlers
app.add_exception_handler(Exception, global_exception_handler)
app.add_exception_handler(StarletteHTTPException, global_exception_handler)

# 5. Public / Infrastructure Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(platform_router)
app.include_router(github_webhooks_router)

# 6. Protected Application Routers (Phase A6 Session Gating)
app.include_router(analyze_router, dependencies=[Depends(require_active_user)])
app.include_router(history_router, dependencies=[Depends(require_active_user)])
app.include_router(repository_router, dependencies=[Depends(require_active_user)])
app.include_router(repository_analysis_router, dependencies=[Depends(require_active_user)])
app.include_router(analytics_router, dependencies=[Depends(require_active_user)])

# 7. Protected Admin Routers (Phase A7 Admin Boundary)
app.include_router(admin_router, dependencies=[Depends(require_admin_user)])


@app.on_event("startup")
def startup_event():
    """Execute startup database initialization and optional root administrator seeding."""
    store = AnalysisStore()
    store.initialize()
    admin_email = getattr(settings, "ADMIN_INITIAL_EMAIL", None)
    if admin_email and str(admin_email).strip():
        admin_name = getattr(settings, "ADMIN_INITIAL_NAME", "Root Administrator")
        store.seed_initial_admin(admin_email=admin_email, admin_name=admin_name)


@app.get("/")
def read_root():
    return {
        "status": "ok",
        "service": "CodeSentinel"
    }

