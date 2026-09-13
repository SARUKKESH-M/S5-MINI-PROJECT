from fastapi import FastAPI
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
    from backend.app.core.config import settings
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
    from app.core.config import settings
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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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

app.include_router(health_router)
app.include_router(analyze_router)
app.include_router(history_router)
app.include_router(repository_router)
app.include_router(repository_analysis_router)
app.include_router(github_webhooks_router)
app.include_router(platform_router)
app.include_router(analytics_router)



@app.get("/")
def read_root():
    return {
        "status": "ok",
        "service": "CodeSentinel"
    }
