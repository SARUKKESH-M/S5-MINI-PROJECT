from fastapi import FastAPI
from app.api.health import router as health_router
from app.api.analyze import router as analyze_router
from app.api.history import router as history_router
from app.api.repository import router as repository_router
from app.api.repository_analysis import router as repository_analysis_router
from app.api.github_webhooks import router as github_webhooks_router
from app.core.config import settings

app = FastAPI(
    title="CodeSentinel API",
    description=f"CodeSentinel DevSecOps Backend ({settings.APP_ENV})"
)

app.include_router(health_router)
app.include_router(analyze_router)
app.include_router(history_router)
app.include_router(repository_router)
app.include_router(repository_analysis_router)
app.include_router(github_webhooks_router)



@app.get("/")
def read_root():
    return {
        "status": "ok",
        "service": "CodeSentinel"
    }
