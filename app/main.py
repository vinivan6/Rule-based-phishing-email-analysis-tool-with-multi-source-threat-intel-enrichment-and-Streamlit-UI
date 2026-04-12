from fastapi import FastAPI
from app.api.routes import router
app = FastAPI(
    title="Phishing Email Analysis Agent",
    description="API for analyzing suspicious emails and returning a structured phishing assessment.",
    version="0.1.0"
)
app.include_router(router)
