from fastapi import APIRouter
from app.models.request_models import EmailAnalysisRequest
from app.models.response_models import EmailAnalysisResponse

router = APIRouter()


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    return EmailAnalysisResponse(
        verdict="suspicious",
        confidence="medium",
        reasons=[
            "Placeholder analysis has not been implemented yet."
        ],
        indicators=[
            "analysis_pending"
        ],
        recommended_action="Review the email manually before taking any action.",
        llm_notes="LLM analysis is not connected yet.",
        model_used="not_connected"
    )