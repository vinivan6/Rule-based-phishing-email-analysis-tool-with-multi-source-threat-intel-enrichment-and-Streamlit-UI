from fastapi import APIRouter
from app.models.request_models import EmailAnalysisRequest
from app.models.response_models import EmailAnalysisResponse
from app.services.phishing_rules import analyze_email_rules

router = APIRouter()


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        attachments=request.attachments
    )

    return EmailAnalysisResponse(
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        indicators=indicators,
        recommended_action=recommended_action,
        llm_notes="LLM analysis is not connected yet. Current result is based on rule-based checks.",
        model_used="rule_based_v3"
    )