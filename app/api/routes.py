from fastapi import APIRouter
from app.models.request_models import EmailAnalysisRequest
from app.models.response_models import EmailAnalysisResponse
from app.services.artifact_extractor import build_artifacts
from app.services.phishing_rules import analyze_email_rules
from app.services.reputation_service import enrich_reputation, summarize_reputation
from app.services.semantic_classifier import classify_semantics
from app.services.decision_engine import decide_final_outcome

router = APIRouter()


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    print("STEP 1: start")
    
    verdict, confidence, reasons, indicators, recommended_action = analyze_email_rules(
        sender=request.sender,
        display_name=request.display_name,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        attachments=request.attachments
    )
    print("STEP 2: rules done")

    artifacts = build_artifacts(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        attachments=request.attachments
    )
    print("STEP 3: artifacts done")

    reputation = enrich_reputation(
        urls=artifacts.urls,
        domains=artifacts.domains,
        ip_addresses=artifacts.ip_addresses
    )
    print("STEP 4: reputation done")
    reputation_summary = summarize_reputation(reputation)

    semantic_result = classify_semantics(
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        indicators=indicators,
    )
    print("STEP 6: semantic done", semantic_result)

    decision = decide_final_outcome(
        rule_verdict=verdict,
        rule_confidence=confidence,
        reputation_overall=reputation_summary.overall,
        semantic_result=semantic_result,
    )
    print("STEP 7: decision done", decision)

    verdict = decision["final_verdict"]
    confidence = decision["final_confidence"]
    recommended_action = decision["final_action"]
    semantic_category = decision["semantic_category"]
    semantic_confidence = decision["semantic_confidence"]

    print("STEP 8: about to return response...")
    return EmailAnalysisResponse(
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        indicators=indicators,
        recommended_action=recommended_action,
        llm_notes="LLM analysis is not connected yet. Current result is based on rule-based checks plus semantic classification and threat-intelligence enrichment.",
        model_used="rule_based_v13_alignment",
        artifacts=artifacts,
        reputation=reputation,
        reputation_summary=reputation_summary,
        semantic_category=semantic_category,
        semantic_confidence=semantic_confidence,
    )