from typing import List
from pydantic import BaseModel, Field


class EmailAnalysisResponse(BaseModel):
    verdict: str = Field(..., description="Overall phishing verdict")
    confidence: str = Field(..., description="Confidence level of the analysis")
    reasons: List[str] = Field(..., description="Why the email received this verdict")
    indicators: List[str] = Field(..., description="Detected phishing indicators")
    recommended_action: str = Field(..., description="Recommended next action")
    llm_notes: str = Field(..., description="Additional LLM reasoning notes")
    model_used: str = Field(..., description="Model used for analysis")