from typing import List
from pydantic import BaseModel, Field


class ExtractedArtifacts(BaseModel):
    urls: List[str] = Field(default_factory=list, description="Extracted URLs from the email")
    domains: List[str] = Field(default_factory=list, description="Extracted domains from sender, URLs, and headers")
    ip_addresses: List[str] = Field(default_factory=list, description="Extracted IP addresses from headers")
    attachments: List[str] = Field(default_factory=list, description="Attachment filenames found in the email")


class EmailAnalysisResponse(BaseModel):
    verdict: str = Field(..., description="Overall phishing verdict")
    confidence: str = Field(..., description="Confidence level of the analysis")
    reasons: List[str] = Field(..., description="Why the email received this verdict")
    indicators: List[str] = Field(..., description="Detected phishing indicators")
    recommended_action: str = Field(..., description="Recommended next action")
    llm_notes: str = Field(..., description="Additional LLM reasoning notes")
    model_used: str = Field(..., description="Model used for analysis")
    artifacts: ExtractedArtifacts = Field(..., description="Extracted artifacts from the email")