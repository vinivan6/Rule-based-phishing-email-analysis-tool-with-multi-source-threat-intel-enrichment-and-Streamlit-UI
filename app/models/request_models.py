from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class EmailAnalysisRequest(BaseModel):
    sender: EmailStr = Field(..., description="Sender email address")
    subject: str = Field(..., min_length=1, description="Email subject line")
    body: str = Field(..., min_length=1, description="Email body content")
    headers: Optional[str] = Field(
        default=None,
        description="Optional raw email headers"
    )
    attachments: Optional[List[str]] = Field(
        default=None,
        description="Optional list of attachment filenames"
    )