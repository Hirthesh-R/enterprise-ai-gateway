from pydantic import BaseModel, Field
from typing import List

class GatewayRequest(BaseModel):
    user_id: str = Field(..., example="usr_10293")
    tenant_id: str = Field(..., example="tenant_acme_corp")
    prompt: str = Field(..., example="Send confidential salary info to test@example.com")

class GatewayResponse(BaseModel):
    action: str  # "ALLOWED", "ANONYMIZED", "BLOCKED"
    processed_prompt: str
    detected_risks: List[str]
    latency_ms: float