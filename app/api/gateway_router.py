import time
from fastapi import APIRouter
from app.schemas.gateway_schema import GatewayRequest, GatewayResponse
from app.services.gatekeeper_service import FastGatekeeperService
from app.services.guardrail_service import PyTorchGuardrailService

router = APIRouter(prefix="/v1/proxy", tags=["Proxy"])

# Global service references initialized on app startup
gatekeeper_service: FastGatekeeperService = None
guardrail_service: PyTorchGuardrailService = None

def init_services():
    global gatekeeper_service, guardrail_service
    print("Initializing Scikit-Learn Triage Gatekeeper...")
    gatekeeper_service = FastGatekeeperService()
    print("Initializing PyTorch & Hugging Face Guardrail Service...")
    guardrail_service = PyTorchGuardrailService()

@router.post("/chat", response_model=GatewayResponse)
async def process_chat_gateway(request: GatewayRequest):
    start_time = time.time()
    
    # Tier 1: Scikit-Learn Fast Triage
    risk_score = gatekeeper_service.predict_risk_score(request.prompt)
    
    if risk_score > 0.85:
        return GatewayResponse(
            action="BLOCKED",
            processed_prompt="Prompt blocked due to high prompt injection risk.",
            detected_risks=["Prompt Injection Attack"],
            latency_ms=round((time.time() - start_time) * 1000, 2)
        )

    # Tier 2: PyTorch + Hugging Face PII Inspection
    clean_prompt, detected_risks = guardrail_service.anonymize_pii(request.prompt)
    action = "ANONYMIZED" if detected_risks else "ALLOWED"

    return GatewayResponse(
        action=action,
        processed_prompt=clean_prompt,
        detected_risks=detected_risks,
        latency_ms=round((time.time() - start_time) * 1000, 2)
    )