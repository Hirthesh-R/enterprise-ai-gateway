from fastapi import FastAPI
import torch
from app.api import gateway_router

app = FastAPI(
    title="Enterprise AI Gateway & Compliance Proxy",
    version="1.0.0",
    description="Layered AI Gateway Microservice using Scikit-Learn, PyTorch, and Hugging Face"
)

@app.on_event("startup")
def startup_event():
    print("Loading Machine Learning models...")
    gateway_router.init_services()
    print("Models loaded into memory successfully.")

app.include_router(gateway_router.router)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "gpu_available": torch.cuda.is_available()
    }