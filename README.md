# Enterprise AI Gateway & Compliance Proxy

A high-performance, two-tier AI Security & Compliance Gateway designed to intercept incoming LLM requests, evaluate security risks, and enforce enterprise data privacy policies in real time.

## 🏗️ Architecture

This microservice uses a **Layered Architecture (Router-Service-Schema)** to ensure complete separation of concern between HTTP routers, machine learning models, and validation contracts.

```text
enterprise-ai-gateway/
├── app/
│   ├── api/          # HTTP Endpoints (FastAPI Routers)
│   ├── services/     # Triage & Guardrail Engines (Scikit-Learn, PyTorch, HF)
│   └── schemas/      # Data Contracts (Pydantic)
├── Dockerfile        # Container setup
└── main.py           # Application Entrypoint
```

### **Two-Tier Threat Mitigation System**
1. **Tier 1: Scikit-Learn Fast Triage Gatekeeper**
   - Uses `TfidfVectorizer` + `LogisticRegression` for sub-10ms evaluation.
   - Instantly blocks prompt injection and malicious payload attacks before invoking downstream deep learning models.
2. **Tier 2: PyTorch & Hugging Face NER Guardrail**
   - Powered by `dslim/bert-base-NER` running on PyTorch tensor math.
   - Automatically detects, tags, and anonymizes Personally Identifiable Information (PII) including names, organizations, and email patterns.

---

## 🚀 Getting Started

### **Option 1: Local Virtual Environment**

```bash
# Clone the repository
git clone [https://github.com/YOUR_GITHUB_USERNAME/enterprise-ai-gateway.git](https://github.com/YOUR_GITHUB_USERNAME/enterprise-ai-gateway.git)
cd enterprise-ai-gateway

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn app.main:app --reload
```

Access Swagger UI at `http://127.0.0.1:8000/docs`.

---

### **Option 2: Docker Container**

```bash
# Build Docker image
docker build -t enterprise-ai-gateway .

# Run container
docker run -p 8000:8000 enterprise-ai-gateway
```

---

## 📑 API Endpoints

### `POST /v1/proxy/chat`
Intercepts and sanitizes user prompts before forwarding to LLM backends.

**Request Body:**
```json
{
  "user_id": "usr_10293",
  "tenant_id": "tenant_acme_corp",
  "prompt": "Send confidential salary info of Alice Johnson to alice@acme.com"
}
```

**Response Body:**
```json
{
  "action": "ANONYMIZED",
  "processed_prompt": "Send confidential salary info of [REDACTED_PER] to [REDACTED_EMAIL]",
  "detected_risks": [
    "PII: Email Address",
    "PII: PER"
  ],
  "latency_ms": 142.3
}
```