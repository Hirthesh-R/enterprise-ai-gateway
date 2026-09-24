import re
import torch
from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline


class PyTorchGuardrailService:

  def __init__(self):
    # Detect GPU acceleration if available, otherwise default to CPU
    self.device = 0 if torch.cuda.is_available() else -1

    # Load Hugging Face BERT NER Model backed by PyTorch
    model_name = "dslim/bert-base-NER"
    self.tokenizer = AutoTokenizer.from_pretrained(model_name)
    self.model = AutoModelForTokenClassification.from_pretrained(model_name)

    self.ner_pipeline = pipeline(
        "ner",
        model=self.model,
        tokenizer=self.tokenizer,
        aggregation_strategy="simple",
        device=self.device,
    )

  def anonymize_pii(self, text: str) -> tuple[str, list[str]]:
    detected_risks = []
    anonymized_text = text

    # 1. Fast Pattern Matching for Emails
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if re.search(email_pattern, anonymized_text):
      detected_risks.append("PII: Email Address")
      anonymized_text = re.sub(
          email_pattern, "[REDACTED_EMAIL]", anonymized_text
      )

    # 2. PyTorch + Hugging Face NER Inference for Person/Org Entities
    ner_results = self.ner_pipeline(text)
    for entity in ner_results:
      if entity["entity_group"] in ["PER", "ORG"] and entity["score"] > 0.85:
        risk_tag = f"PII: {entity['entity_group']}"
        if risk_tag not in detected_risks:
          detected_risks.append(risk_tag)
        anonymized_text = anonymized_text.replace(
            entity["word"], f"[REDACTED_{entity['entity_group']}]"
        )

    return anonymized_text, detected_risks