import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("witness-brain")

MODEL_NAME = os.getenv("MODEL_NAME", "protectai/deberta-v3-base-prompt-injection-v2")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
THRESHOLD = float(os.getenv("INJECTION_THRESHOLD", "0.5"))

model = None
tokenizer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, tokenizer
    logger.info(f"Loading model: {MODEL_NAME}")
    logger.info(f"Device: {DEVICE}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.to(DEVICE)
    model.eval()

    logger.info("Model loaded successfully")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="Witness Brain",
    description="ML-powered prompt injection detection",
    version="1.0.0",
    lifespan=lifespan
)


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeResponse(BaseModel):
    score: float
    is_threat: bool
    model: str
    threshold: float


@app.get("/health")
async def health():
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {"status": "healthy", "service": "witness-brain", "model": MODEL_NAME}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        inputs = tokenizer(
            request.text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        inputs = {k: v.to(DEVICE) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=-1)
            injection_score = probabilities[0][1].item()

        is_threat = injection_score >= THRESHOLD

        logger.info(f"Analysis complete: score={injection_score:.4f}, is_threat={is_threat}")

        return AnalyzeResponse(
            score=round(injection_score, 4),
            is_threat=is_threat,
            model=MODEL_NAME,
            threshold=THRESHOLD
        )

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
