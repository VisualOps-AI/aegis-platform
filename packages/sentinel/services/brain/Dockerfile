FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2'); \
    AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')"

RUN useradd -m -u 1000 witness && chown -R witness:witness /app
USER witness

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
