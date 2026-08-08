# Meridian Cloud Alert Triage — FastAPI service (api/main.py)
# Azure Search, Azure OpenAI, and Cosmos DB credentials are injected at
# runtime via env vars (`docker run --env-file .env ...`), never baked in.
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY api ./api
COPY agents ./agents
COPY graph ./graph
COPY data ./data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
