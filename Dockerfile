# Meridian Cloud Alert Triage — FastAPI service (api/main.py)
# Azure Search, Azure OpenAI, and Cosmos DB credentials are injected at
# runtime via env vars (`docker run --env-file .env ...`), never baked in.

# Lightweight Linux os
FROM python:3.12-slim

# Working Directory
WORKDIR /app

# Skip writing .pyc files and enable unbuffered output for logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    # Enable unbuffered output for logging
    PYTHONUNBUFFERED=1 \
    # Disable pip cache to reduce image size
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the application code into the container
COPY api ./api
COPY agents ./agents
COPY graph ./graph
COPY data ./data

# Expose the port that the FastAPI application will run on
EXPOSE 8000

# Healthcheck to ensure the FastAPI service is running and responsive every 30 seconds, with a 5-second timeout and a 10-second start period.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start the FastAPI application using Uvicorn, binding to all network interfaces on port 8000.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
