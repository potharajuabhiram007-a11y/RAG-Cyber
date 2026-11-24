# CyberIntelliX / RAG-Cyber backend (FastAPI) + website, as one container.
#
# Works on Render (Docker runtime), Hugging Face Spaces (Docker SDK) and any server.
# The database is not inside: point NEO4J_URI at Neo4j AuraDB, or use
# docker-compose.yml, which also starts Neo4j.
#
#   docker build -t cyberintellix .
#   docker run -p 8000:8000 --env-file .env cyberintellix
#
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # embedding model cache, baked into the image (see below)
    HF_HOME=/app/.hf-cache \
    # sentence-transformer model, run with ONNX Runtime (no PyTorch)
    EMBEDDING_PROVIDER=sentence-transformers \
    EMBEDDING_MODEL=BAAI/bge-small-en-v1.5 \
    EMBEDDING_RUNTIME=onnx \
    # the default port; Render and Hugging Face set PORT themselves
    PORT=8000

# Hugging Face Spaces runs containers as user 1000; use the same everywhere.
RUN useradd --create-home --uid 1000 app
WORKDIR /app

# Dependencies first, so code changes do not reinstall them.
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

# Download the embedding model at build time: a cold start then needs no download,
# and the container can run with HF_HUB_OFFLINE=1.
COPY backend/__init__.py backend/__init__.py
COPY backend/updater/__init__.py backend/updater/st_onnx.py backend/updater/
RUN python -c "from backend.updater.st_onnx import OnnxSentenceEncoder; \
OnnxSentenceEncoder('BAAI/bge-small-en-v1.5')"
ENV HF_HUB_OFFLINE=1

COPY backend backend
COPY frontend frontend
RUN mkdir -p backend/logs backend/data && chown -R app:app /app
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/api/status', timeout=8)"

# Shell form so ${PORT} is expanded; exec so uvicorn receives stop signals.
CMD exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips="*"
