FROM python:3.12.11-slim

LABEL org.opencontainers.image.title="PhishShield" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin phishshield

COPY backend/app/ ./backend/app/
COPY backend/migrations/ ./backend/migrations/
COPY backend/alembic.ini ./backend/alembic.ini
COPY frontend/ ./frontend/
COPY docs/README.md docs/project-api.md docs/project-endpoint-setup.md ./docs/
COPY README.md LICENSE .env.example ./
COPY docker/entrypoint.py ./docker/entrypoint.py

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=6s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=5).close()"]
ENTRYPOINT ["python", "/app/docker/entrypoint.py"]
