# syntax=docker/dockerfile:1.7
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 65532 backstreet \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin backstreet \
    && mkdir -p /app /data /run/backstreet \
    && chown -R 65532:65532 /app /data /run/backstreet

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --requirement requirements.txt
COPY --chown=65532:65532 server.py .

USER 65532:65532
ENTRYPOINT ["python", "/app/server.py"]
