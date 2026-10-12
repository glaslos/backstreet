# syntax=docker/dockerfile:1.7
FROM python:3.13-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd --gid 65532 backstreet \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin backstreet \
    && mkdir -p /app /data /run/backstreet \
    && chown -R 65532:65532 /app /data /run/backstreet

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-dev --no-install-project \
    && chown -R 65532:65532 /app/.venv

COPY --chown=65532:65532 worker/server.py .

USER 65532:65532
ENTRYPOINT ["python", "/app/server.py"]
