# Build stage
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

# Copiar dependencias
COPY services/lib-shared-kernel /services/lib-shared-kernel
COPY services/CU-03/pyproject.toml services/CU-03/uv.lock ./

# Instalar dependencias
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Final stage
FROM python:3.12-slim-bookworm

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY services/CU-03/main.py /app/main.py
COPY services/CU-03/tests /app/tests
COPY services/lib-shared-kernel /services/lib-shared-kernel

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
