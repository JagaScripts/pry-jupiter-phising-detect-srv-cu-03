# Build stage
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=services/CU-03/pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=services/CU-03/uv.lock,target=uv.lock \
    --mount=type=bind,source=services/lib-shared-kernel,target=/services/lib-shared-kernel \
    uv sync --frozen --no-install-project --no-dev

# Final stage
FROM python:3.12-slim-bookworm

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY services/CU-03/app /app/app
COPY services/lib-shared-kernel /services/lib-shared-kernel

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"

EXPOSE 8002
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
