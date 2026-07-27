FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

WORKDIR /app

RUN python -m pip install --upgrade pip \
    && python -m pip install "poetry==2.4.1"

COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-root

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN groupadd --system --gid 10001 mycleanbot \
    && useradd --system --uid 10001 --gid mycleanbot --home-dir /app mycleanbot

COPY --from=builder /app/.venv /app/.venv
COPY pyproject.toml poetry.lock README.md ./
COPY config ./config
COPY core ./core
COPY templates ./templates
COPY static ./static
COPY manage.py ./

RUN python manage.py collectstatic --noinput \
    && chown -R mycleanbot:mycleanbot /app

USER 10001:10001

EXPOSE 8000

CMD ["gunicorn", "config.asgi:application", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-"]
