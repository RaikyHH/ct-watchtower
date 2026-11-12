# syntax=docker/dockerfile:1
# Multi-stage, a lean non-root runtime image (§13.1).

FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/
# `pip install .` resolves the dependencies out of pyproject; the package itself
# is thrown out again afterwards - in the runtime image the source lies under
# /app/src, so that `REPO_ROOT` (config.py) and `RULES_DIR` (rules/loader.py)
# resolve just as they do in development.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install . gunicorn \
 && /opt/venv/bin/pip uninstall -y ct-watchtower

FROM python:3.12-slim
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_PATH=/data/ctwatchtower.sqlite3 \
    HOME=/tmp
RUN useradd -r -u 10001 -s /usr/sbin/nologin watchtower \
 && mkdir -p /data && chown watchtower:watchtower /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=watchtower:watchtower src/ ./src/
COPY --chown=watchtower:watchtower data/ ./data/
COPY --chown=watchtower:watchtower rules/ ./rules/
# A second, immutable copy: in compose, `rules/` is covered by a volume. Without
# this copy, new shared building blocks would never reach an existing
# installation - they would stay hidden behind the volume.
COPY --chown=watchtower:watchtower rules/ ./rules-shipped/
COPY --chown=watchtower:watchtower config/ ./config/
# The tools needed in operation: the backup runs as a service of its own, the
# rescoring is set off by hand after rule changes, and the CA watch runs as a
# service of its own against the full stream.
COPY --chown=watchtower:watchtower scripts/backup.py scripts/rescore.py scripts/ca_watch.py ./scripts/
USER watchtower
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=4).read()" || exit 1

# -w 1: the pipeline thread (ingest plus scorer) may run exactly once.
# gthread: the SSE endpoint holds a thread open per connection.
# --timeout 0: no worker watchdog - long-lived streams are the normal case here.
CMD ["gunicorn", "--workers", "1", "--worker-class", "gthread", "--threads", "24", \
     "--bind", "0.0.0.0:8000", "--timeout", "0", "--graceful-timeout", "10", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "ctwatchtower.app:create_app()"]
