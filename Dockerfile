# CyberAsset Guard — local MVP image (Asset Management + Monitoring).
# nmap is installed so the Monitoring module can scan from inside the container.
# The container runs as a non-root user (uid 10001): the Monitoring scans use
# nmap's TCP connect scan (-sT), which needs no privileges. SYN/UDP/OS-detection
# scans would require the NET_RAW/NET_ADMIN capabilities, which are deliberately
# NOT granted here — the application never requests them.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# nmap (with its service/version fingerprint database) powers the Monitoring
# scans. --no-install-recommends keeps the image small; the apt lists are removed
# in the same layer so they are not baked into the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt constraints.txt ./
RUN pip install -r requirements.txt -c constraints.txt

COPY app ./app
COPY cli.py ./
# Alembic migrations: the app runs database.ensure_schema() at startup, which upgrades
# to head using BASE_DIR/alembic.ini and BASE_DIR/alembic. Both must be in the image.
COPY alembic.ini ./
COPY alembic ./alembic

# Unprivileged user; data and backups live on volumes outside the image.
RUN useradd --system --uid 10001 --no-create-home cag \
 && mkdir -p /data /backups \
 && chown cag /data /backups
USER cag

ENV CAG_DB_PATH=/data/cyberasset_guard.db \
    CAG_BACKUP_DIR=/backups \
    CAG_LOG_LEVEL=INFO

VOLUME ["/data", "/backups"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=4).status == 200 else 1)"

# No auto-reload in containers. Single worker: SQLite + in-process scheduler.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
