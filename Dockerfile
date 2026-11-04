# ── Stage 1: Node build ───────────────────────────────────────────────────────
FROM node:lts-slim AS node-builder

WORKDIR /build

COPY package*.json ./
COPY tailwind.config.* ./
COPY postcss.config.* ./
COPY assets/ ./assets/
COPY app/ ./app/

RUN npm install
RUN npm run build

# ── Stage 2: Python deps ──────────────────────────────────────────────────────
FROM python:3.13-slim AS python-builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /install /usr/local
# Only the application code (no tests, docs or local state), then the built CSS.
COPY app/ ./app/
COPY --from=node-builder /build/app/static/css/tailwind.css ./app/static/css/tailwind.css

# Unprivileged user (fixed UID so host-mounted log directories can be
# granted to it: chown 10001 <log dir>).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin issuer \
 && mkdir -p /tmp/issuer_frontend/logs /tmp/issuer_frontend/log_dev \
 && chown -R issuer:issuer /app /tmp/issuer_frontend

USER issuer

ENV FLASK_APP=app

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]