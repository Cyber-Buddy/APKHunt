# Pin the multi-architecture Syft image used for the supply-chain evidence step.
FROM anchore/syft:v1.52.0 AS syft
FROM ghcr.io/trufflesecurity/trufflehog:3.95.9@sha256:59b244249d1a1aef4baa24fe73d3c931616264482580d806d77f6c74d26b3e42 AS trufflehog

FROM python:3.12-slim

# System deps: Java (for JADX/Apktool), WeasyPrint deps, and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    ca-certificates \
    wget \
    unzip \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Install JADX
ENV JADX_VERSION=1.5.1
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && rm /tmp/jadx.zip
ENV PATH="/opt/jadx/bin:${PATH}"

# Install Apktool
ENV APKTOOL_VERSION=2.10.0
RUN wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" -O /usr/local/bin/apktool.jar \
    && printf '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# The dependency dashboard consumes the CycloneDX document created by Syft.
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy app code
COPY . .

# Create runtime directories
RUN mkdir -p uploads decompiled_apks reports

# Non-root user for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5005

ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5005
ENV DEBUG_MODE=false
CMD ["gunicorn", "--bind", "0.0.0.0:5005", "--workers", "1", "--threads", "4", "--timeout", "600", "app:app"]
