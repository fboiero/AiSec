# ============================================================
# Stage 1: Builder — install dependencies
# ============================================================
FROM python:3.14-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install ".[all]"

# ============================================================
# Stage 2: Runtime — minimal production image
# ============================================================
FROM python:3.14-slim

LABEL maintainer="Federico Boiero <fboiero@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/fboiero/AiSec"
LABEL org.opencontainers.image.description="Deep security analysis for autonomous AI agents"
LABEL org.opencontainers.image.version="1.9.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 aisec \
    && useradd --uid 1000 --gid aisec --shell /bin/false --create-home aisec

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=aisec:aisec pyproject.toml README.md LICENSE ./
COPY --chown=aisec:aisec src/ src/

RUN pip install --no-cache-dir --no-deps -e .

# Create data directories
RUN mkdir -p /data /reports /home/aisec/.aisec && \
    chown -R aisec:aisec /data /reports /home/aisec

USER aisec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

ENTRYPOINT ["aisec"]
CMD ["--help"]
