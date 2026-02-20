FROM python:3.12-slim

LABEL maintainer="Federico Boiero <fboiero@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/fboiero/AiSec"
LABEL org.opencontainers.image.description="Deep security analysis for autonomous AI agents"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[all]"

ENTRYPOINT ["aisec"]
CMD ["--help"]
