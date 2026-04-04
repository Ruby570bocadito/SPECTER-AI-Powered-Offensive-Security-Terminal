# SPECTER - AI-Powered Offensive Security Terminal
# Multi-stage build: Kali Linux base + Python app
# Ollama runs separately (host or separate container)

# ── Stage 1: Build dependencies ──────────────────────────────────────────
FROM kalilinux/kali-rolling AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    gcc g++ libffi-dev libssl-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/specter-venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev,ollama,export,workflows]"

COPY src/ src/
COPY tests/ tests/
COPY .github/ .github/
RUN pip install --no-cache-dir -e .

# ── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime pentesting tools (no build deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    nmap masscan rustscan \
    gobuster ffuf nikto nuclei httpx \
    dnsrecon subfinder amass \
    whois curl wget theharvester \
    sqlmap \
    crackmapexec impacket-scripts kerbrute \
    git jq net-tools iputils-ping traceroute dnsutils \
    exiftool binwalk \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/specter-venv /opt/specter-venv
ENV PATH="/opt/specter-venv/bin:$PATH"

# Create non-root user
RUN groupadd -r specter && useradd -r -g specter -d /home/specter -s /bin/bash specter \
    && mkdir -p /home/specter \
    && chown -R specter:specter /home/specter

WORKDIR /app

# Create working directories with proper ownership
RUN mkdir -p /app/sessions /app/plugins /app/output /app/logs \
    && chown -R specter:specter /app

# Copy application
COPY --from=builder /build/src/ /app/src/
COPY --from=builder /build/tests/ /app/tests/
COPY --from=builder /build/.github/ /app/.github/
COPY pyproject.toml /app/

# Runtime config
ENV SPECTER_OLLAMA_HOST=http://host.docker.internal:11434
ENV SPECTER_DATA_DIR=/app
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER specter

# Expose port for potential future web UI
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

ENTRYPOINT ["python", "-m", "specter.cli.main"]
CMD []
