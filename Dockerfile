# SPECTER - AI-Powered Offensive Security Terminal
# Multi-stage build: Kali Linux base + Python app
# Ollama runs separately (host or separate container)

FROM kalilinux/kali-rolling AS base

# Avoid interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

# ── Install pentesting tools ───────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core Python
    python3 python3-pip python3-venv \
    # Recon
    nmap masscan rustscan \
    # Web
    gobuster ffuf nikto nuclei httpx wpscan whatweb \
    # DNS
    dnsrecon subfinder amass \
    # Info gathering
    whois curl wget theharvester \
    # Exploitation
    sqlmap hydra metasploit-framework \
    # AD
    crackmapexec impacket-scripts kerbrute \
    # Utils
    git jq net-tools iputils-ping traceroute dnsutils \
    # Forensics
    exiftool binwalk \
    # Build deps
    gcc g++ libffi-dev libssl-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Python virtual environment ─────────────────────────────────────────
ENV VIRTUAL_ENV=/opt/specter-venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# ── Install SPECTER ────────────────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev,ollama,export,workflows]"

COPY src/ src/
COPY tests/ tests/
COPY .github/ .github/

# Install the package itself
RUN pip install --no-cache-dir -e .

# ── Create working directories ─────────────────────────────────────────
RUN mkdir -p /app/sessions /app/plugins /app/output

# ── Runtime config ─────────────────────────────────────────────────────
ENV SPECTER_OLLAMA_HOST=http://host.docker.internal:11434
ENV SPECTER_DATA_DIR=/app
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Expose port for potential future web UI
EXPOSE 8000

ENTRYPOINT ["python", "-m", "specter.cli.main"]
CMD []
