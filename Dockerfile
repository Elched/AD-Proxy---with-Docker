# ==============================================================================
# Active Directory Secure LDAPS Proxy - Enterprise Production Dockerfile
# Compliant with official Docker Best Practices & CIS Docker Benchmark
# Base: Debian Bookworm slim (minimal attack surface, official Python runtime)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder - Dependency compilation & wheel resolution
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

# Prevent Python bytecode & buffering
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build prerequisites for C-extensions (if needed by cryptography/yaml)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and build virtual environment
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 2: Final Runtime Image (Hardened, Non-Root, Minimal Attack Surface)
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runner

LABEL org.opencontainers.image.title="Active Directory Secure LDAPS Proxy" \
      org.opencontainers.image.description="Enterprise Zero-Trust LDAPS Proxy for AI Agents and Service Accounts" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Enterprise Security Operations"

# Optimize Python execution in container
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    CONFIG_PATH="/app/ad_proxy/config.yaml"

WORKDIR /app

# Install only minimal runtime dependencies & security updates
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system group and user (UID/GID 10001, no shell, no home dir)
RUN groupadd -g 10001 -r adproxy && \
    useradd -u 10001 -r -g adproxy -s /sbin/nologin -M -d /app adproxy

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application source code and default configurations
COPY --chown=adproxy:adproxy ad_proxy /app/ad_proxy
COPY --chown=adproxy:adproxy certs /app/certs
COPY --chown=adproxy:adproxy tests /app/tests

# Create logs directory with proper ownership for non-root execution
RUN mkdir -p /app/logs && \
    chown -R adproxy:adproxy /app && \
    chmod 750 /app/logs && \
    chmod 700 /app/certs

# Switch to unprivileged user (Never run as root)
USER 10001:10001

# Expose Secure LDAPS REST Gateway port (Default: 10636)
EXPOSE 10636

# Healthcheck testing the /health endpoint over TLS
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request, ssl; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; res = urllib.request.urlopen('https://127.0.0.1:10636/health', context=ctx, timeout=3); exit(0 if res.status == 200 else 1)" || exit 1

# Default execution: run the secure LDAPS proxy server with TLS enabled
ENTRYPOINT ["python3", "-m", "ad_proxy.cli"]
CMD ["--run", "--tls", "--config", "/app/ad_proxy/config.yaml"]
