# QuantumTrace: scanner + CycloneDX CBOM + web dashboard, with tshark for PCAP files, in one image.
#
#   docker build -t quantumtrace .
#   docker run --rm -p 8501:8501 -v "$PWD/../JunctionX-QuantumTrace:/data:ro" quantumtrace        # dashboard
#   docker run --rm -v "$PWD/../JunctionX-QuantumTrace:/data:ro" quantumtrace scan /data            # CLI
#   docker run --rm -v "$PWD/../JunctionX-QuantumTrace:/data:ro" quantumtrace benchmark             # accuracy
#
# Or simply ./demo.sh, which runs all three.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    QT_SUITE=/app/tests/benchmarks \
    QT_KIT=/data

# tshark decodes PCAP files (TLS / SSH handshakes). Only reading files: no capture rights needed.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY quantumtrace/ quantumtrace/
RUN pip install ".[dashboard]"
# the labelled benchmark datasets (`quantumtrace benchmark`) and the sample infrastructure
COPY tests/ tests/
# readable by the non-root user whatever permissions the files had on the build machine (e.g. 600)
RUN chmod -R a+rX /app

# never run as root; uid 1000 = the usual first Linux user, so files written to a mounted folder are yours
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin quantumtrace
USER quantumtrace

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)" || exit 1

ENTRYPOINT ["quantumtrace"]
CMD ["dashboard", "/data", "--headless", "--port", "8501"]
