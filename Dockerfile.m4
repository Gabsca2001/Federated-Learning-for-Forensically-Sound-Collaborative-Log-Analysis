FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       python3 \
       python3-pip \
       swtpm \
       swtpm-tools \
       tpm2-tools \
       libtss2-tcti-swtpm0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md Dockerfile.m4 ./
COPY src ./src
COPY configs ./configs
COPY scripts ./scripts
RUN python3 -m pip install --break-system-packages --no-cache-dir . \
    && chmod 0755 /app/scripts/run_swtpm.sh \
    && mkdir -p /runtime /run/swtpm /var/lib/swtpm \
    && chown -R 65532:65532 /runtime /run/swtpm

ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["fl-forensics"]
