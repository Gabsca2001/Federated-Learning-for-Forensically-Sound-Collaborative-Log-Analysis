# Phase-1 development image. The campaign renderer must resolve and record the
# registry digest before a formal experiment; this file does not invent one.
FROM python:3.14-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
RUN pip install --no-cache-dir .
RUN mkdir -p /runtime && chown 65532:65532 /runtime

ENV PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
ENTRYPOINT ["fl-forensics"]
