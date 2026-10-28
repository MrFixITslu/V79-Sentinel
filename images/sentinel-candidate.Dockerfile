# Isolated, source-only V79 Sentinel candidate. NOT a production deployment.
# The builder MUST pass a concrete repo@sha256 base pinned at CI runtime.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Pinned package version, no private repositories, keys or customer data.
RUN python -m pip install --no-cache-dir 'cryptography==45.0.7' \
 && groupadd --gid 10001 sentinel \
 && useradd --uid 10001 --gid 10001 --home-dir /app \
    --shell /usr/sbin/nologin sentinel

# CI constructs a fresh allowlisted context: never copy the repository root.
COPY --chown=10001:10001 . /app/
RUN mkdir -p /app/data && chown 10001:10001 /app/data \
 && python -B -c 'import sentinel, monitor_core, noc.inprocess_probe_receipt; print("CANDIDATE_IMPORTS=PASS")'

USER 10001:10001
# No EXPOSE or published port. Container service is loopback-only.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8787/healthz", timeout=2).status == 200'
# This is a future live candidate COMMAND only. GitHub CI deliberately
# overrides the command to demo mode with --network none.
CMD ["python","sentinel.py","--live","--bind","127.0.0.1","--port","8787"]
