# Isolated, source-only V79 Sentinel candidate. NOT a production deployment.
# Independently recorded base manifest digest from GitHub trial run 40762993639.
# Linux/amd64 only; change this digest only via a reviewed source update.
FROM python@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Three exactly hash-pinned public wheels, no sdist, no other dependencies.
# A wheel checksum mismatch fails the build before startup.
COPY images/sentinel-candidate-requirements.lock /tmp/sentinel-requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: \
    --require-hashes --no-deps -r /tmp/sentinel-requirements.lock \
 && python -m pip check \
 && rm -f /tmp/sentinel-requirements.lock \
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
