FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir -p /app/data /app/qa && chown -R 10001:10001 /app/data /app/qa
COPY --chown=10001:10001 config.json monitor_core.py lab_probe.py qa_results.py protected_preflight.py sentinel.py ./
COPY --chown=10001:10001 qa/protected-qa-policy.json ./qa/protected-qa-policy.json
COPY --chown=10001:10001 web ./web
USER 10001:10001
EXPOSE 8787
CMD ["python","sentinel.py","--live","--bind","0.0.0.0","--port","8787"]
