FROM --platform=linux/amd64 python:3.12-slim

LABEL maintainer="BlindGuard Team"
LABEL description="Private Security Agent — audits code without seeing or stealing it"
LABEL version="0.1.0"

USER root

WORKDIR /app

COPY analyzer.py .
COPY crypto.py .
COPY server.py .
COPY state.py .
COPY upgrade.py .
COPY github_app.py .
COPY blindguard_cli.py .
COPY manifest.json .
COPY sample_vulnerable_app.py .
COPY index.html .

RUN mkdir -p /data/blindguard-state
ENV BLINDGUARD_STATE_DIR=/data/blindguard-state

EXPOSE 8000

ENV PORT=8000

CMD ["python3", "server.py"]
