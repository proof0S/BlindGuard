FROM python:3.12-slim

LABEL maintainer="BlindGuard Team"
LABEL description="Private Security Agent — audits code without seeing or stealing it"
LABEL version="0.1.0"

# Security: non-root user
RUN groupadd -r blindguard && useradd -r -g blindguard blindguard

WORKDIR /app

# Copy agent code
COPY agent/ ./agent/
COPY cli/ ./cli/
COPY manifest.json .

# State directory (TEE-encrypted in production)
RUN mkdir -p /data/blindguard-state && chown -R blindguard:blindguard /data
ENV BLINDGUARD_STATE_DIR=/data/blindguard-state

# No external dependencies needed for core agent (stdlib only)
# EigenAI is accessed via HTTP — no SDK install required

USER blindguard

EXPOSE 8000

ENV PORT=8000

CMD ["python", "-m", "agent.server"]
