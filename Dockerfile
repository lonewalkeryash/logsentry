# LogSentry container image.
#   docker build -t logsentry .
#   docker run --rm -v "$PWD/samples:/logs:ro" logsentry scan /logs/auth.log --year 2026
# Detection needs no privileges. Auto-block from a container needs the host's
# network namespace and NET_ADMIN, see docker-compose.yml.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
 && useradd --system --no-create-home --shell /usr/sbin/nologin logsentry \
 && mkdir -p /var/lib/logsentry && chown logsentry /var/lib/logsentry

ENV LOGSENTRY_STATE=/var/lib/logsentry/blocks.json PYTHONUNBUFFERED=1
USER logsentry
ENTRYPOINT ["logsentry"]
CMD ["--help"]
