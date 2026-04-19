FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wireguard-tools \
      iptables \
      iproute2 \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py gateway.py wg.py audit.py hash_password.py entrypoint.sh ./
COPY templates ./templates
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
EXPOSE 51820/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
