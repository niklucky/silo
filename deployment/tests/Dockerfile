FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx openssh-client sqlite3 certbot ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY deployment /test/deployment
CMD ["bash", "/test/deployment/tests/provision.sh"]
