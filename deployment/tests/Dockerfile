FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx openssh-client sqlite3 certbot ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY deployment /test/deployment
RUN test ! -e /test/deployment/.env.production \
    && test ! -e /test/deployment/github_deploy_key \
    && test ! -e /test/deployment/github_deploy_key.pub
CMD ["bash", "-ec", "bash /test/deployment/tests/provision.sh && python3 /test/deployment/tests/deploy.py"]
