# Build only the server; the other manifests are needed to resolve the workspace.
FROM rust:1.90-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/desktop/src-tauri ./apps/desktop/src-tauri
RUN cargo build --locked --release -p silo-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 silo \
    && useradd --uid 10001 --gid silo --no-create-home --shell /usr/sbin/nologin silo \
    && install -d -o silo -g silo -m 0700 /data/db /data/files
COPY --from=builder /build/target/release/silo-server /usr/local/bin/silo-server
USER silo:silo
ENV SILO_SERVER_DB=/data/db/silo-server.db
# In the container namespace; Compose publishes this only on host loopback.
ENV SILO_SERVER_ADDR=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["silo-server"]
