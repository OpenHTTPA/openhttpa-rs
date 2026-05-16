# Stage 1: Build everything (C library + Caddy)
FROM golang:1.22-bookworm AS builder

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    libclang-dev \
    cmake \
    build-essential \
    pkg-config \
    curl \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/openhttpa
COPY . .

# Build the C library (required by Go bindings)
RUN cargo build --release -p openhttpa-c

# Prepare Go bindings
RUN mkdir -p bindings/go/lib && \
    cp target/release/libopenhttpa_c.so bindings/go/lib/

# Build the custom caddy binary
WORKDIR /usr/src/openhttpa/modules/caddy
RUN go build -o openhttpa-caddy main.go

# Stage 2: Final image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/openhttpa/modules/caddy/openhttpa-caddy /usr/bin/caddy
COPY --from=builder /usr/src/openhttpa/target/release/libopenhttpa_c.so /usr/lib/libopenhttpa_c.so
COPY demo/native-modules/index.html /usr/share/caddy/index.html

# Ensure caddy is executable
RUN chmod +x /usr/bin/caddy

EXPOSE 8082

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
