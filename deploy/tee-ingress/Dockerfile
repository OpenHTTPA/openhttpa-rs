# TEE-Native Ingress Controller Dockerfile
# This Dockerfile is designed to package the openhttpa-ingress binary
# for deployment within an Intel TDX or SGX Enclave.

# --- Build Stage ---
FROM rust:1.88-bullseye AS builder

WORKDIR /usr/src/openhttpa
COPY . .

# Build the ingress controller natively
RUN cargo build --release -p openhttpa-ingress

# --- Final Enclave Stage ---
# For TDX, we can use a standard minimal base image since TDX supports full VMs.
# For SGX, we would typically use a Gramine base image here.
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /usr/src/openhttpa/target/release/openhttpa-ingress /usr/local/bin/openhttpa-ingress

# Configure environment variables
# For TDX, the TDX guest driver must be available at /dev/tdx_guest
ENV RUST_LOG=info
ENV EVENT_BROKER_URL="127.0.0.1:9092"

# Expose the OpenHTTPA port
EXPOSE 8443

# Run the ingress controller
CMD ["openhttpa-ingress"]
