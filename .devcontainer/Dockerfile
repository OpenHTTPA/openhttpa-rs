FROM mcr.microsoft.com/devcontainers/rust:1-1.88-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    cmake \
    make \
    ninja-build \
    nasm \
    golang \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install pnpm
RUN npm install -g pnpm

# Install wasm-pack
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install ProVerif (optional, but good for formal verification)
# This is just an example, a real install might need more steps
# RUN wget https://proverif.inria.fr/proverif2.05.tar.gz && ...

USER vscode
