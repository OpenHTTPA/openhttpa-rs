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
    opam \
    bubblewrap \
    apt-transport-https \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Install pnpm
RUN npm install -g pnpm

# Install wasm-pack
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

USER vscode

# Configure cargo-binstall and install Cargo CLI tools (uses pre-compiled binaries to speed up container build)
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash && \
    /home/vscode/.cargo/bin/cargo binstall -y cargo-audit cargo-deny maturin cargo-cyclonedx

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    export PATH="/home/vscode/.foundry/bin:$PATH" && \
    /home/vscode/.foundry/bin/foundryup

# Initialize OPAM and install ProVerif
RUN opam init --disable-sandboxing --bare -y && \
    opam switch create 4.14.0 -y && \
    eval $(opam env) && \
    opam install -y proverif

# Expose binaries in vscode PATH
ENV PATH="/home/vscode/.foundry/bin:/home/vscode/.cargo/bin:${PATH}"

USER vscode
