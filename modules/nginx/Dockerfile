# Stage 1: Build the Rust module and Nginx headers
FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libclang-dev \
    cmake \
    build-essential \
    curl \
    git \
    pkg-config \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    golang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/openhttpa
COPY . .

# Build the nginx module
WORKDIR /usr/src/openhttpa/modules/nginx
RUN cargo build --release

# Stage 2: Final image with Nginx
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    wget \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dev \
    libssl-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV NGINX_VERSION 1.27.0

RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz

WORKDIR /nginx-${NGINX_VERSION}

# Configure and build Nginx with dynamic module support
RUN ./configure \
    --prefix=/usr/local/nginx \
    --with-http_ssl_module \
    --with-compat \
    && make && make install

# Create modules directory
RUN mkdir -p /usr/local/nginx/modules

# Copy the built .so from stage 1
COPY --from=builder /usr/src/openhttpa/target/release/libopenhttpa_nginx.so /usr/local/nginx/modules/ngx_http_openhttpa_module.so

# Add nginx to PATH
ENV PATH="/usr/local/nginx/sbin:${PATH}"

# Copy the demo configurations and assets
COPY demo/native-modules/nginx.conf /usr/local/nginx/conf/nginx.conf
COPY demo/native-modules/index.html /usr/local/nginx/html/index.html

EXPOSE 8081

CMD ["nginx", "-g", "daemon off;"]
