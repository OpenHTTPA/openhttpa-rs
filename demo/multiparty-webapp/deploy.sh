#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

# deploy.sh - Helper for building and deploying the OpenHTTPA demo website.

set -e

# Default tag
TAG=${1:-latest}
IMAGE_NAME="openhttpa-demo"

echo "🚀 Building production image: ${IMAGE_NAME}:${TAG}"

# Build from workspace root
cd ../..
docker build -t ${IMAGE_NAME}:${TAG} -f demo/multiparty-webapp/Dockerfile.prod .

echo ""
echo "✅ Build complete!"
echo "To run locally: docker run -p 3001:80 ${IMAGE_NAME}:${TAG}"
echo ""
echo "Next steps:"
echo "1. Tag the image for your registry: docker tag ${IMAGE_NAME}:${TAG} your-registry.com/${IMAGE_NAME}:${TAG}"
echo "2. Push the image: docker push your-registry.com/${IMAGE_NAME}:${TAG}"
echo "3. Deploy to your cloud provider (Fly.io, Railway, DigitalOcean, etc.)"
