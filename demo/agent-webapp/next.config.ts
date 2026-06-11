import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/graphql',
        destination: 'http://127.0.0.1:8081/graphql',
      },
    ];
  },
};

export default nextConfig;
