import { createRequire } from 'module';
import path from 'path';

// v1.6.4.8: expose the real package version to the client so it can never be
// hand-typed stale again (TopNav/CommandBar/JSON-LD previously hardcoded
// "v1.6.2" in five separate places). createRequire (not the `with { type:
// "json" }` import-attribute syntax) so this works regardless of the Node
// version running next build in any given environment.
const require = createRequire(import.meta.url);
const pkg = require('./package.json');

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:8000';

/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_AEGIS_VERSION: pkg.version,
  },
  turbopack: {
    root: path.resolve('.'),
  },
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: `${BACKEND_URL}/api/v1/:path*`,
      },
      {
        source: '/docs',
        destination: `${BACKEND_URL}/docs`,
      },
      {
        source: '/openapi.json',
        destination: `${BACKEND_URL}/openapi.json`,
      },
    ];
  },
};

export default nextConfig;
