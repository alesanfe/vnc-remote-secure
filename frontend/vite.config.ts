import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The bundle is served by the landing service under /admin/ — the
// build output lands inside the Python package so the wheel carries
// it and no Node runtime is needed in production.
export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  build: {
    outDir: '../src/vnc_remote_secure/web/static/admin',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      // Dev server proxies API calls to a running landing service.
      '/api': 'http://127.0.0.1:8000',
    },
  },
});
