import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// API target for the dev proxy; e2e tests point it at an isolated backend.
const apiTarget = process.env.TF_API_URL ?? 'http://127.0.0.1:8000';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: { manualChunks: { cytoscape: ['cytoscape'] } },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/health': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
});
