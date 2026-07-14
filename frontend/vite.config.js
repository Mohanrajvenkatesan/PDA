import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Forwards frontend calls to /api/* -> the backend on :4000
      // so PDAVisualizer.jsx can just fetch('/api/validate') with no
      // hardcoded host and no CORS issues in dev.
      '/api': {
        target: 'http://localhost:4000',
        changeOrigin: true,
      },
    },
  },
});
