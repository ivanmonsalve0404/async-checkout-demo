import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { readPublicConfig } from './src/shared/config/public-config.ts';

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, process.cwd(), 'VITE_');
  readPublicConfig(environment);
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': { target: 'http://127.0.0.1:3000', changeOrigin: false },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      proxy: {
        '/api': { target: 'http://127.0.0.1:3000', changeOrigin: false },
      },
    },
  };
});
