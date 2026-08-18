import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { readPublicConfig } from './src/shared/config/public-config.ts';

const localProxyTarget = (candidate: string): string => {
  const target = new URL(candidate);
  const isLoopback = target.hostname === '127.0.0.1' || target.hostname === 'localhost';
  if (
    target.protocol !== 'http:' ||
    !isLoopback ||
    target.username.length > 0 ||
    target.password.length > 0 ||
    target.pathname !== '/' ||
    target.search.length > 0 ||
    target.hash.length > 0
  ) {
    throw new Error('SMOKE_API_PROXY_TARGET_INVALID');
  }
  return target.origin;
};

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, process.cwd(), 'VITE_');
  const apiProxyTarget = localProxyTarget(
    process.env.SMOKE_API_PROXY_TARGET ?? 'http://127.0.0.1:3000',
  );
  readPublicConfig(environment);
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': { target: apiProxyTarget, changeOrigin: false },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      proxy: {
        '/api': { target: apiProxyTarget, changeOrigin: false },
      },
    },
  };
});
