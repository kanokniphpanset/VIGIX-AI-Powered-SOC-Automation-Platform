import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: true,
    port: 5173,
    // Real backend (apps/backend, :4000). All API calls go through /api, so the browser never needs CORS.
    proxy: {
      '/api': { target: process.env.VITE_BACKEND_URL ?? 'http://localhost:4000', changeOrigin: true },
    },
  },
})
