import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// En développement (npm run dev), /api est relayé vers le backend .NET.
// En production (Docker), c'est nginx qui fait ce relais (voir nginx.conf).
export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 900 },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.VITE_BACKEND_URL ?? 'http://localhost:8080', changeOrigin: true },
    },
  },
})
