import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Keep editor API and contributions on one module graph in development.
  optimizeDeps: { exclude: ['monaco-editor'] },
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: { host: '127.0.0.1', port: 5173, strictPort: true,
    proxy: { '/api': { target: process.env.PROTOCOL_LAB_API_URL ?? 'http://127.0.0.1:8000' } } },
})
