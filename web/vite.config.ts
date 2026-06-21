import { defineConfig } from "vite";

// The backend (mx-server) listens on 127.0.0.1:9990. We proxy REST + WebSocket through
// Vite so the browser talks same-origin (no CORS, no server changes). Override the backend
// location with MX_BACKEND if you run it elsewhere.
const backend = process.env.MX_BACKEND ?? "http://127.0.0.1:9990";

export default defineConfig({
  server: {
    port: 5180,
    strictPort: false,
    host: true,
    proxy: {
      "/v1": { target: backend, changeOrigin: true, ws: true },
      "/health": { target: backend, changeOrigin: true },
    },
  },
});
