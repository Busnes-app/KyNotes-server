import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "VITE_");
  return {
    plugins: [react()],
    // BlockNote's upstream locales/editor already produce ~620 KiB chunks; this
    // measured budget keeps the existing warning actionable above that baseline.
    build: { chunkSizeWarningLimit: 650 },
    server: {
      proxy: { "/api": env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8080" },
    },
  };
});
