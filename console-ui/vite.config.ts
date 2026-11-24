import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build lands in the console crate, which embeds it: fixed file names, one script and one stylesheet, so the
// Rust side names each file once and a rebuild with no change leaves git clean.
export default defineConfig({
  base: "/console/app/",
  plugins: [react(), tailwindcss()],
  // "/src" is the project root's src: Vite reads a leading slash as the root.
  resolve: { alias: { "@": "/src" } },
  build: {
    outDir: "../crates/enterplace-console/app",
    emptyOutDir: true,
    cssCodeSplit: false,
    modulePreload: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        assetFileNames: "app.[ext]",
        inlineDynamicImports: true,
      },
    },
  },
  // `npm run dev` against a gateway on this machine: the API and the session cookie are the gateway's.
  server: {
    proxy: {
      "/console/api": "http://127.0.0.1:8080",
      "/console/assets": "http://127.0.0.1:8080",
      "/console/live.json": "http://127.0.0.1:8080",
      // Vite prefixes index.html's root-relative links with the base in dev.
      "/console/app/console/assets": { target: "http://127.0.0.1:8080", rewrite: (p) => p.replace("/console/app", "") },
    },
  },
});
