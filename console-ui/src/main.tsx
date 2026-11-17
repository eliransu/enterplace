import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";

// The tokens switch on data-theme, as the server-rendered pages set it from the system setting.
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const theme = () => document.documentElement.setAttribute("data-theme", dark.matches ? "dark" : "light");
theme();
dark.addEventListener("change", theme);

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
