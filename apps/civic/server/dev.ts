import { serve } from "@hono/node-server";
import { spawn } from "node:child_process";
import { createCivic, ORIGIN } from "./app.js";

const { app } = createCivic();
const port = 8787;

serve({ fetch: app.fetch, hostname: "127.0.0.1", port }, () => {
  console.log(`Panacea API listening on http://127.0.0.1:${port}`);
  console.log(`Open ${ORIGIN}`);
});

const vite = spawn("pnpm", ["exec", "vite", "--host", "127.0.0.1", "--port", "5173"], {
  cwd: new URL("..", import.meta.url),
  stdio: "inherit",
});

function shutdown() {
  vite.kill();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
