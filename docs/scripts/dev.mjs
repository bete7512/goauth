import { watch } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { root, syncContent } from "./sync-content.mjs";

syncContent();
let timer;
const watchers = ["docs", "blog", "standalone"].map((dir) =>
  watch(join(root, dir), { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try {
        syncContent();
      } catch (error) {
        console.error(error);
      }
    }, 100);
  }),
);
const next = spawn(
  process.execPath,
  ["node_modules/next/dist/bin/next", "dev", ...process.argv.slice(2)],
  { cwd: root, stdio: "inherit" },
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => next.kill(signal));
next.on("exit", (code) => {
  watchers.forEach((watcher) => watcher.close());
  clearTimeout(timer);
  process.exit(code ?? 0);
});
