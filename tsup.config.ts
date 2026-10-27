import { copyFile } from "node:fs/promises";
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/workout-tools.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  onSuccess: async () => {
    await copyFile("src/workout-tools.json", "dist/workout-tools.json");
  },
});
