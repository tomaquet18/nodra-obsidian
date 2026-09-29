import { existsSync } from "node:fs";
import process from "node:process";
import esbuild from "esbuild";
import { checkBuildConfig } from "./build-config.mjs";

// The Obsidian plugin build: src/main.ts → main.js (CommonJS), `obsidian` and the editor packages
// provided by the app. The environment is fixed at build time (build-config.mjs, fail closed):
//
//   node esbuild.config.mjs <production|staging|development> [--watch] [--outfile=<path>] [--config=<env file>|none]
//
// The configuration comes from the environment (NODRA_API_URL, NODRA_SUPABASE_URL,
// NODRA_SUPABASE_ANON_KEY), and from `.env.<environment>` next to this file when it exists (variables
// already set win). The development build defaults to the local dev server. It becomes constants in
// the bundle (src/globals.d.ts), so a production build holds no dev or staging code.

const [target = "", ...flags] = process.argv.slice(2);
const flag = (name) => flags.find((f) => f.startsWith(`--${name}=`))?.slice(name.length + 3);
const watch = flags.includes("--watch");

const envFile = flag("config") ?? `.env.${target}`;
if (target !== "" && envFile !== "none" && existsSync(envFile)) process.loadEnvFile(envFile);

const checked = checkBuildConfig({ ...process.env, NODRA_ENV: target });
if (!checked.ok) {
  console.error(`Nodra plugin: invalid build configuration (see README.md, "Building"):\n${checked.problems.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(1);
}
const { config } = checked;
const release = config.env !== "development";

const context = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  external: ["obsidian", "electron", "@codemirror/*", "@lezer/*"],
  format: "cjs",
  platform: "browser",
  target: "es2022",
  logLevel: "info",
  sourcemap: release ? false : "inline",
  treeShaking: true,
  minify: release,
  define: {
    NODRA_ENV: JSON.stringify(config.env),
    NODRA_API_URL: JSON.stringify(config.apiUrl),
    NODRA_SUPABASE_URL: JSON.stringify(config.supabaseUrl),
    NODRA_SUPABASE_ANON_KEY: JSON.stringify(config.supabaseAnonKey),
  },
  outfile: flag("outfile") ?? "main.js",
});

if (watch) {
  await context.watch();
} else {
  await context.rebuild();
  await context.dispose();
}
