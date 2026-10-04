import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// A release is `node esbuild.config.mjs production`, the exact command run here (in a child process,
// with the configuration in the environment). Like the web's bundle test (apps/web/test/bundle.test.ts),
// it builds the real main.js and pins what is in it: the production API and Supabase project, and no dev
// server, no dev route or header, no staging host and no "(dev)" wording. The staging build is built too,
// so the negative checks are shown to look at real code. A bad configuration refuses to build.

const PLUGIN = fileURLToPath(new URL("..", import.meta.url));
const b64url = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const anonJwt = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ role: "anon" })}.c2ln`;
// ADR-024: the OAuth client ids (public values; examples here).
const PRODUCTION = { NODRA_API_URL: "https://api.nodranotes.com", NODRA_SUPABASE_URL: "https://zlsckqzllncgreukxhqt.supabase.co", NODRA_SUPABASE_ANON_KEY: anonJwt, NODRA_OAUTH_CLIENT_ID: "3b7e2a40-5c1d-4e8f-9a6b-2d4c6e8f0a12" };
const STAGING = { NODRA_API_URL: "https://api-staging.nodranotes.com", NODRA_SUPABASE_URL: "https://kkolsptpyiubqlhnnwfn.supabase.co", NODRA_SUPABASE_ANON_KEY: "sb_publishable_example", NODRA_OAUTH_CLIENT_ID: "8c1f4d2e-6a3b-4c5d-8e9f-0a1b2c3d4e5f" };
/** The dev server's OAuth client id (DEV_OAUTH_CLIENT; login.test.ts pins build-config.mjs's default to it). Literal: this file is exported without the dev server. */
const DEV_OAUTH_CLIENT = { id: "6f9a3c1e-0d2b-4c55-9a7e-0b5d1e0a1c01" };
const KEYS = ["NODRA_ENV", "NODRA_API_URL", "NODRA_SUPABASE_URL", "NODRA_SUPABASE_ANON_KEY", "NODRA_OAUTH_CLIENT_ID"];

let dir: string;
beforeAll(() => void (dir = mkdtempSync(join(tmpdir(), "nodra-plugin-build-"))));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** `node <script> <args>` in the plugin folder, with exactly this configuration (no env file). */
function run(script: string, args: string[], env: Record<string, string>, cwd = PLUGIN) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !KEYS.includes(k)));
  const r = spawnSync(process.execPath, [script, ...args], { cwd, env: { ...clean, ...env }, encoding: "utf8" });
  return { status: r.status, output: `${r.stdout}${r.stderr}` };
}

function build(env: string, config: Record<string, string>, name: string) {
  const outfile = join(dir, name, "main.js");
  const r = run("esbuild.config.mjs", [env, `--outfile=${outfile}`, "--config=none"], config);
  return { ...r, outfile, js: existsSync(outfile) ? readFileSync(outfile, "utf8") : null };
}

/** The needles found in the text (not `toContain` on the bundle: a failure would print all of it). */
const found = (text: string, needles: readonly string[]) => needles.filter((n) => text.includes(n));

const DEV_ONLY = ["/v1/dev/", "127.0.0.1", "localhost:8787", "x-nodra-dev-replica", "devSignIn", "(dev)", "DEVELOPMENT BUILD", "api-staging", "kkolsptpyiubqlhnnwfn", DEV_OAUTH_CLIENT.id, STAGING.NODRA_OAUTH_CLIENT_ID];
const STAGING_ONLY = ["cf-access-client-id", "Access client id"];

describe("the production build", () => {
  let js: string;
  beforeAll(() => {
    const r = build("production", PRODUCTION, "production");
    expect(r.status, r.output).toBe(0);
    js = r.js!;
  }, 120_000);

  it("is the real plugin: the production API and Supabase project, auth-js's routes and the plugin's commands are in it", () => {
    expect(js.length).toBeGreaterThan(100_000);
    expect(found(js, ["https://api.nodranotes.com", PRODUCTION.NODRA_SUPABASE_URL, "/auth/v1", "Sync now", "Sign in"])).toHaveLength(5);
  });

  it("ADR-024: signs in as the production OAuth client, through the browser; no password form is left", () => {
    expect(found(js, [PRODUCTION.NODRA_OAUTH_CLIENT_ID, "/auth/v1/oauth", "grant_type: \"authorization_code\"", "Sign in with your browser"])).toHaveLength(4);
    expect(found(js, ["signInWithPassword(email, password", "Forgot your password?", "Continue with GitHub"])).toEqual([]);
  });

  it("holds no dev path, no dev wording, no staging host and no Access field", () => {
    expect(found(js, [...DEV_ONLY, ...STAGING_ONLY])).toEqual([]);
  });
});

/**
 * Loads main.js the way Obsidian does (CommonJS, `obsidian` from the app; a stub here), with the global
 * `Function` replaced by a trap: what the bundle compiles from strings while its modules load (zod's JIT
 * builds parsers with `new Function`, and probes for it when a schema is created).
 */
function load(js: string) {
  const compiled: string[] = [];
  const Trap = new Proxy(Function, {
    construct: (target, args: unknown[]) => (compiled.push(String(args.at(-1))), Reflect.construct(target, args) as object),
    apply: (target, self, args: unknown[]) => (compiled.push(String(args.at(-1))), Reflect.apply(target, self, args) as unknown),
  });
  const app = new Proxy({}, { get: (_t, name) => (name === "__esModule" ? false : class {}) });
  const module = { exports: {} as Record<string, unknown> };
  const sandbox: Record<string, unknown> = { module, exports: module.exports, require: () => app, Function: Trap, console, setTimeout, clearTimeout, TextEncoder, TextDecoder, crypto, URL, navigator: { userAgent: "Obsidian" } };
  sandbox.window = sandbox.self = sandbox.globalThis = sandbox;
  runInNewContext(js, sandbox);
  return { compiled, plugin: module.exports.default };
}

describe("the production build holds no dynamic code (Obsidian's review)", () => {
  let js: string;
  beforeAll(() => {
    const r = build("production", PRODUCTION, "no-eval");
    expect(r.status, r.output).toBe(0);
    js = r.js!;
  }, 120_000);

  it("is not minified, so it can be read: the source's names are in it, one statement per line", () => {
    expect(found(js, ["function hintDebouncer(", "function takeOwnership(", "NodraPlugin = class extends"])).toHaveLength(3);
    const lines = js.split("\n");
    expect(js.length / lines.length).toBeLessThan(80); // a minified bundle is a few very long lines
  });

  // Unminified, esbuild names each bundled file by its path (comments, CommonJS keys). The public repo
  // has the plugin at its root: the same paths there and here, so both builds are byte for byte equal.
  it("names bundled files by layout-free paths, so the public repo's build is the same bytes", () => {
    expect(found(js, ["../../node_modules/", "../../packages/", "../node_modules/"])).toEqual([]);
    expect(found(js, ["// node_modules/.pnpm/zod@", "// packages/sync-client/src/", "// src/main.ts"])).toHaveLength(3);
  });

  it("has no global-object probe through Function (lodash's `Function(\"return this\")`)", () => {
    expect(found(js, ['Function("return this")', "Function('return this')"])).toEqual([]);
  });

  it("loads without compiling any code from a string: zod is jitless before its first schema", () => {
    const { compiled, plugin } = load(js);
    expect(typeof plugin).toBe("function"); // it really loaded: the plugin class is exported
    expect(compiled).toEqual([]);
  });

  it("the trap sees zod's JIT when it is on (so the check above can fail)", () => {
    const on = /config\(\{ jitless: (?:true|!0) \}\)/;
    expect(js).toMatch(on);
    const { compiled } = load(js.replace(on, "config({ jitless: false })"));
    expect(compiled.length).toBeGreaterThan(0);
  });
});

describe("the staging build", () => {
  it("talks to staging and has the Access fields (so the checks above look at real code)", () => {
    const r = build("staging", STAGING, "staging");
    expect(r.status, r.output).toBe(0);
    expect(found(r.js!, ["api-staging.nodranotes.com", "kkolsptpyiubqlhnnwfn", STAGING.NODRA_OAUTH_CLIENT_ID, ...STAGING_ONLY])).toHaveLength(5);
    expect(found(r.js!, ["/v1/dev/", "127.0.0.1", "(dev)"])).toEqual([]);
  }, 120_000);
});

describe("the development build", () => {
  it("points at the local dev server, and its OAuth client (DEV_OAUTH_CLIENT), with no configuration", () => {
    const r = build("development", {}, "development");
    expect(r.status, r.output).toBe(0);
    expect(found(r.js!, ["http://127.0.0.1:8787", DEV_OAUTH_CLIENT.id])).toHaveLength(2);
  }, 120_000);
});

describe("the build fails closed", () => {
  const refused = (env: string, config: Record<string, string>, name: string, problem: RegExp) => {
    const r = build(env, config, name);
    expect(r.status).not.toBe(0);
    expect(r.output).toMatch(problem);
    expect(r.js).toBeNull();
  };

  it("without an environment, or with an unknown one", () => {
    refused("", PRODUCTION, "no-env", /NODRA_ENV/);
    refused("prod", PRODUCTION, "bad-env", /NODRA_ENV/);
  }, 120_000);

  it("production without its configuration names what is missing", () => {
    refused("production", {}, "missing", /NODRA_API_URL: missing[\s\S]*NODRA_SUPABASE_URL: missing[\s\S]*NODRA_SUPABASE_ANON_KEY: missing[\s\S]*NODRA_OAUTH_CLIENT_ID: missing/);
  }, 120_000);

  it("ADR-024: an OAuth client id that is not a UUID, or production with the dev client's", () => {
    refused("production", { ...PRODUCTION, NODRA_OAUTH_CLIENT_ID: "nodra-for-obsidian" }, "client-id", /NODRA_OAUTH_CLIENT_ID/);
    refused("production", { ...PRODUCTION, NODRA_OAUTH_CLIENT_ID: DEV_OAUTH_CLIENT.id }, "dev-client-id", /NODRA_OAUTH_CLIENT_ID/);
  }, 120_000);

  it("production or staging over http, with a path, or with the dev key", () => {
    refused("production", { ...PRODUCTION, NODRA_API_URL: "http://127.0.0.1:8787" }, "http", /NODRA_API_URL/);
    refused("staging", { ...STAGING, NODRA_SUPABASE_URL: "https://kkolsptpyiubqlhnnwfn.supabase.co/auth/v1" }, "path", /NODRA_SUPABASE_URL/);
    refused("production", { ...PRODUCTION, NODRA_SUPABASE_ANON_KEY: "dev" }, "dev-key", /NODRA_SUPABASE_ANON_KEY/);
  }, 120_000);

  it("a secret key, in any build", () => {
    const serviceRole = `${b64url({ alg: "HS256" })}.${b64url({ role: "service_role" })}.c2ln`;
    refused("production", { ...PRODUCTION, NODRA_SUPABASE_ANON_KEY: serviceRole }, "service-role", /secret key/);
    refused("development", { NODRA_SUPABASE_ANON_KEY: "sb_secret_abc" }, "dev-secret", /secret key/);
  }, 120_000);
});

describe("release metadata", () => {
  const json = (path: string) => JSON.parse(readFileSync(join(PLUGIN, path), "utf8")) as Record<string, unknown>;

  it("manifest.json is the public plugin's, and versions.json and package.json agree with it", () => {
    const manifest = json("manifest.json");
    expect(manifest).toMatchObject({ id: "nodra", name: "Nodra", minAppVersion: "1.11.4", isDesktopOnly: true });
    expect((manifest.description as string).length).toBeLessThanOrEqual(250);
    expect(manifest.description).not.toMatch(/\bdev\b|development|phase/i);
    expect(json("package.json").version).toBe(manifest.version);
    expect(json("versions.json")[manifest.version as string]).toBe(manifest.minAppVersion);
  });

  // §3.5: new accounts are Managed (the server keeps an escrow and can read notes), so a public claim of
  // end-to-end encryption, or that Nodra cannot read notes, may only be made of Private mode.
  const claimProblems = (text: string) =>
    text
      .replace(/\s+/g, " ")
      .split(/(?<=[.!?:;])\s+|\n|^#+ /m)
      .filter((s) => /zero[- ]knowledge/i.test(s) || (/end-to-end|\be2ee\b|cannot read|can't read|ciphertext only/i.test(s) && (!/\bprivate\b/i.test(s) || /\bmanaged\b/i.test(s))));

  it("the manifest and the README never claim end-to-end encryption outside Private mode (§3.5)", () => {
    expect(claimProblems(json("manifest.json").description as string)).toEqual([]);
    expect(claimProblems(readFileSync(join(PLUGIN, "README.md"), "utf8"))).toEqual([]);
    // The check can fail.
    expect(claimProblems("End-to-end encrypted sync for your vault.")).toHaveLength(1);
    expect(claimProblems("Nodra cannot read your notes in Managed or Private mode.")).toHaveLength(1);
    expect(claimProblems("In Private mode, sync is end-to-end encrypted.")).toEqual([]);
  });

  it("the README discloses that Nodra is a service with paid plans, and that the plugin takes no payment (Obsidian developer policies)", () => {
    const readme = readFileSync(join(PLUGIN, "README.md"), "utf8");
    expect(readme).toMatch(/^## Plans and payments$/m);
    expect(readme).toContain("Paid plans (Pro, Max)");
    expect(readme).toContain("the plugin never asks for payment details");
  });

  it("the README's Network use links the privacy policy for what Nodra's servers see (Obsidian developer policies)", () => {
    const readme = readFileSync(join(PLUGIN, "README.md"), "utf8");
    const network = readme.slice(readme.indexOf("## Network use"), readme.indexOf("\n## ",readme.indexOf("## Network use") + 1));
    expect(network).toContain("https://nodranotes.com/privacy");
    expect(network).toContain("It sends no telemetry and no analytics.");
  });

  it("`version` bumps manifest.json, versions.json and package.json in lockstep", () => {
    const copy = join(dir, "version");
    rmSync(copy, { recursive: true, force: true });
    spawnSync(process.execPath, ["-e", `require("node:fs").mkdirSync(${JSON.stringify(copy)}, { recursive: true })`]);
    for (const f of ["manifest.json", "versions.json", "package.json"]) copyFileSync(join(PLUGIN, f), join(copy, f));
    const r = run(join(PLUGIN, "version-bump.mjs"), ["9.8.7"], {}, copy);
    expect(r.status, r.output).toBe(0);
    const read = (f: string) => JSON.parse(readFileSync(join(copy, f), "utf8")) as Record<string, unknown>;
    const manifest = read("manifest.json");
    expect(manifest.version).toBe("9.8.7");
    expect(read("package.json").version).toBe("9.8.7");
    expect(read("versions.json")["9.8.7"]).toBe(manifest.minAppVersion);
    expect(run(join(PLUGIN, "version-bump.mjs"), ["not-a-version"], {}, copy).status).not.toBe(0);
  });
});

describe("styles.css (the panel's styles, a release asset next to main.js)", () => {
  it("colors only through Obsidian's CSS variables, so it follows every theme", () => {
    const css = readFileSync(join(PLUGIN, "styles.css"), "utf8");
    expect(css.match(/#[0-9a-f]{3,8}\b|\b(rgb|rgba|hsl|hsla)\(/gi)).toBeNull();
    expect(css).toContain("var(--");
  });
});
