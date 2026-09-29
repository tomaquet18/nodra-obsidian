import { z } from "zod";

// The plugin's configuration is fixed at build time: which environment (production, staging or
// development), the Nodra API, the Supabase project and its public (anon / publishable) key. It is
// checked here and a bad one refuses to build: fail closed. Ported from the web's check
// (apps/web/src/config.ts); production and staging are held to the web's production rules.

export const ENVIRONMENTS = ["production", "staging", "development"];

/** The development build's defaults: the local dev server (`pnpm dev:server`), which answers /auth/v1 too. */
const DEVELOPMENT = { NODRA_API_URL: "http://127.0.0.1:8787", NODRA_SUPABASE_URL: "http://127.0.0.1:8787", NODRA_SUPABASE_ANON_KEY: "dev" };

/** An origin and nothing else: no path, query, fragment, credentials or wildcard. https unless development. */
const origin = (strict) =>
  z
    .string({ error: "missing" })
    .min(1, "missing")
    .transform((s, ctx) => {
      let u;
      try {
        u = new URL(s);
      } catch {
        ctx.addIssue({ code: "custom", message: "not an absolute URL" });
        return z.NEVER;
      }
      const ok =
        (u.protocol === "https:" || (!strict && u.protocol === "http:")) &&
        u.username === "" &&
        u.password === "" &&
        u.pathname === "/" &&
        u.search === "" &&
        u.hash === "" &&
        !s.includes("*") &&
        /^https?:\/\/[^/?#\s;,'"]+\/?$/.test(s);
      if (!ok) ctx.addIssue({ code: "custom", message: `must be an origin only (${strict ? "https" : "http or https"}://host[:port]), with no path, query or wildcard` });
      return u.origin;
    });

/** The `role` claim of a legacy Supabase API key (a JWT); null when it is not one. */
function jwtRole(key) {
  const parts = key.split(".");
  if (parts.length !== 3) return null;
  try {
    const role = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")).role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

/** The public key only: a secret one in a public bundle would hand the project to anyone. */
const anonKey = (strict) =>
  z
    .string({ error: "missing" })
    .min(1, "missing")
    .refine((k) => !k.startsWith("sb_secret_") && jwtRole(k) !== "service_role", "is a secret key: use the anon (or publishable) key")
    .refine((k) => !strict || jwtRole(k) === "anon" || /^sb_publishable_[A-Za-z0-9_-]+$/.test(k), "is not a Supabase anon or publishable key");

/**
 * The build configuration from the environment, or the problems (one line each, never a value).
 * @param {Record<string, string | undefined>} env
 * @returns {{ ok: true, config: { env: string, apiUrl: string, supabaseUrl: string, supabaseAnonKey: string } } | { ok: false, problems: string[] }}
 */
export function checkBuildConfig(env) {
  const name = env.NODRA_ENV;
  if (!ENVIRONMENTS.includes(name)) return { ok: false, problems: [`NODRA_ENV: must be one of ${ENVIRONMENTS.join(", ")}`] };
  const strict = name !== "development";
  const keys = Object.keys(DEVELOPMENT);
  const input = Object.fromEntries(keys.map((k) => [k, env[k] || (strict ? undefined : DEVELOPMENT[k])]));
  const parsed = z.object({ NODRA_API_URL: origin(strict), NODRA_SUPABASE_URL: origin(strict), NODRA_SUPABASE_ANON_KEY: anonKey(strict) }).safeParse(input);
  if (!parsed.success) return { ok: false, problems: parsed.error.issues.map((i) => `${String(i.path[0])}: ${i.message}`) };
  const d = parsed.data;
  return { ok: true, config: { env: name, apiUrl: d.NODRA_API_URL, supabaseUrl: d.NODRA_SUPABASE_URL, supabaseAnonKey: d.NODRA_SUPABASE_ANON_KEY } };
}
