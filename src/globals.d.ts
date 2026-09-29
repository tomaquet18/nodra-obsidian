// The build's configuration: esbuild.config.mjs replaces these identifiers with constants (`define`),
// checked by build-config.mjs. A comparison such as `NODRA_ENV === "staging"` becomes a constant too, so a
// production bundle keeps no staging-only code (the Cloudflare Access fields).

declare const NODRA_ENV: "production" | "staging" | "development";
declare const NODRA_API_URL: string;
declare const NODRA_SUPABASE_URL: string;
declare const NODRA_SUPABASE_ANON_KEY: string;
