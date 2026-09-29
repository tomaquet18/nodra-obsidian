import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";

// Bumps the plugin's version in lockstep: manifest.json (what Obsidian and BRAT read), package.json, and
// versions.json (each version's minAppVersion, for Obsidian to offer an older release to an older app).
//
//   pnpm --filter @nodra/obsidian-plugin run version 0.2.0
//
// Without an argument it takes npm_package_version (the `npm version` lifecycle). Run in the plugin folder.

const version = process.argv[2] ?? process.env.npm_package_version;
if (version === undefined || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("usage: node version-bump.mjs <major.minor.patch>");
  process.exit(1);
}

const read = (file) => JSON.parse(readFileSync(file, "utf8"));
const write = (file, data) => writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);

const manifest = read("manifest.json");
const pkg = read("package.json");
const versions = read("versions.json");
write("manifest.json", { ...manifest, version });
write("package.json", { ...pkg, version });
write("versions.json", { ...versions, [version]: manifest.minAppVersion });
console.log(`Nodra plugin ${version} (minAppVersion ${manifest.minAppVersion})`);
