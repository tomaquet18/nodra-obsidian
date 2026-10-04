// typescript-eslint (the parser of Obsidian's plugin linter, eslint-plugin-obsidianmd) needs TypeScript's
// JavaScript API, which TypeScript 7 (this workspace's compiler) no longer has: with TypeScript 7 as its
// peer it refuses to run. Its packages get TypeScript 6, the last version with that API, as their own
// dependency instead. Only the linter is affected; `tsc` stays TypeScript 7.
const LINTER_TYPESCRIPT = "6.0.3";
const NEEDS_TS_API = /^(typescript-eslint|@typescript-eslint\/.+|ts-api-utils)$/;

function readPackage(pkg) {
  if (NEEDS_TS_API.test(pkg.name) && pkg.peerDependencies?.typescript !== undefined) {
    delete pkg.peerDependencies.typescript;
    pkg.dependencies = { ...pkg.dependencies, typescript: LINTER_TYPESCRIPT };
  }
  return pkg;
}

module.exports = { hooks: { readPackage } };
