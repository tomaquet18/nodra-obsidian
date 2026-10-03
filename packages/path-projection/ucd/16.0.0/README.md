# Unicode Character Database 16.0.0 (vendored)

Pinned Unicode tables for spec §16.2 and ADR-013 (`unicode_tables_version = 16.0.0`).

- Source: https://www.unicode.org/Public/16.0.0/ucd/
- Files, byte for byte as downloaded (SHA-256 in `SHA256SUMS`):

| File | Used for | SHA-256 |
|---|---|---|
| `UnicodeData.txt` | canonical decompositions, canonical combining classes | `ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f` |
| `CompositionExclusions.txt` | composition exclusions (Full_Composition_Exclusion is derived: listed + singletons + non-starter decompositions) | `89e83cf9cc8bef6c1f8bf77e42cf6f0341dfa42e66261f4dbe9b492e7a23c8ee` |
| `CaseFolding.txt` | full case folding, statuses C + F (never T) | `6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb` |
| `NormalizationTest.txt` | conformance vectors (tests only) | `d811971453e7075e1ad56fb1b301eece5aa80757b81f6156e74a1bfb3ae5ceb1` |

`test/unicode-data.test.ts` checks these hashes. `pnpm gen:unicode` regenerates
`src/generated/unicode-16.0.0.ts`, and the same test fails if the output differs.

Unicode data files are © Unicode, Inc., under the Unicode License v3 (https://www.unicode.org/license.txt).
Changing the version is a protocol migration (ADR-013), never a silent update.
