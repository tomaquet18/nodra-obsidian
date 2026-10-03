import { isTmpName } from "@nodra/sync-core";
import type { WindowRule } from "./e2e.js";

// The ONLY exemptions of the end-to-end oracles (E2 no lost edit, E3 safe replaces). Without a rule,
// every write or remove that meets content the client did not read last is a violation (e2e.ts).

/**
 * §44.5 / §13.4: "aplicar eventos remotos nunca sobrescribe contenido local no confirmado, salvo una
 * edición dentro de la ventana de reemplazo del adaptador posterior a la recomprobación final". A
 * replace (temporary renamed over the destination, §15 step 4) is not atomic with its re-check: an
 * edit landing after the final re-check is overwritten (or, if it landed in our temporary, placed).
 * Allowed exactly for replaces that apply remote content: applyRemote, and resolve (§17.1, which writes
 * the remote content or a merge with it). Never for removes: those are park → verify → delete.
 * Also allowed for intent applies (question 67): the leader applies a follower's decision with the same
 * §15 write, so it has the same window. The spec names only remote events; this reading is pending.
 */
export const replaceWindow: WindowRule = (e) =>
  (e.kind === "replace-destroyed" || e.kind === "replace-placed") &&
  (e.action === "applyRemote" || e.action === "resolve" || (e.action?.startsWith("intent:") ?? false));

/**
 * §15: deleting one of the client's own temporaries (the write temporary, or a parked file already
 * verified as the expected bytes) "relee el archivo inmediatamente antes y repite la comprobación". An
 * edit of that `nodra-tmp-*` file after the re-read and before the remove is lost: the residual window
 * of a non-atomic delete, moved by parking onto a name the client created. Only temporaries qualify.
 */
export const temporaryRemoveWindow: WindowRule = (e) => e.kind === "remove-destroyed" && isTmpName(e.path);

export const SPEC_WINDOWS: WindowRule = (e) => replaceWindow(e) || temporaryRemoveWindow(e);
