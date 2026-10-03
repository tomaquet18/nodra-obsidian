import Dexie from "dexie";

/**
 * Test guard for the rule "never await anything that is not IndexedDB inside a Dexie transaction":
 * every Web Crypto call, fetch and timer throws while a Dexie transaction is the current zone.
 * Returns a function that restores the originals.
 */
export function guardForeignAwaits(): () => void {
  const subtle = globalThis.crypto.subtle as unknown as Record<string, unknown>;
  const restores: Array<() => void> = [];
  const wrap = (target: Record<string, unknown>, name: string) => {
    const original = target[name];
    if (typeof original !== "function") return;
    target[name] = function (this: unknown, ...args: unknown[]) {
      if (Dexie.currentTransaction) throw new Error(`${name} called inside a Dexie transaction`);
      return (original as (...a: unknown[]) => unknown).apply(this, args);
    };
    restores.push(() => {
      target[name] = original;
    });
  };
  for (const name of ["encrypt", "decrypt", "sign", "verify", "digest", "importKey", "generateKey", "deriveKey", "deriveBits", "exportKey", "wrapKey", "unwrapKey"]) {
    wrap(subtle, name);
  }
  const g = globalThis as unknown as Record<string, unknown>;
  for (const name of ["fetch", "setTimeout"]) wrap(g, name);
  return () => {
    for (const r of restores.reverse()) r();
  };
}
