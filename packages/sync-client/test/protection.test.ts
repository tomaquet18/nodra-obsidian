import { describe, expect, it } from "vitest";
import { PROTECTION_CLAIMS, SWITCHED_TO_PRIVATE_CAVEATS, protectionClaim } from "../src/protection.js";

// §3.5: the claim each mode permits, word for word, and the two statements a switched account needs.

describe("§3.5 claims", () => {
  it("Managed: at rest and in transit, and nothing about end-to-end", () => {
    const c = protectionClaim({ mode: "MANAGED", switchedToPrivate: false });
    expect(c.claim).toBe("cifrado en reposo y en tránsito");
    expect(c.claim).not.toMatch(/end-to-end|zero-knowledge/i);
    expect(c.caveats).toEqual([]);
  });

  it("Private from the start: end-to-end encrypted, no caveat", () => {
    expect(protectionClaim({ mode: "PRIVATE", switchedToPrivate: false })).toEqual({ mode: "PRIVATE", claim: "end-to-end encrypted", caveats: [], historyCovered: true });
  });

  it("Private after a switch: both statements, and the earlier history is covered only once re-encrypted", () => {
    const during = protectionClaim({ mode: "PRIVATE", switchedToPrivate: true, historyReencrypted: false });
    expect(during.claim).toBe(PROTECTION_CLAIMS.PRIVATE);
    expect(during.caveats).toEqual([SWITCHED_TO_PRIVATE_CAVEATS.after, SWITCHED_TO_PRIVATE_CAVEATS.before]);
    expect(during.historyCovered).toBe(false);
    expect(protectionClaim({ mode: "PRIVATE", switchedToPrivate: true }).historyCovered).toBe(false); // unknown is not ended
    const after = protectionClaim({ mode: "PRIVATE", switchedToPrivate: true, historyReencrypted: true });
    expect(after.historyCovered).toBe(true);
    expect(after.caveats).toContain(SWITCHED_TO_PRIVATE_CAVEATS.before); // "aun entonces el operador pudo copiarlo"
  });
});
