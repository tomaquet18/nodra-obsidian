// §3.5 and §3.6 for the UI: the account's protection mode and the claim it permits, derived from the
// verified root chain (through this installation's pins when it holds them) and never from anything
// the server declares. The wording is §3.5's, verbatim.
import type { ProtectionMode } from "@nodra/key-lifecycle";
import { type IdbDeps, installationStore } from "./installation.js";
import { uuidToBytes } from "./manifest.js";
import { type AccountPins, type AccountTransport, PINS, type TrustSession, accountTransport, provedRoot, readAccountRows } from "./trust.js";

export type { ProtectionMode } from "@nodra/key-lifecycle";

/** §3.5 "Claim permitido", per mode. */
export const PROTECTION_CLAIMS: Readonly<Record<ProtectionMode, string>> = {
  MANAGED: "cifrado en reposo y en tránsito",
  PRIVATE: "end-to-end encrypted",
};

/**
 * §3.5, "Cuenta que pasó de Managed a Private (§35.13)": the two things the UI must say. The second
 * holds until the history re-encryption ends, and its last clause even after.
 */
export const SWITCHED_TO_PRIVATE_CAVEATS = {
  after: "el contenido escrito después del cambio queda fuera del alcance del operador",
  before: "El contenido anterior solo deja de estar a su alcance cuando termina el re-cifrado del historial, y aun entonces el operador pudo copiarlo mientras era legible.",
} as const;

export interface AccountProtection {
  readonly mode: ProtectionMode;
  /** §3.5: the account is Private now and was Managed before (the chain has a SWITCH_TO_PRIVATE). */
  readonly switchedToPrivate: boolean;
}

/** §3.6: the mode as the verified root chain derives it (pinned, when this installation holds pins). */
export async function accountProtection(
  o: TrustSession & IdbDeps & { readonly installNs: string; readonly transport?: AccountTransport },
): Promise<AccountProtection> {
  // §20.2: another account's pins are never applied to this one's chain (NOTES question 413).
  const pins = (await readAccountRows(installationStore(o), o, [PINS])).rows.get(PINS) as AccountPins | undefined;
  const root = await provedRoot(o.transport ?? accountTransport(o), uuidToBytes(o.accountId), pins);
  return { mode: root.mode, switchedToPrivate: root.switchedToPrivate };
}

export interface ProtectionClaim {
  readonly mode: ProtectionMode;
  /** §3.5 "Claim permitido". */
  readonly claim: string;
  /**
   * What the UI must say beside it. For a Private account that was Managed: both §3.5 statements, and,
   * while the re-encryption has not ended, that the earlier history is NOT covered by the claim.
   */
  readonly caveats: readonly string[];
  /** §3.5: false while the history written before the switch is still under the old epochs. */
  readonly historyCovered: boolean;
}

/**
 * The claim for a mode. `historyReencrypted`: whether the §35.13 re-encryption has ended (the server's
 * list is empty in every vault); only meaningful after a switch, and unknown counts as not ended.
 */
export function protectionClaim(p: AccountProtection & { readonly historyReencrypted?: boolean }): ProtectionClaim {
  const claim = PROTECTION_CLAIMS[p.mode];
  if (p.mode === "MANAGED" || !p.switchedToPrivate) return { mode: p.mode, claim, caveats: [], historyCovered: true };
  return { mode: p.mode, claim, caveats: [SWITCHED_TO_PRIVATE_CAVEATS.after, SWITCHED_TO_PRIVATE_CAVEATS.before], historyCovered: p.historyReencrypted === true };
}
