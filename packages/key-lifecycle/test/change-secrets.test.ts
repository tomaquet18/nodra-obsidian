// §35.6: changing the Encryption Password or the Account Secret Key.
//
// The whole operation is "the same keys, reachable through different secrets", so the assertions
// are about *continuity*, not about new material: the re-wrapped keyset must still be the pair the
// root in force names, and every envelope written before the change must still open. Those are
// checked by using the keys — signing under the new Signing handle and verifying against the
// unchanged `account_signing_public_key`, and opening E1's ACCOUNT envelope with the new Operation
// handle — rather than by comparing wrapped blobs, which would prove nothing about what they hold.
//
// The negatives are the four ways §35.6 can go wrong: a profile signed against the wrong
// `config_version` (the replay the signature exists to stop), a profile with no signature at all,
// a bundle that also changes something §35.1.1 marks **—**, and a bundle prepared over a state
// that has moved.
import {
  importHkdfBase,
  importVerifyingKey,
  openEpochSecret,
  signContext,
  timingSafeEqual,
  verifyContext,
} from "@nodra/crypto";
import { describe, expect, it } from "vitest";
import { validateSecurityBundle } from "../src/bundle.js";
import { assembleBundle, signProfileUpdate } from "../src/bundle-build.js";
import { changeSecrets } from "../src/change-secrets.js";
import type { ChangedSecrets } from "../src/change-secrets.js";
import { expectedOf } from "../src/client-state.js";
import { selfTestContext } from "../src/contexts.js";
import { deriveEpochCommitment, idKey } from "../src/epoch.js";
import { envelopeLabelContext } from "../src/contexts.js";
import { nextRegistry, signRegistry } from "../src/registry.js";
import { unlockForOperation, unlockSession } from "../src/unlock.js";
import { filled } from "./support.js";
import { envelopeFor, operationWorld, withScopes } from "./operations-support.js";

const BUNDLE_ID = filled(16, 0x81);
const NEW_PASSWORD = "an entirely different passphrase";
const NEW_SALT = filled(16, 0x5c);

/** The §35.6 result, built once: it runs Argon2id over a brand-new salt. */
let changed: Promise<ChangedSecrets> | null = null;

async function passwordChange(): Promise<ChangedSecrets> {
  changed ??= (async () => {
    const world = await operationWorld();
    const outcome = await changeSecrets({
      view: world.view,
      bundleId: BUNDLE_ID,
      keys: {
        // §25.1 "Re-wrap temporal": the same privates, extractable. §35.2 still holds them here.
        encryptionKey: world.created.keyset.encryption.privateKey,
        signingKey: world.created.keyset.signing.privateKey,
      },
      password: NEW_PASSWORD,
      // Only the password changes: the Account Secret Key in force travels through unchanged.
      secretKey: world.created.setupKit.accountSecretKey,
      kdfSalt: NEW_SALT,
      ports: world.ports,
    });
    if (!outcome.ok) throw new Error(`§35.6: ${outcome.failure.code} ${outcome.failure.message}`);
    return outcome.value;
  })();
  return changed;
}

describe("§35.6 the CHANGE_SECRETS bundle", () => {
  it("is accepted by §35.1.1 and carries only the profile and its signature", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const decision = await validateSecurityBundle(
      result.bundle,
      withScopes(world.state, ["ACCOUNT_SECURITY"]),
    );
    expect(decision.ok).toBe(true);
    if (!decision.ok || decision.value.kind !== "ACCEPT") return;

    expect(decision.value.accepted.configVersion).toBe(world.view.configVersion + 1);
    // §35.1.1's row: everything else is "—", and §35.1 says it rotates nothing.
    expect(result.bundle.root_transition).toBeUndefined();
    expect(result.bundle.registry).toBeUndefined();
    expect(result.bundle.epochs).toBeUndefined();
    expect(result.bundle.coverage_envelopes).toBeUndefined();
    expect(result.bundle.profile_signature).toBeDefined();
    // The root and registry in force are still the pending ones: nothing moved (§28.2 has no row).
    expect(decision.value.accepted.pendingRootGeneration).toBe(world.view.root.root_generation);
    expect(decision.value.accepted.pendingRegistryVersion).toBe(world.view.registry.registry_version);
    expect(result.pins.epochs.map((pin) => idKey(pin.epochId))).toEqual(
      world.view.vaults.map((vault) => idKey(vault.current!.epochId)),
    );
  });

  it("re-wraps the SAME account keys: the new secrets reach the keys the root names", async () => {
    const world = await operationWorld();
    const result = await passwordChange();

    const unlocked = await unlockForOperation({
      accountId: world.accountId,
      profile: result.profile,
      secrets: { password: NEW_PASSWORD, secretKey: world.created.setupKit.accountSecretKey },
      ports: world.ports,
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;

    // The Account Signing key is the one the *unchanged* root descriptor names (§28.2: no change).
    const context = selfTestContext(world.accountId, filled(16, 0x09));
    const signature = await signContext(unlocked.value.signingKey, context);
    const rootKey = await importVerifyingKey(world.view.root.account_signing_public_key);
    expect(await verifyContext(rootKey, context, signature)).toBe(true);

    // The Account Encryption key still opens an envelope sealed to it before the change (§35.6:
    // "No cambia claves ni rota epochs" — every epoch written under the old secrets stays readable).
    const epoch = world.created.epoch;
    const label = envelopeLabelContext(
      epoch.descriptor.vault_id,
      epoch.descriptor.epoch_id,
      world.account.recipientId,
      "ACCOUNT",
    );
    const secret = await openEpochSecret(
      unlocked.value.operationKey,
      label,
      envelopeFor(epoch.envelopes, world.account.recipientId).ciphertext,
    );
    const commitment = await deriveEpochCommitment(
      await importHkdfBase(secret),
      epoch.descriptor.vault_id,
      epoch.descriptor.epoch_id,
    );
    expect(timingSafeEqual(commitment, epoch.descriptor.epoch_commitment)).toBe(true);
  });

  it("leaves the old secrets unable to open the new profile", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const stale = await unlockSession({
      accountId: world.accountId,
      profile: result.profile,
      secrets: { password: "correct horse battery staple", secretKey: world.created.setupKit.accountSecretKey },
      ports: world.ports,
    });
    expect(stale.ok).toBe(false);
    if (stale.ok) return;
    expect(stale.failure.code).toBe("SECRETS_REJECTED");
  });

  it("opens the config under the new secrets, at the new config_version", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const unlocked = await unlockSession({
      accountId: world.accountId,
      profile: result.profile,
      secrets: { password: NEW_PASSWORD, secretKey: world.created.setupKit.accountSecretKey },
      ports: world.ports,
    });
    expect(unlocked.ok).toBe(true);
    if (!unlocked.ok) return;
    expect(unlocked.value.config.config_version).toBe(world.view.configVersion + 1);
    expect(unlocked.value.config.root_generation).toBe(world.view.root.root_generation);
  });

  it("changes the Account Secret Key only when asked to, and then produces a new Setup Kit", async () => {
    const world = await operationWorld();
    const kept = await passwordChange();
    expect(Array.from(kept.setupKit.accountSecretKey)).toEqual(
      Array.from(world.created.setupKit.accountSecretKey),
    );

    const rotated = await changeSecrets({
      view: world.view,
      bundleId: filled(16, 0x82),
      keys: {
        encryptionKey: world.created.keyset.encryption.privateKey,
        signingKey: world.created.keyset.signing.privateKey,
      },
      password: NEW_PASSWORD,
      secretKey: "GENERATE",
      kdfSalt: filled(16, 0x5d),
      ports: world.ports,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;
    expect(Array.from(rotated.value.setupKit.accountSecretKey)).not.toEqual(
      Array.from(world.created.setupKit.accountSecretKey),
    );
    expect(rotated.value.setupKit.accountSecretKeyText).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$/);
  });
});

describe("§35.6 broken variants", () => {
  it("is INVALID_SIGNATURE when the profile is signed over another config_version", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    // §35.6 step 6 signs the version **in force**. Signing the new one instead is exactly the
    // mistake that would let a profile prepared for one state be replayed onto another.
    const wrong = await signProfileUpdate(
      world.created.keyset.signing.privateKey,
      world.accountId,
      result.configVersion,
      result.profile,
    );
    const forged = assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.view),
      profile: result.profile,
      profileSignature: wrong,
    });
    const decision = await validateSecurityBundle(forged, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_SIGNATURE");
    expect(decision.failure.rule).toBe("profile-signature/invalid");
  });

  it("is INVALID_BUNDLE when the profile travels unsigned", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const unsigned = assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.view),
      profile: result.profile,
    });
    const decision = await validateSecurityBundle(unsigned, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("INVALID_BUNDLE");
    expect(decision.failure.rule).toBe("applicability/missing:profile_signature");
  });

  it("is INVALID_BUNDLE when it also changes something §35.6 may not", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    // §35.1's table: "Cambiar Encryption Password … Rota epoch: no", and §35.1.1 marks registry,
    // transition and epochs as "—" for CHANGE_SECRETS. A bundle that smuggles the registry in is
    // how a client would try to slip a recipient change past the scope rules of step 0.
    const nextValidRegistry = await signRegistry(
      await nextRegistry(world.view.registry, { revoke: [world.client.recipient.recipientId] }),
      world.created.keyset.signing.privateKey,
    );
    const withRegistry = assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.view),
      profile: result.profile,
      profileSignature: result.profileSignature,
      registry: nextValidRegistry,
    });
    const first = await validateSecurityBundle(withRegistry, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(first.ok).toBe(false);
    if (first.ok) return;
    expect(first.failure.code).toBe("INVALID_BUNDLE");
    expect(first.failure.rule).toBe("applicability/forbidden:registry");

    const withRotation = assembleBundle({
      operationType: "CHANGE_SECRETS",
      bundleId: BUNDLE_ID,
      expected: expectedOf(world.view),
      profile: result.profile,
      profileSignature: result.profileSignature,
      epochs: [],
    });
    const second = await validateSecurityBundle(withRotation, withScopes(world.state, ["ACCOUNT_SECURITY"]));
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.failure.rule).toBe("applicability/forbidden:epochs");
  });

  it("is SECURITY_STATE_STALE when the config moved between preparation and commit", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const moved = { ...withScopes(world.state, ["ACCOUNT_SECURITY"]), configVersion: world.view.configVersion + 1 };
    const decision = await validateSecurityBundle(result.bundle, moved);
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SECURITY_STATE_STALE");
    expect(decision.failure.retryable).toBe(true);
  });

  it("needs a scope §11.3 allows for CHANGE_SECRETS", async () => {
    const world = await operationWorld();
    const result = await passwordChange();
    const decision = await validateSecurityBundle(result.bundle, withScopes(world.state, ["VAULT_WRITE"]));
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.failure.code).toBe("SCOPE_REQUIRED");
  });
});
