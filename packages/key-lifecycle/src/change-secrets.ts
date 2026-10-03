// §35.6: changing the Encryption Password, the Account Secret Key, or both.
//
// This is the only §35 operation that changes nothing anybody else can see. §35.1's table says it
// plainly — "re-envolver keyset y config", "Rota epoch: no" — and §28.2 agrees by not having a
// transition type for it: the Account Encryption and Account Signing key pairs are the *same*
// pairs afterwards, re-wrapped under a key derived from the new secrets. No root moves, no
// registry moves, no epoch rotates, and every envelope in the account keeps opening.
//
// Two things therefore carry the whole operation:
//
//   1. **The Re-wrap temporal handles (§25.1).** They are the only handles in Nodra that are
//      `extractable = true` on an *existing* private key, and they exist only here, so the two
//      PKCS#8 blobs can be produced again under the new `AccountKeyWrapKey`. `unlockForRewrap`
//      creates them; this module never unwraps anything itself.
//   2. **`profile_signature` (§35.6 step 6).** Without it, anyone holding only the account's login
//      could replace the wrapped keyset, the salt and the config with rubbish and lock the owner
//      out permanently. The signature is over the config_version **in force** — not the one the
//      new profile carries — so a profile prepared against an older state cannot be replayed onto
//      a newer one; the Worker checks exactly that in §35.1.1 step 7.9.
//
// Like every other builder here it enforces no §35.1.1 rule: `validateSecurityBundle` is the one
// place those live.
import { ARGON2_PARAMS_V1, KDF_SALT_BYTES } from "@nodra/crypto";
import type { Argon2Params, ExtractableEnvelopePrivateKey, ExtractableSigningKey } from "@nodra/crypto";
import { SECURITY_BUNDLE, encodeRecord } from "@nodra/encoding/records";
import type { AccountSecurityConfig, AccountSecurityProfile, SecurityBundle } from "@nodra/encoding/records";
import { ACCOUNT_SECRET_KEY_BYTES, formatAccountSecretKey } from "@nodra/encoding/secret-key";
import { assembleBundle, signProfileUpdate } from "./bundle-build.js";
import type { AccountView, ClientPins, OperationFailure } from "./client-state.js";
import { expectedOf, sealNextConfig } from "./client-state.js";
import { KeyLifecycleError } from "./errors.js";
import type { Outcome, UnlockFailure, UnlockFailureCode } from "./errors.js";
import { buildAccountSecurityProfile, wrapAccountPrivateKeys } from "./keyset.js";
import { defaultPorts } from "./ports.js";
import type { KeyLifecyclePorts } from "./ports.js";
import { checkKdfParams, deriveAccountKeys, resolveAccountSecretKey, toArgon2ParamsRecord } from "./secrets.js";
import type { AccountSecretKeyInput, DerivedAccountKeys } from "./secrets.js";

/** Whatever stopped §35.6: only the §24 secrets can reject it (§25 generates nothing here). */
export type ChangeSecretsFailureCode = UnlockFailureCode;

export type ChangeSecretsFailure = OperationFailure<ChangeSecretsFailureCode>;

/** §25.1's two "Re-wrap temporal" rows: the same privates, extractable, only for this operation. */
export interface RewrapHandles {
  readonly encryptionKey: ExtractableEnvelopePrivateKey;
  readonly signingKey: ExtractableSigningKey;
}

export interface ChangeSecretsRequest {
  /** The verified state in force (§26, §28.3, §29). Nothing in it changes but `config_version`. */
  readonly view: AccountView;
  readonly bundleId: Uint8Array;
  /** §35.6 step 1: Root Unlock with the **current** secrets, through `unlockForRewrap`. */
  readonly keys: RewrapHandles;
  /** The Encryption Password **after** the change: the new one, or the current one unchanged. */
  readonly password: string;
  /**
   * The Account Secret Key after the change. §35.1 has two rows here, and they differ only in this
   * argument, so it is explicit rather than optional: pass the Secret Key in force when only the
   * password changes, and `"GENERATE"` (or chosen bytes) when the Secret Key itself changes, which
   * is what produces a new Setup Kit. An omitted-means-generate default would silently invalidate
   * a user's Setup Kit on a plain password change.
   */
  readonly secretKey: AccountSecretKeyInput | "GENERATE";
  /** §24: a chance to move to stronger parameters. Defaults to ADR-004 profile 1. */
  readonly argon2Params?: Argon2Params;
  /** §35.6 step 2 generates one; supplied only by tests that need determinism. */
  readonly kdfSalt?: Uint8Array;
  readonly ports?: KeyLifecyclePorts;
}

export interface ChangedSecrets {
  readonly bundle: SecurityBundle;
  readonly serializedBundle: Uint8Array;
  /** §23.4 key 5: the new salt, parameters, re-wrapped keyset and sealed config, in one record. */
  readonly profile: AccountSecurityProfile;
  /** §35.6 step 6, over the config_version **in force** — the CAS that stops a replay. */
  readonly profileSignature: Uint8Array;
  readonly config: AccountSecurityConfig;
  readonly configVersion: number;
  readonly kdfSalt: Uint8Array;
  /**
   * The Account Secret Key now in force, and its Crockford form (§24). Shown as a new Setup Kit
   * only when it actually changed — the caller knows which of the two §35.1 rows it asked for.
   * The bytes are the caller's to zeroize when the operation ends (§24).
   */
  readonly setupKit: { readonly accountSecretKey: Uint8Array; readonly accountSecretKeyText: string };
  /** §24.1: alive only until this operation ends. Returned so the caller can finish and drop them. */
  readonly derived: DerivedAccountKeys;
  /** §26: root, registry and every epoch pin unchanged; only `configVersion` moves. */
  readonly pins: ClientPins;
}

function failed(step: number, failure: UnlockFailure): Outcome<never, ChangeSecretsFailure> {
  return { ok: false, failure: { code: failure.code, step, message: failure.message } };
}

/**
 * §35.6 steps 2–6, returning what steps 7–8 need. The handles of step 1 arrive as an argument and
 * the discarding of step 7 belongs to the caller: only it knows when its operation is over.
 */
export async function changeSecrets(
  request: ChangeSecretsRequest,
): Promise<Outcome<ChangedSecrets, ChangeSecretsFailure>> {
  const ports = request.ports ?? defaultPorts;
  const view = request.view;

  // Step 2: a fresh salt, and the two §24 keys derived from the secrets that will be in force.
  const params = checkKdfParams(request.argon2Params ?? ARGON2_PARAMS_V1);
  if (!params.ok) return failed(2, params.failure);
  const secretKey =
    request.secretKey === "GENERATE"
      ? { ok: true as const, value: ports.randomBytes(ACCOUNT_SECRET_KEY_BYTES) }
      : resolveAccountSecretKey(request.secretKey);
  if (!secretKey.ok) return failed(2, secretKey.failure);
  const kdfSalt = request.kdfSalt ?? ports.randomBytes(KDF_SALT_BYTES);
  if (kdfSalt.length !== KDF_SALT_BYTES) {
    throw new KeyLifecycleError(`kdf_salt must be ${KDF_SALT_BYTES} bytes, got ${kdfSalt.length}`);
  }
  const derived = await deriveAccountKeys(secretKey.value, request.password, kdfSalt, params.value, ports);

  // Steps 3–4: the *same* two privates, wrapped again under the new AccountKeyWrapKey (§25).
  const wrapped = await wrapAccountPrivateKeys(derived.keyWrapKey, view.accountId, {
    encryption: request.keys.encryptionKey,
    signing: request.keys.signingKey,
  });

  // Step 5: the config, rewritten under the new AccountConfigKey. Same root, same registry (§26).
  const sealed = await sealNextConfig(derived.configKey, {
    root: view.root,
    rootHash: view.rootHash,
    genesisRootHash: view.genesisRootHash,
    registryVersion: view.registry.registry_version,
    registryHash: view.registryHash,
    configVersion: view.configVersion + 1,
  });

  // Step 6: the profile, signed with the Re-wrap Account Signing handle over the version in force.
  const profile = buildAccountSecurityProfile({
    accountId: view.accountId,
    kdfSalt,
    argon2Params: toArgon2ParamsRecord(params.value),
    wrappedEncryptionKey: wrapped.encryption,
    wrappedSigningKey: wrapped.signing,
    configVersion: sealed.configVersion,
    configBlob: sealed.blob,
  });
  const profileSignature = await signProfileUpdate(
    request.keys.signingKey,
    view.accountId,
    view.configVersion,
    profile,
  );

  const bundle = assembleBundle({
    operationType: "CHANGE_SECRETS",
    bundleId: request.bundleId,
    expected: expectedOf(view),
    profile,
    profileSignature,
  });

  return {
    ok: true,
    value: {
      bundle,
      serializedBundle: encodeRecord(SECURITY_BUNDLE, bundle),
      profile,
      profileSignature,
      config: sealed.config,
      configVersion: sealed.configVersion,
      kdfSalt,
      setupKit: {
        accountSecretKey: secretKey.value,
        accountSecretKeyText: formatAccountSecretKey(secretKey.value),
      },
      derived,
      pins: {
        rootGeneration: view.root.root_generation,
        rootHash: view.rootHash,
        genesisRootHash: view.genesisRootHash,
        registryVersion: view.registry.registry_version,
        registryHash: view.registryHash,
        configVersion: sealed.configVersion,
        // §35.6 rotates nothing, so every vault keeps the epoch pin it had.
        epochs: view.vaults.flatMap((vault) =>
          vault.current === null
            ? []
            : [{ vaultId: vault.vaultId, epochId: vault.current.epochId, descriptorHash: vault.current.descriptorHash }],
        ),
      },
    },
  };
}
