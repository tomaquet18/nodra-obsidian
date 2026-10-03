// `@nodra/key-lifecycle` — §24 two-secret unlock, §25 Account Root Keyset, and as much of §26 as
// those two need. Pure domain plus two ports; no network, no IndexedDB, no DOM.
//
// It also owns the root chain (§28) and the Recipient Registry (§29): building and signing them,
// and the two replays that turn a chain of transitions or registry versions into the state in
// force, or into a typed rejection.
//
// It owns the Recovery Kit too (§27): the document, its obligatory self-test, and the two handles
// a §35 recovery operation reads out of it.
//
// It owns epochs too (§31–§34): creating one with its envelopes, verifying a vault's descriptor
// chain, opening an envelope under the §32.3 rules, deriving the §31.2 keys, and the coverage rule
// of §34.
//
// It owns the §35.1.1 `SecurityBundle` validation too, plus the per-operation applicability table
// it reads and the two client-side signatures a bundle needs (§35.6, §35.11/§35.12).
//
// It owns privileged re-enveloping (§33.2) and the client half of the §35 operations that are not
// deletions: account creation (§35.2), the key pair a new client generates (§35.3/§35.4),
// enrollment with its coverage (§35.4), revocation with its rotation (§35.5), the secret change of
// §35.6, the reset of §35.7, the re-enrollment plan of §35.8 and the kit replacement of §35.9.
//
// Deliberately **not** here (later slices): §35.10–§35.12 and §36 as an operation. `NOTES.md`
// lists what each of them will need from this package.

export { KeyLifecycleError, SECRETS_REJECTED_MESSAGE } from "./errors.js";
export type { Outcome, Result, UnlockFailure, UnlockFailureCode } from "./errors.js";

export {
  CHANGED_KEYS,
  REQUIRED_SIGNER_ROLES,
  genesisDescriptor,
  modeAfter,
  nextDescriptor,
  rootHash,
  signRootTransition,
  verifyRootChain,
} from "./root-chain.js";
export type {
  ProtectionMode,
  RootChainFailure,
  RootChainFailureCode,
  RootChainLink,
  RootPin,
  RootPublicKeys,
  RootState,
  SignRootTransitionRequest,
  SignerRole,
  TransitionType,
  UnsignedRootTransition,
  VerifyRootChainOptions,
} from "./root-chain.js";

export {
  activeRecipients,
  compareRecipientIds,
  initialRegistry,
  nextRegistry,
  registryHash,
  signRegistry,
  verifyRegistryChain,
} from "./registry.js";
export type {
  NewRecipient,
  RecipientType,
  RegistryChange,
  RegistryFailure,
  RegistryFailureCode,
  RegistryPin,
  RegistryState,
  UnsignedRegistry,
  VerifyRegistryChainOptions,
} from "./registry.js";

export {
  ENVELOPE_ALGORITHM_VERSION,
  EPOCH_COMMITMENT_BITS,
  RECIPIENT_ID_BYTES,
  createEpoch,
  deriveContentKey,
  deriveDedupKey,
  deriveEpochCommitment,
  deriveManifestKey,
  envelopeSetHash,
  epochDescriptorHash,
  epochRecipients,
  idKey,
  openEpoch,
  rootRecipientId,
  rootRecipients,
  sealEnvelope,
  signEpochDescriptor,
} from "./epoch.js";
export type {
  CreateEpochRequest,
  CreatedEpoch,
  EnvelopeRecipient,
  EnvelopeRecipientType,
  EpochKey,
  EpochOpenFailure,
  EpochOpenFailureCode,
  OpenEpochRequest,
  PreviousEpoch,
  RecipientIdentity,
} from "./epoch.js";

export {
  contentFingerprint,
  openContentBlob,
  openManifestBlob,
  sealContentBlob,
  sealManifestBlob,
} from "./blob.js";
export type { ManifestBinding } from "./blob.js";

export { verifyEpochChain } from "./epoch-chain.js";
export type {
  EpochChainFailure,
  EpochChainFailureCode,
  EpochChainState,
  EpochPin,
  VerifyEpochChainOptions,
} from "./epoch-chain.js";

export { belongsToRequiredVaults, checkCoverage, requiredEpochSet } from "./coverage.js";
export type {
  CoverageFailure,
  CoverageGap,
  CoverageGapCode,
  CoverageRequest,
  CoverageResult,
  EpochState,
  ListedEpoch,
  RequiredEpoch,
  VaultEpochs,
  VaultState,
} from "./coverage.js";

export {
  OPERATION_RULES,
  RECOVERY_RECORD_SIGNERS,
  forbiddenFields,
  isRecoveryRecordOperation,
  operationRules,
  requiredFields,
  vetoRole,
} from "./operations.js";
export type {
  ConfigRequirement,
  CoverageRequirement,
  DeletionPrecondition,
  DeletionRequirement,
  EpochsRequirement,
  EscrowRequirement,
  OperationRules,
  OperationType,
  RecoveryRecordOperation,
  RecoveryRequestKind,
  RegistryShape,
  Scope,
  TransitionRequirement,
} from "./operations.js";

export { BUNDLE_STEPS, REAUTH_WINDOW_SECONDS, currentArgon2Version, validateSecurityBundle } from "./bundle.js";
export type {
  AcceptedBundle,
  AccountState,
  BundleAuthorization,
  BundleDecision,
  BundleFailure,
  BundleFailureCode,
  BundleOutcome,
  BundleState,
  BundleStep,
  BundleVault,
  EscrowChange,
  RecoveryChange,
  StoredBundleResult,
  WriteCapability,
} from "./bundle.js";

export { assembleBundle, signDeletion, signProfileUpdate, signRecoveryRecord } from "./bundle-build.js";
export type { BundleParts, DeletionRequest, RecoveryRecordRequest } from "./bundle-build.js";

export { isLive, isMature, recoveryRequestPhase } from "./recovery-request-state.js";
export type { RecoveryRequestPhase, RecoveryRequestState, StoredRecoveryRequest } from "./recovery-request-state.js";

export { cancelRecovery, requestRecovery, verifyRecoveryRequest, vetoRecovery } from "./recovery-request.js";
export type {
  BuiltRecoveryRecord,
  PendingRecoveryRequest,
  RecoveryRecordBundleRequest,
  RecoveryRecordView,
} from "./recovery-request.js";

export { buildCoverage, proveEnvelope, reEnvelope } from "./re-envelope.js";
export type {
  BuildCoverageRequest,
  EnvelopeProver,
  EnvelopeSource,
  ReEnvelopeFailure,
  ReEnvelopeFailureCode,
  ReEnvelopeRequest,
} from "./re-envelope.js";

export { buildAccountConfig, expectedOf, sealNextConfig } from "./client-state.js";
export type {
  AccountConfigRequest,
  AccountView,
  ClientPins,
  ClientVault,
  OperationFailure,
  OperationKeys,
  SealedAccountConfig,
  SigningKeys,
  VaultEpochPin,
} from "./client-state.js";

export { createAccount, createManagedAccount } from "./account-creation.js";
export type {
  AssembledAccount,
  CreateAccountBase,
  CreateAccountFailure,
  CreateAccountFailureCode,
  CreateAccountRequest,
  CreateManagedAccountRequest,
  CreatedAccount,
  CreatedManagedAccount,
} from "./account-creation.js";

export { enrollClient, planReEnrollment, prepareEnrollment } from "./enrollment.js";
export type {
  EnrollClientFailure,
  EnrollClientFailureCode,
  EnrollClientRequest,
  EnrolledClient,
  EnrollmentKeys,
  PrepareEnrollmentRequest,
  ReEnrollmentFailure,
  ReEnrollmentFailureCode,
  ReEnrollmentPlan,
  ReEnrollmentRequest,
  RetainedState,
} from "./enrollment.js";

export { revokeClient } from "./revocation.js";
export type { RevokeClientRequest, RevokedClient } from "./revocation.js";

export { createVault } from "./vault-creation.js";
export type { CreateVaultRequest, CreatedVault } from "./vault-creation.js";

export {
  buildAccountDeletion,
  buildVaultDeletion,
  cancelDeleteAccount,
  cancelDeleteVault,
  deleteAccount,
  deleteVault,
  operationsAllowedWhileAccountDeleting,
} from "./deletion.js";
export type {
  AccountDeletionEffects,
  AccountDeletionRequest,
  AccountDeletionType,
  DeletionKeys,
  ScheduledAccountDeletion,
  ScheduledVaultDeletion,
  VaultDeletionEffects,
  VaultDeletionRequest,
  VaultDeletionType,
} from "./deletion.js";

export { liveVaults, rotateLiveVaults } from "./rotation.js";
export type { RotateLiveVaultsRequest, Rotation } from "./rotation.js";

export { changeSecrets } from "./change-secrets.js";
export type {
  ChangeSecretsFailure,
  ChangeSecretsFailureCode,
  ChangeSecretsRequest,
  ChangedSecrets,
  RewrapHandles,
} from "./change-secrets.js";

export { recoveryReset } from "./recovery-reset.js";
export type {
  ManagedRecoveryResetRequest,
  PrivateRecoveryResetRequest,
  RecoveryReset,
  RecoveryResetFailure,
  RecoveryResetFailureCode,
  RecoveryResetRequest,
} from "./recovery-reset.js";

export { switchToPrivate } from "./switch-to-private.js";
export type {
  SwitchToPrivateFailure,
  SwitchToPrivateFailureCode,
  SwitchToPrivateRequest,
  SwitchedToPrivate,
} from "./switch-to-private.js";

export { switchToManaged } from "./switch-to-managed.js";
export type {
  SwitchToManagedFailure,
  SwitchToManagedFailureCode,
  SwitchToManagedRequest,
  SwitchedToManaged,
} from "./switch-to-managed.js";

export { replaceRecoveryKit } from "./kit-replacement.js";
export type {
  ReplaceRecoveryKitFailure,
  ReplaceRecoveryKitFailureCode,
  ReplaceRecoveryKitRequest,
  ReplacedRecoveryKit,
} from "./kit-replacement.js";

export {
  CAPABILITY_CHALLENGE_BYTES,
  CAPABILITY_CHALLENGE_SECONDS,
  CAPABILITY_NONCE_BYTES,
  CAPABILITY_SCOPES,
  CAPABILITY_TOKEN_SECONDS,
  capabilityProofMatches,
  capabilityReplicaBinding,
  expectedCapabilityProof,
  issueCapabilityChallenge,
  proveCapabilityWithDecryptKey,
  proveCapabilityWithUnwrapKey,
  writeCapabilityLabel,
  writeCapabilityProofContext,
} from "./write-capability.js";
export type { CapabilityChallenge, CapabilityRecipientType, ReplicaBinding } from "./write-capability.js";

export { defaultPorts } from "./ports.js";
export type { KeyLifecyclePorts } from "./ports.js";

export {
  ACCOUNT_CONFIG_INFO,
  ACCOUNT_KEYWRAP_INFO,
  DEDUP_KEY_INFO,
  accountConfigAad,
  accountPrivateKeyAad,
  contentKeyInfo,
  envelopeLabelContext,
  deleteAccountContext,
  deleteVaultContext,
  envelopeSetContext,
  epochCommitmentInfo,
  epochDescriptorContext,
  manifestKeyInfo,
  profileHash,
  profileUpdateContext,
  recoveryKitContext,
  registryContext,
  rootDescriptorContext,
  rootTransitionContext,
  selfTestContext,
} from "./contexts.js";
export type { EnvelopeSetEntry } from "./contexts.js";

export {
  SELF_TEST_NONCE_BYTES,
  SELF_TEST_SECRET_BYTES,
  createRecoveryKit,
  escrowedRecoveryKeysOf,
  generateRecoveryKeyPairs,
  openEscrowedRecoveryKeys,
  openRecoveryKit,
  parseRecoveryKit,
  recoveryRootKeys,
  selfTestEscrowedRecoveryKeys,
  selfTestRecoveryKit,
  serializeEscrowedRecoveryKeys,
  serializeRecoveryKit,
  verifyRecoveryKit,
} from "./recovery-kit.js";
export type {
  CreateRecoveryKitRequest,
  CreatedRecoveryKit,
  RecoveryHandles,
  RecoveryKeyMaterial,
  RecoveryKeyPairs,
  RecoveryKitCheckRequest,
  RecoveryKitFailure,
  RecoveryKitFailureCode,
  RecoveryKitProof,
  RecoveryKitScope,
} from "./recovery-kit.js";

export { buildEscrowBlob, openEscrowRewrap, rewrapEscrowSlot } from "./escrow.js";
export type {
  BuildEscrowBlobRequest,
  EscrowFailure,
  EscrowFailureCode,
  EscrowKeyStore,
  EscrowPublicKey,
  OpenEscrowRewrapRequest,
  OpenedEscrow,
  RewrapEscrowSlotRequest,
  RewrappedSlot,
} from "./escrow.js";

export {
  checkKdfParams,
  deriveAccountKeys,
  deriveManagedAccountKeys,
  ROOT_UNLOCK_KEY_BYTES,
  resolveAccountSecretKey,
  toArgon2Params,
  toArgon2ParamsRecord,
} from "./secrets.js";
export type { AccountSecretKeyInput, AccountSecrets, DerivedAccountKeys, RootUnlockKeySource } from "./secrets.js";

export {
  CRYPTO_VERSIONS,
  isSupportedCryptoVersion,
  openAccountSecurityConfig,
  parseAccountSecurityProfile,
  unlockForOperation,
  unlockForRewrap,
  unlockSession,
} from "./unlock.js";
export type {
  CryptoVersion,
  OperationUnlock,
  RewrapUnlock,
  SessionUnlock,
  UnlockRequest,
  UnlockedAccount,
} from "./unlock.js";

export {
  buildAccountSecurityProfile,
  createAccountRootKeyset,
  createManagedAccountKeyset,
  sealAccountSecurityConfig,
  wrapAccountPrivateKeys,
} from "./keyset.js";
export type {
  AccountKeyMaterial,
  AccountKeyset,
  AccountSecurityProfileParts,
  CreateAccountRootKeysetRequest,
  CreatedAccountRootKeyset,
  CreatedManagedKeyset,
} from "./keyset.js";
