/**
 * Minimal local type for Cloudflare Email Sending binding (env.EMAIL).
 * Matches the Cloudflare Workers Email Sending API (send_email binding).
 * Requires Workers Paid plan + verified sending domain.
 */
export interface CfEmailBinding {
  send(msg: { from: string; to: string; subject: string; text: string; html?: string }): Promise<{ messageId?: string }>;
}

// Environment bindings
export interface Env {
  DB: D1Database;
  NOTIFICATIONS_HUB: DurableObjectNamespace;
  ASSETS?: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
  // Prefer R2 when available. Optional to support KV-only deployments.
  ATTACHMENTS?: R2Bucket;
  // Optional fallback for attachment/send file storage (no credit card required).
  ATTACHMENTS_KV?: KVNamespace;
  JWT_SECRET: string;
  // Email 2FA (P2). At minimum MFA_EMAIL_FROM plus one sending backend must be set.
  // If absent, isEmailSenderConfigured() returns false and Email 2FA is silently omitted.
  MFA_EMAIL_FROM?: string;
  // Cloudflare Email Sending binding (default backend). Declared via [[send_email]] in wrangler.toml.
  EMAIL?: CfEmailBinding;
  // Generic HTTP email backend selection: 'cloudflare' | 'http' | 'auto' (default).
  MFA_EMAIL_PROVIDER?: string;
  // Generic HTTP endpoint for transactional email (any flat-JSON API).
  MFA_EMAIL_HTTP_ENDPOINT?: string;
  // Authorization header value for the HTTP endpoint (e.g. "Bearer <token>").
  MFA_EMAIL_HTTP_AUTH?: string;
  // Extra headers as JSON object string (merged with Authorization if set).
  MFA_EMAIL_HTTP_HEADERS?: string;
  // Extra body fields as JSON object string (added to every send request).
  MFA_EMAIL_HTTP_BODY?: string;
  // Set to "1", "true", or "yes" to send the 'to' field as an array (some APIs require this).
  MFA_EMAIL_HTTP_TO_ARRAY?: string;
  // JSON body template for APIs with nested structures (e.g. from:{email:"{{from}}"}).
  // When set, the flat-mode fields (MFA_EMAIL_HTTP_BODY / MFA_EMAIL_HTTP_TO_ARRAY / fieldMap)
  // are ignored and the template drives the entire request body.
  MFA_EMAIL_HTTP_BODY_TEMPLATE?: string;
}

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'banned';

// Sample JWT secret used by `.dev.vars.example`.
// If runtime JWT_SECRET equals this value, treat it as unsafe.
export const DEFAULT_DEV_SECRET = 'Enter-your-JWT-key-here-at-least-32-characters';

// Attachment model
export interface Attachment {
  id: string;
  cipherId: string;
  fileName: string;  // encrypted
  size: number;
  sizeName: string;
  key: string | null;  // encrypted attachment key
}

// User model
export interface User {
  id: string;
  email: string;
  name: string | null;
  masterPasswordHint: string | null;
  masterPasswordHash: string;
  key: string;
  privateKey: string | null;
  publicKey: string | null;
  kdfType: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  securityStamp: string;
  role: UserRole;
  status: UserStatus;
  verifyDevices?: boolean;
  totpSecret: string | null;
  /** Whether TOTP is actively enabled (separate from having a secret — allows reversible disable). */
  totpEnabled: boolean;
  totpRecoveryCode: string | null;
  /**
   * Replay protection: the counter value (floor(nowMs/30000) + delta) of the last
   * successfully verified TOTP code. A submitted code whose counter is ≤ this value
   * is rejected. NULL means no TOTP login has been recorded yet.
   */
  totpLastCounter: number | null;
  apiKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UserDomainSettings {
  userId: string;
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  excludedGlobalEquivalentDomains: number[];
  updatedAt: string | null;
}

export interface CustomEquivalentDomain {
  id: string;
  domains: string[];
  excluded: boolean;
}

export interface GlobalEquivalentDomain {
  type: number;
  domains: string[];
  excluded: boolean;
  [key: string]: unknown;
}

export interface DomainRulesResponse {
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  globalEquivalentDomains: GlobalEquivalentDomain[];
  object: 'domains';
}

export interface Invite {
  code: string;
  createdBy: string;
  usedBy: string | null;
  expiresAt: string;
  status: 'active' | 'used' | 'revoked' | 'expired';
  createdAt: string;
  updatedAt: string;
}

export interface AuditLog {
  id: string;
  actorUserId: string | null;
  actorEmail?: string | null;
  action: string;
  category: 'auth' | 'security' | 'device' | 'data' | 'system';
  level: 'info' | 'warn' | 'error' | 'security';
  targetType: string | null;
  targetId: string | null;
  targetUserEmail?: string | null;
  metadata: string | null;
  createdAt: string;
}

// Cipher types
export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
}

export interface CipherLoginUri {
  uri: string | null;
  uriChecksum: string | null;
  match: number | null;
}

export interface CipherLogin {
  username: string | null;
  password: string | null;
  uris: CipherLoginUri[] | null;
  totp: string | null;
  autofillOnPageLoad: boolean | null;
  fido2Credentials: any[] | null;
  uri: string | null;
  passwordRevisionDate: string | null;
}

export interface CipherCard {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}

export interface CipherSshKey {
  publicKey: string;
  privateKey: string;
  keyFingerprint: string;
}

export interface CipherIdentity {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
}

export interface CipherSecureNote {
  type: number;
}

export interface CipherField {
  name: string | null;
  value: string | null;
  type: number;
  linkedId: number | null;
}

export interface PasswordHistory {
  password: string;
  lastUsedDate: string;
}

export interface Cipher {
  id: string;
  userId: string;
  type: CipherType;
  folderId: string | null;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  key: string | null;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
  deletedAt: string | null;
  /** Allow unknown fields from Bitwarden clients to be stored and passed through transparently. */
  [key: string]: any;
}

// Folder model
export interface Folder {
  id: string;
  userId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface Device {
  userId: string;
  deviceIdentifier: string;
  name: string;
  deviceNote: string | null;
  type: number;
  sessionStamp: string;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
  devicePendingAuthRequest?: DevicePendingAuthRequest | null;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface DevicePendingAuthRequest {
  id: string;
  creationDate: string;
}

export interface DeviceResponse {
  id: string;
  userId?: string | null;
  name: string;
  systemName?: string | null;
  deviceNote?: string | null;
  identifier: string;
  type: number;
  creationDate: string;
  revisionDate: string;
  lastSeenAt?: string | null;
  hasStoredDevice?: boolean;
  isTrusted: boolean;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  devicePendingAuthRequest: DevicePendingAuthRequest | null;
  object: string;
  [key: string]: any;
}

export interface ProtectedDeviceResponse {
  id: string;
  name: string;
  identifier: string;
  type: number;
  creationDate: string;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  object: string;
  [key: string]: any;
}

export interface RefreshTokenRecord {
  userId: string;
  expiresAt: number;
  deviceIdentifier: string | null;
  deviceSessionStamp: string | null;
}

export interface TrustedDeviceTokenSummary {
  deviceIdentifier: string;
  expiresAt: number;
  tokenCount: number;
}

export enum SendType {
  Text = 0,
  File = 1,
}

export enum SendAuthType {
  Email = 0,
  Password = 1,
  None = 2,
}

export interface Send {
  id: string;
  userId: string;
  type: SendType;
  name: string;
  notes: string | null;
  data: string;
  key: string;
  passwordHash: string | null;
  passwordSalt: string | null;
  passwordIterations: number | null;
  authType: SendAuthType;
  emails: string | null;
  maxAccessCount: number | null;
  accessCount: number;
  disabled: boolean;
  hideEmail: boolean | null;
  createdAt: string;
  updatedAt: string;
  expirationDate: string | null;
  deletionDate: string;
}

export interface SendResponse {
  id: string;
  accessId: string;
  type: number;
  name: string;
  notes: string | null;
  text: any | null;
  file: any | null;
  key: string;
  maxAccessCount: number | null;
  accessCount: number;
  password: string | null;
  emails: string | null;
  authType: SendAuthType;
  disabled: boolean;
  hideEmail: boolean | null;
  revisionDate: string;
  expirationDate: string | null;
  deletionDate: string;
  object: string;
}

// JWT Payload
export interface JWTPayload {
  sub: string;      // user id
  email: string;
  name: string | null;
  email_verified: boolean; // required by mobile client
  amr: string[];    // authentication methods reference - required by mobile client
  sstamp: string;   // security stamp - invalidates token when user changes password
  did?: string;     // device identifier - invalidates per-device sessions
  dstamp?: string;  // device session stamp
  iat: number;
  exp: number;
  iss: string;
  premium: boolean;
}

// UserDecryptionOptions types for mobile client compatibility
export interface MasterPasswordUnlockKdf {
  KdfType: number;
  Iterations: number;
  Memory: number | null;
  Parallelism: number | null;
}

export interface MasterPasswordUnlock {
  Kdf: MasterPasswordUnlockKdf;
  MasterKeyEncryptedUserKey: string;
  MasterKeyWrappedUserKey: string;
  Salt: string;
  Object: string;
}

export interface UserDecryptionOptions {
  HasMasterPassword: boolean;
  Object: string;
  // Bitwarden Android 2026.1.x expects this to exist; missing it breaks unlock when the vault is empty.
  MasterPasswordUnlock: MasterPasswordUnlock;
  TrustedDeviceOption: null;
  KeyConnectorOption: null;
}

// API Response types
export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token?: string;
  web_session?: boolean;
  TwoFactorToken?: string;
  Key: string;
  PrivateKey: string | null;
  Kdf: number;
  KdfIterations: number;
  KdfMemory?: number;
  KdfParallelism?: number;
  ForcePasswordReset: boolean;
  ResetMasterPassword: boolean;
  scope: string;
  unofficialServer: boolean;
  MasterPasswordPolicy?: {
    Object: string;
  } | null;
  ApiUseKeyConnector?: boolean;
  AccountKeys?: any | null;
  accountKeys?: any | null;
  UserDecryptionOptions: UserDecryptionOptions;
  userDecryptionOptions?: UserDecryptionOptions;
  VaultKeys?: {
    symEncKey: string;
    symMacKey: string;
  };
}

export interface ProfileResponse {
  id: string;
  name: string | null;
  email: string;
  emailVerified: boolean;
  premium: boolean;
  premiumFromOrganization: boolean;
  usesKeyConnector: boolean;
  masterPasswordHint: string | null;
  culture: string;
  twoFactorEnabled: boolean;
  key: string;
  privateKey: string | null;
  accountKeys: any | null;
  securityStamp: string;
  organizations: any[];
  providers: any[];
  providerOrganizations: any[];
  forcePasswordReset: boolean;
  avatarColor: string | null;
  creationDate: string;
  verifyDevices?: boolean;
  role?: UserRole;
  status?: UserStatus;
  object: string;
}

export interface CipherResponse {
  id: string;
  organizationId: string | null;
  folderId: string | null;
  type: number;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  organizationUseTotp: boolean;
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
  edit: boolean;
  viewPassword: boolean;
  permissions: CipherPermissions | null;
  object: string;
  collectionIds: string[];
  attachments: any[] | null;
  key: string | null;
  encryptedFor: string | null;
  /** Allow unknown fields to pass through to clients transparently. */
  [key: string]: any;
}

export interface CipherPermissions {
  delete: boolean;
  restore: boolean;
}

export interface FolderResponse {
  id: string;
  name: string;
  revisionDate: string;
  creationDate: string;
  object: string;
}

export interface SyncResponse {
  profile: ProfileResponse;
  folders: FolderResponse[];
  collections: any[];
  ciphers: CipherResponse[];
  domains: any;
  policies: any[];
  sends: SendResponse[];
  UserDecryption?: {
    MasterPasswordUnlock: MasterPasswordUnlock | null;
    TrustedDeviceOption?: null;
    KeyConnectorOption?: null;
    WebAuthnPrfOption?: null;
    Object?: string;
  } | null;
  // PascalCase for desktop/browser clients
  UserDecryptionOptions: UserDecryptionOptions | null;
  // camelCase for Android client (SyncResponseJson uses @SerialName("userDecryption"))
  userDecryption: {
    masterPasswordUnlock: {
      kdf: {
        kdfType: number;
        iterations: number;
        memory: number | null;
        parallelism: number | null;
      };
      masterKeyWrappedUserKey: string;
      masterKeyEncryptedUserKey: string;
      salt: string;
    } | null;
  } | null;
  object: string;
}
