import { Env, User, ProfileResponse, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent, safeWriteAuditEvent } from '../services/audit-events';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import { createRecoveryCode, hashRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { buildAccountKeys } from '../utils/user-decryption';
import {
  getTwoFactor,
  upsertTwoFactor,
  deleteTwoFactor,
} from '../services/storage-two-factor-repo';
import {
  EMAIL_ENROLLMENT_ATYPE,
  EMAIL_LOGIN_CHALLENGE_ATYPE,
  generateNumericCode,
  maskEmail,
  CODE_TTL_S,
} from '../services/two-factor/email-provider';
import { buildEmailSenderFromEnv } from '../services/email-sender';

// CONTRACT:
// users.master_password_hash is server-side login verification only. It does
// not decrypt vault data. Password changes must keep encrypted user key material,
// securityStamp, refresh-token invalidation, and client compatibility together.
// Password hints are non-secret reminders; never treat them as recovery secrets.
function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

/**
 * Validate KDF parameters according to Bitwarden minimum requirements.
 * Returns an error message if invalid, or null if OK.
 */
function validateKdfParams(kdfType: number | undefined, kdfIterations: number | undefined, kdfMemory?: number | undefined, kdfParallelism?: number | undefined): string | null {
  const type = kdfType ?? 0;
  if (type === 0) {
    // PBKDF2-SHA256: minimum 100 000 iterations
    if (typeof kdfIterations === 'number' && kdfIterations < 100_000) {
      return 'PBKDF2 iterations must be at least 100000';
    }
  } else if (type === 1) {
    // Argon2id: iterations >= 2, memory >= 16 MiB, parallelism >= 1
    if (typeof kdfIterations === 'number' && kdfIterations < 2) {
      return 'Argon2id iterations must be at least 2';
    }
    if (typeof kdfMemory === 'number' && kdfMemory < 16) {
      return 'Argon2id memory must be at least 16 MiB';
    }
    if (typeof kdfParallelism === 'number' && kdfParallelism < 1) {
      return 'Argon2id parallelism must be at least 1';
    }
  }
  return null;
}

function normalizeTotpSecret(input: string): string {
  const raw = String(input || '').toUpperCase();
  let out = '';
  for (const char of raw) {
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === '-') continue;
    out += char;
  }
  while (out.endsWith('=')) {
    out = out.slice(0, -1);
  }
  return out;
}

function normalizeRecoveryCodeInput(input: string): string {
  return String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function normalizeMasterPasswordHint(input: string | null | undefined): string | null {
  const normalized = String(input || '').trim();
  return normalized ? normalized : null;
}

function jwtSecretUnsafeReason(env: Env): 'missing' | 'default' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

async function verifyUserSecret(
  auth: AuthService,
  user: User,
  secret: string | null | undefined
): Promise<boolean> {
  const normalized = String(secret || '').trim();
  if (!normalized) return false;
  return auth.verifyPassword(normalized, user.masterPasswordHash, user.email);
}

function toProfile(user: User, env: Env, twoFactorRows: import('../services/storage-two-factor-repo').TwoFactorRow[] = []): ProfileResponse {
  void env;
  const accountKeys = buildAccountKeys(user);
  // C3: twoFactorEnabled reflects any active provider, not just TOTP.
  const twoFactorEnabled =
    (!!user.totpSecret && user.totpEnabled !== false) ||
    twoFactorRows.some(r => r.enabled && r.atype < 1000);
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    verifyDevices: user.verifyDevices,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    const message = unsafe === 'missing'
      ? 'JWT_SECRET is not set'
      : unsafe === 'default'
        ? 'JWT_SECRET is using the default/sample value. Please change it.'
        : 'JWT_SECRET must be at least 32 characters';
    return errorResponse(message, 400);
  }

  let body: {
    email?: string;
    name?: string;
    masterPasswordHash?: string;
    key?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
    inviteCode?: string;
    masterPasswordHint?: string;
    keys?: {
      publicKey?: string;
      encryptedPrivateKey?: string;
    };
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase().trim();
  const name = body.name?.trim() || email;
  const masterPasswordHash = body.masterPasswordHash;
  const key = body.key;
  const privateKey = body.keys?.encryptedPrivateKey;
  const publicKey = body.keys?.publicKey;
  const inviteCode = (body.inviteCode || '').trim();
  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);

  if (!email || !masterPasswordHash || !key) {
    return errorResponse('Email, masterPasswordHash, and key are required', 400);
  }
  if (!email.includes('@') || email.length < 3) {
    return errorResponse('Invalid email address', 400);
  }
  if (!privateKey || !publicKey) {
    return errorResponse('Private key and public key are required', 400);
  }
  if (!looksLikeEncString(key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  const kdfErr = validateKdfParams(body.kdf, body.kdfIterations, body.kdfMemory, body.kdfParallelism);
  if (kdfErr) return errorResponse(kdfErr, 400);

  const now = new Date().toISOString();
  const auth = new AuthService(env);
  const serverHash = await auth.hashPasswordServer(masterPasswordHash, email);

  const user: User = {
    id: generateUUID(),
    email,
    name: name || email,
    masterPasswordHint,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: body.kdf ?? 0,
    kdfIterations: body.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: body.kdfMemory,
    kdfParallelism: body.kdfParallelism,
    securityStamp: generateUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: true,
    totpSecret: null,
    totpEnabled: true,
    totpRecoveryCode: null,
    totpLastCounter: null,
    apiKey: null,
    createdAt: now,
    updatedAt: now,
  };

  const userCount = await storage.getUserCount();
  if (userCount === 0) {
    user.role = 'admin';
    const created = await storage.createFirstUser(user);
    if (!created) {
      return errorResponse('Registration is temporarily unavailable, retry once', 409);
    }
    await storage.setRegistered();
    await writeAuditEvent(storage, {
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      category: 'security',
      level: 'security',
      metadata: { email: user.email, ...auditRequestMetadata(request) },
    });
    return jsonResponse({ success: true, role: user.role }, 200);
  }

  if (!inviteCode) {
    return errorResponse('Invite code is required', 403);
  }

  try {
    await storage.createUser(user);
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    throw error;
  }

  const inviteMarked = await storage.markInviteUsed(inviteCode, user.id);
  if (!inviteMarked) {
    await storage.deleteUserById(user.id);
    return errorResponse('Invite code is invalid or expired', 403);
  }

  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'user.register.invite',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'info',
    metadata: { email: user.email, inviteCode, ...auditRequestMetadata(request) },
  });

  return jsonResponse({ success: true, role: user.role }, 200);
}

// POST /api/accounts/password-hint
export async function handleGetPasswordHint(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const rateLimit = new RateLimitService(env.DB);
  const minuteBudget = await rateLimit.consumeBudgetWithWindow(
    `${clientIdentifier}:password-hint`,
    LIMITS.rateLimit.passwordHintRequestsPerMinute,
    60
  );
  if (!minuteBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${minuteBudget.retryAfterSeconds || 60} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(minuteBudget.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const hourlyBudget = await rateLimit.consumeBudgetWithWindow(
    `${clientIdentifier}:password-hint-hour`,
    LIMITS.rateLimit.passwordHintRequestsPerHour,
    60 * 60
  );
  if (!hourlyBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${hourlyBudget.retryAfterSeconds || 3600} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(hourlyBudget.retryAfterSeconds || 3600),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const user = await storage.getUser(email);
  const hint = user?.status === 'active' ? normalizeMasterPasswordHint(user.masterPasswordHint) : null;
  return jsonResponse({
    object: 'passwordHint',
    hasHint: !!hint,
    masterPasswordHint: hint,
  });
}

// GET /api/accounts/profile
export async function handleGetProfile(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const [user, twoFactorRows] = await Promise.all([
    storage.getUserById(userId),
    storage.getTwoFactorsByUserId(userId),
  ]);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(toProfile(user, env, twoFactorRows));
}

// PUT /api/accounts/profile
export async function handleUpdateProfile(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const [user, twoFactorRows] = await Promise.all([
    storage.getUserById(userId),
    storage.getTwoFactorsByUserId(userId),
  ]);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHint?: string | null;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  user.masterPasswordHint = masterPasswordHint;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.profile.update',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedMasterPasswordHint: true,
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(toProfile(user, env, twoFactorRows));
}

// PUT/POST /api/accounts/verify-devices
export async function handleSetVerifyDevices(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    secret?: string;
    masterPasswordHash?: string;
    verifyDevices?: boolean;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (typeof body.verifyDevices !== 'boolean') {
    return errorResponse('verifyDevices must be true or false', 400);
  }

  const verified = await verifyUserSecret(auth, user, body.secret || body.masterPasswordHash);
  if (!verified) {
    return errorResponse('User verification failed.', 400);
  }

  user.verifyDevices = body.verifyDevices;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.verify_devices.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      verifyDevices: user.verifyDevices,
      ...auditRequestMetadata(request),
    },
  });

  return new Response(null, { status: 200 });
}

// POST /api/accounts/keys
export async function handleSetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: {
    masterPasswordHash?: string;
    key?: string;
    encryptedPrivateKey?: string;
    publicKey?: string;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const passwordValid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  user.updatedAt = new Date().toISOString();

  await storage.saveUser(user);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.keys.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedKey: !!body.key,
      updatedPrivateKey: !!body.encryptedPrivateKey,
      updatedPublicKey: !!body.publicKey,
      ...auditRequestMetadata(request),
    },
  });

  return handleGetProfile(request, env, userId);
}

// POST/PUT /api/accounts/password
export async function handleChangePassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHash?: string;
    currentPasswordHash?: string;
    newMasterPasswordHash?: string;
    key?: string;
    newKey?: string;
    encryptedPrivateKey?: string;
    newEncryptedPrivateKey?: string;
    publicKey?: string;
    newPublicKey?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse('Current password hash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!body.newMasterPasswordHash) {
    return errorResponse('newMasterPasswordHash is required', 400);
  }
  const nextKey = body.newKey || body.key;
  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (nextKey && !looksLikeEncString(nextKey)) {
    return errorResponse('new key is not a valid encrypted string', 400);
  }
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse('new encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const kdfErr = validateKdfParams(body.kdf ?? user.kdfType, body.kdfIterations, body.kdfMemory, body.kdfParallelism);
  if (kdfErr) return errorResponse(kdfErr, 400);

  user.masterPasswordHash = await auth.hashPasswordServer(body.newMasterPasswordHash, user.email);
  if (nextKey) user.key = nextKey;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (typeof body.kdf === 'number') user.kdfType = body.kdf;
  if (typeof body.kdfIterations === 'number') user.kdfIterations = body.kdfIterations;
  if (typeof body.kdfMemory === 'number') user.kdfMemory = body.kdfMemory;
  if (typeof body.kdfParallelism === 'number') user.kdfParallelism = body.kdfParallelism;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'user.password.change',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'security',
    metadata: { email: user.email, ...auditRequestMetadata(request) },
  });

  return new Response(null, { status: 200 });
}

// GET /api/accounts/totp
export async function handleGetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const configured = isTotpEnabled(user.totpSecret);
  return jsonResponse({
    // enabled = actively requires TOTP on login (secret exists AND flag is on)
    enabled: configured && user.totpEnabled !== false,
    // configured = secret is stored (re-enable path exists without re-scanning QR)
    configured,
    object: 'twoFactor',
  });
}

// PUT /api/accounts/totp
// Initial setup:  { enabled: true, secret: "...", token: "123456" }
// Re-enable:      { enabled: true, masterPasswordHash: "..." }  (no secret/token — uses retained secret)
// Disable:        { enabled: false, masterPasswordHash: "..." }  (preserves secret, just marks disabled)
export async function handleSetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { enabled?: boolean; secret?: string; token?: string; masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.enabled === true) {
    const hasSecret = !!(body.secret && normalizeTotpSecret(body.secret));
    const hasToken = !!body.token;

    if (hasSecret) {
      // --- Initial setup path: new secret + token verification ---
      const normalizedSecret = normalizeTotpSecret(body.secret || '');
      if (!isTotpEnabled(normalizedSecret)) {
        return errorResponse('Invalid TOTP secret', 400);
      }
      if (!hasToken) {
        return errorResponse('TOTP token is required', 400);
      }
      const verified = await verifyTotpToken(normalizedSecret, body.token!);
      if (!verified) {
        return errorResponse('Invalid TOTP token', 400);
      }
      user.totpSecret = normalizedSecret;
      user.totpEnabled = true;
      if (!user.totpRecoveryCode) {
        // H4: Store hash, not plaintext. The code was previously shown to the user
        // at TOTP-setup initiation; no need to re-display here.
        user.totpRecoveryCode = await hashRecoveryCode(createRecoveryCode());
      }
      user.updatedAt = new Date().toISOString();
      await storage.saveUser(user);
      await storage.deleteRefreshTokensByUserId(user.id);
      AuthService.invalidateUserCache(user.id);
      await writeAuditEvent(storage, {
        actorUserId: user.id,
        action: 'account.totp.enable',
        category: 'security',
        level: 'security',
        targetType: 'user',
        targetId: user.id,
        metadata: auditRequestMetadata(request),
      });
      return jsonResponse({ enabled: true, recoveryCode: user.totpRecoveryCode, object: 'twoFactor' });
    }

    // --- Re-enable path: no new secret, just restore the existing one ---
    if (!isTotpEnabled(user.totpSecret)) {
      return errorResponse('TOTP is not configured. Please set up TOTP first by providing a secret and token.', 400);
    }
    if (!body.masterPasswordHash) {
      return errorResponse('masterPasswordHash is required to re-enable TOTP', 400);
    }
    const validReEnable = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
    if (!validReEnable) return errorResponse('Invalid password', 400);

    user.totpEnabled = true;
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    AuthService.invalidateUserCache(user.id);
    await writeAuditEvent(storage, {
      actorUserId: user.id,
      action: 'account.totp.reenable',
      category: 'security',
      level: 'security',
      targetType: 'user',
      targetId: user.id,
      metadata: auditRequestMetadata(request),
    });
    return jsonResponse({ enabled: true, object: 'twoFactor' });
  }

  if (body.enabled === false) {
    if (!body.masterPasswordHash) {
      return errorResponse('masterPasswordHash is required to disable TOTP', 400);
    }
    const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
    if (!valid) return errorResponse('Invalid password', 400);

    // Reversible disable: preserve secret, only flip the enabled flag.
    // The user can re-enable without re-scanning the QR code.
    user.totpEnabled = false;
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    AuthService.invalidateUserCache(user.id);
    await writeAuditEvent(storage, {
      actorUserId: user.id,
      action: 'account.totp.disable',
      category: 'security',
      level: 'security',
      targetType: 'user',
      targetId: user.id,
      metadata: auditRequestMetadata(request),
    });
    // configured=true signals the front-end that re-enable is available without re-scan.
    return jsonResponse({ enabled: false, configured: isTotpEnabled(user.totpSecret), object: 'twoFactor' });
  }

  return errorResponse('enabled must be true or false', 400);
}

// POST /api/accounts/totp/recovery-code
export async function handleGetTotpRecoveryCode(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = String(body.masterPasswordHash || body.master_password_hash || body.password || '').trim();
  if (!currentHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!user.totpRecoveryCode) {
    // H4: First-time generation — create a new code, show plaintext to user once,
    // store only the SHA-256 hash. The plaintext is never persisted.
    const plainCode = createRecoveryCode();
    user.totpRecoveryCode = await hashRecoveryCode(plainCode);
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    return jsonResponse({
      code: plainCode,
      object: 'twoFactorRecover',
    });
  }

  // H4: If a hash is already stored, the plaintext is unavailable server-side.
  // Return an empty string — the client should prompt the user to regenerate
  // their recovery code via the accounts.recover-2fa flow if they've lost it.
  // (Legacy plaintext rows are still returned as-is for one final display before
  //  the lazy-migration path upgrades them on next login.)
  const isLegacyPlaintext = /^[A-Z2-7 ]+$/.test(user.totpRecoveryCode) && user.totpRecoveryCode.replace(/ /g, '').length === 32;
  return jsonResponse({
    code: isLegacyPlaintext ? user.totpRecoveryCode : '',
    object: 'twoFactorRecover',
  });
}

// POST /identity/accounts/recover-2fa
// Disable TOTP by recovery code + password, then rotate recovery code.
export async function handleRecoverTwoFactor(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || body.username || '').trim().toLowerCase();
  const masterPasswordHash = String(body.masterPasswordHash || body.password || '').trim();
  const recoveryCode = normalizeRecoveryCodeInput(String(body.recoveryCode || body.twoFactorToken || body.recovery_code || ''));
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }
  const recoverLimitKey = `${clientIdentifier}:recover-2fa`;

  const recoverAttemptCheck = await rateLimit.checkLoginAttempt(recoverLimitKey);
  if (!recoverAttemptCheck.allowed) {
    return errorResponse(
      `Too many failed recovery attempts. Try again in ${Math.ceil((recoverAttemptCheck.retryAfterSeconds || 60) / 60)} minutes.`,
      429
    );
  }

  if (!email || !masterPasswordHash || !recoveryCode) {
    return errorResponse('Email, masterPasswordHash and recoveryCode are required', 400);
  }

  const user = await storage.getUser(email);
  if (!user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  const validPassword = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!validPassword) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  // H4: recoveryCodeEquals is now async and returns { match, upgradedHash? }.
  const rcVerify = await recoveryCodeEquals(recoveryCode, user.totpRecoveryCode);
  if (!rcVerify.match) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  // Recovery code = destructive escape hatch: wipe ALL 2FA providers.
  user.totpSecret = null;
  user.totpEnabled = true; // reset to default; user will start fresh if they re-setup TOTP
  // Rotate and immediately hash the new recovery code (one-time use).
  user.totpRecoveryCode = await hashRecoveryCode(createRecoveryCode());
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  // Also destroy WebAuthn and Email rows (full wipe, not just disable).
  await storage.deleteAllTwoFactorsByUserId(user.id);
  await storage.deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
  await rateLimit.clearLoginAttempts(recoverLimitKey);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: 'account.totp.recover',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    success: true,
    twoFactorEnabled: false,
    newRecoveryCode: user.totpRecoveryCode,
    object: 'twoFactorRecovery',
  });
}

// GET /api/accounts/revision-date
export async function handleGetRevisionDate(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const revisionDate = await storage.getRevisionDate(userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return jsonResponse(timestamp);
}

// POST /api/accounts/verify-password
export async function handleVerifyPassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: { masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }

  const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }

  return new Response(null, { status: 200 });
}

// POST /api/accounts/api-key
export async function handleGetApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, false);
}

// POST /api/accounts/rotate-api-key
export async function handleRotateApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, true);
}

async function apiKey(request: Request, env: Env, userId: string, rotate: boolean): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = String(body.masterPasswordHash || body.master_password_hash || body.password || '').trim();
  if (!currentHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (rotate || user.apiKey === null) {
    // Upstream apikeys are 30-character random alphanumeric strings
    user.apiKey = randomStringAlphanum(LIMITS.auth.clientSecretLength);
    if (rotate) {
      user.securityStamp = generateUUID();
      await storage.deleteRefreshTokensByUserId(user.id);
    }
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    AuthService.invalidateUserCache(user.id);
    await writeAuditEvent(storage, {
      actorUserId: user.id,
      action: rotate ? 'account.api_key.rotate' : 'account.api_key.create',
      category: 'security',
      level: rotate ? 'security' : 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: auditRequestMetadata(request),
    });
  }

  return jsonResponse({
    apiKey: user.apiKey,
    revisionDate: user.updatedAt,
    object: 'apiKey',
  });
}

// ---------------------------------------------------------------------------
// WebAuthn (FIDO2) management endpoints
// ---------------------------------------------------------------------------

import {
  generateRegistrationChallenge,
  completeRegistration,
  listCredentials,
  deleteCredential,
  renameCredential,
  disableAllWebAuthn,
  reenableAllWebAuthn,
} from '../services/two-factor/webauthn-provider';

/**
 * GET /api/two-factor/webauthn
 * Returns the registration challenge options + list of existing credentials.
 * Bitwarden-compatible: also accepts GET /api/two-factor/get-webauthn.
 */
export async function handleGetWebAuthnChallenge(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  // Master password校验是可选的：仅当请求携带 masterPasswordHash 时才验证。
  //
  // 设计说明（BUG-BE-1 修复，Option A）：
  //   - 强制校验已移至 handleRegisterWebAuthn（attestation POST）。
  //   - GET challenge 本身无主密码也无害：没有 attestation 步骤就无法完成注册，
  //     即使攻击者拿到 challenge，也无法在没有用户设备私钥的情况下伪造 attestation。
  //   - HTTP GET 传 body 会被代理/CDN（如 Cloudflare）丢弃，不可靠；
  //     前端 getWebAuthnChallenge() 发的是无 body 的 GET，不能要求必须有 masterPasswordHash。
  //   - 若客户端自愿附带主密码（如某些第三方客户端），仍做验证以提供额外防御层。
  let body: Record<string, string | undefined> = {};
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries()) as Record<string, string>;
    } else if (request.method !== 'GET') {
      body = await request.json();
    }
  } catch { /* ignored — body is optional for this endpoint */ }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  // Optional: only verify if the client provided a master password hash.
  if (masterPasswordHash) {
    const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
    if (!valid) return errorResponse('Invalid password', 400);
  }

  const twoFactorRows = await storage.getTwoFactorsByUserId(userId);
  const existingCredentials = listCredentials(twoFactorRows);
  const options = await generateRegistrationChallenge(env.DB, user, request, existingCredentials);

  // Surface enabled status so the front-end can distinguish:
  //   enabled=true, retainedCredentials>0  → active
  //   enabled=false, retainedCredentials>0 → soft-disabled, re-enable available
  //   enabled=false, retainedCredentials=0 → fully disabled / never set up
  const webAuthnRow = twoFactorRows.find(r => r.atype === 7 /* TwoFactorType.WebAuthn */);
  const webAuthnEnabled = !!(webAuthnRow?.enabled);

  return jsonResponse({
    ...options,
    enabled: webAuthnEnabled,
    keys: existingCredentials.map(c => ({
      id: c.id,
      name: c.name,
      createdAt: c.createdAt,
      transports: c.transports,
      attachment: c.attachment,
    })),
    object: 'twoFactorWebAuthn',
  });
}

/**
 * POST /api/two-factor/webauthn
 * Complete WebAuthn credential registration.
 */
export async function handleRegisterWebAuthn(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  try {
    const credential = await completeRegistration(
      env.DB,
      user,
      {
        id: String(body.id ?? ''),
        rawId: String(body.rawId ?? body.id ?? ''),
        type: String(body.type ?? 'public-key'),
        response: body.response as Record<string, string> | undefined,
        deviceName: String(body.name ?? body.deviceName ?? ''),
        transports: Array.isArray(body.transports) ? body.transports as string[] : undefined,
        attachment: body.attachment ? String(body.attachment) : undefined,
      },
      env
    );

    // Ensure the account has a recovery code now that WebAuthn is enabled.
    // The recovery code is account-level (not TOTP-specific): it acts as an
    // escape hatch to disable ALL 2FA providers at once (Bitwarden semantics).
    // H4: Store hash only; the user retrieves plaintext via the recover endpoint.
    if (!user.totpRecoveryCode) {
      user.totpRecoveryCode = await hashRecoveryCode(createRecoveryCode());
      user.updatedAt = new Date().toISOString();
      await storage.saveUser(user);
    }

    // C1: Revoke existing sessions after adding a new 2FA provider so that stale
    // sessions (which pre-date the new factor) cannot be used without re-authentication.
    await storage.deleteRefreshTokensByUserId(userId);
    AuthService.invalidateUserCache(userId);

    await safeWriteAuditEvent(env, {
      actorUserId: userId,
      action: 'account.webauthn.register',
      category: 'security',
      level: 'info',
      targetType: 'webauthn_credential',
      targetId: credential.id,
      metadata: auditRequestMetadata(request),
    });

    const twoFactorRows = await storage.getTwoFactorsByUserId(userId);
    const allCredentials = listCredentials(twoFactorRows);
    return jsonResponse({
      id: credential.id,
      name: credential.name,
      createdAt: credential.createdAt,
      transports: credential.transports,
      attachment: credential.attachment,
      keys: allCredentials.map(c => ({ id: c.id, name: c.name, createdAt: c.createdAt, transports: c.transports, attachment: c.attachment })),
      object: 'twoFactorWebAuthn',
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Registration failed';
    return errorResponse(msg, 400);
  }
}

/**
 * DELETE /api/two-factor/webauthn
 * Two modes:
 *   - With credentialId/id in body: remove a single credential (requires masterPasswordHash).
 *   - Without credentialId/id: disable ALL WebAuthn credentials (requires masterPasswordHash).
 */
export async function handleDeleteWebAuthn(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const credentialId = String(body.id ?? body.credentialId ?? '').trim();

  // Bulk disable: no credentialId → disable all WebAuthn credentials
  if (!credentialId) {
    await disableAllWebAuthn(env.DB, userId);
    await safeWriteAuditEvent(env, {
      actorUserId: userId,
      action: 'account.webauthn.disable_all',
      category: 'security',
      level: 'security',
      targetType: 'webauthn_credential',
      targetId: '',
      metadata: auditRequestMetadata(request),
    });
    return jsonResponse({ keys: [], object: 'twoFactorWebAuthn' });
  }

  const deleted = await deleteCredential(env.DB, userId, credentialId);
  if (!deleted) return errorResponse('Credential not found', 404);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn.delete',
    category: 'security',
    level: 'security',
    targetType: 'webauthn_credential',
    targetId: credentialId,
    metadata: auditRequestMetadata(request),
  });

  const twoFactorRows = await storage.getTwoFactorsByUserId(userId);
  const remaining = listCredentials(twoFactorRows);
  return jsonResponse({
    keys: remaining.map(c => ({ id: c.id, name: c.name, createdAt: c.createdAt, transports: c.transports, attachment: c.attachment })),
    object: 'twoFactorWebAuthn',
  });
}

/**
 * POST /api/two-factor/webauthn/reenable
 * Re-enable WebAuthn after a reversible disable (disableAllWebAuthn).
 * Requires masterPasswordHash. Credentials are preserved — no re-registration needed.
 *
 * Body: { masterPasswordHash: string }
 */
export async function handleReenableWebAuthn(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const reenabled = await reenableAllWebAuthn(env.DB, userId);
  if (!reenabled) {
    return errorResponse('No retained WebAuthn credentials found. Please register a new credential.', 400);
  }

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn.reenable',
    category: 'security',
    level: 'security',
    targetType: 'webauthn_credential',
    targetId: '',
    metadata: auditRequestMetadata(request),
  });

  const twoFactorRows = await storage.getTwoFactorsByUserId(userId);
  const credentials = listCredentials(twoFactorRows);
  return jsonResponse({
    enabled: true,
    keys: credentials.map(c => ({ id: c.id, name: c.name, createdAt: c.createdAt, transports: c.transports, attachment: c.attachment })),
    object: 'twoFactorWebAuthn',
  });
}

/**
 * PUT /api/two-factor/webauthn
 * Rename a registered WebAuthn credential.
 * Requires only login authentication (not masterPasswordHash — renaming is cosmetic).
 */
export async function handleRenameWebAuthn(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const credentialId = String(body.credentialId ?? '').trim();
  const name = String(body.name ?? '').trim();
  if (!credentialId) return errorResponse('credentialId is required', 400);
  if (!name) return errorResponse('name is required', 400);

  const renamed = await renameCredential(env.DB, userId, credentialId, name);
  if (!renamed) return errorResponse('Credential not found', 404);

  const twoFactorRows = await storage.getTwoFactorsByUserId(userId);
  const keys = listCredentials(twoFactorRows).map(c => ({
    id: c.id,
    name: c.name,
    createdAt: c.createdAt,
    transports: c.transports,
    attachment: c.attachment,
  }));
  return jsonResponse({ keys, object: 'twoFactorWebAuthn' });
}

// ---------------------------------------------------------------------------
// Email 2FA management endpoints (P2)
// ---------------------------------------------------------------------------

/**
 * GET /api/two-factor/email
 * Returns the current Email 2FA status and the masked enrolled email (if any).
 * Also triggers sending a fresh code to the enrolled email (for setup/verify flow).
 */
export async function handleGetEmailTwoFactor(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  // available = email provider is configured (RESEND_API_KEY + MFA_EMAIL_FROM must be set)
  const available = !!(env.RESEND_API_KEY && env.MFA_EMAIL_FROM);

  const row = await getTwoFactor(env.DB, userId, EMAIL_ENROLLMENT_ATYPE);
  const enabled = row?.enabled ?? false;
  // configured=true even when disabled, as long as the enrollment row exists.
  // Allows front-end to show "re-enable" instead of "set up".
  const configured = !!row;
  const enrolledEmail = row ? (JSON.parse(row.data) as { email: string }).email : null;

  return jsonResponse({
    enabled,
    available,
    configured,
    email: enrolledEmail ? maskEmail(enrolledEmail) : null,
    object: 'twoFactorEmail',
  });
}

/**
 * POST /api/two-factor/send-email
 * Already-authenticated user triggers sending a verification code to their email
 * (used during 2FA enrollment setup flow).
 *
 * Body: { email, masterPasswordHash }
 */
export async function handleSendEmailSetup(request: Request, env: Env, userId: string): Promise<Response> {
  if (!env.RESEND_API_KEY || !env.MFA_EMAIL_FROM) {
    return errorResponse('Email 2FA is not configured on this server', 503);
  }

  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  // Per-user send budget: limit to 5 sends per 10 minutes.
  const sendBudget = await rateLimit.consumeBudgetWithWindow(`${userId}:email-setup-send`, 5, 600);
  if (!sendBudget.allowed) {
    return errorResponse('Too many email verification requests. Please try again later.', 429);
  }

  let body: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid request body', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const targetEmail = String(body.email ?? '').trim().toLowerCase();
  if (!targetEmail || !targetEmail.includes('@')) return errorResponse('Valid email is required', 400);

  // Generate + store challenge.
  const code = generateNumericCode();
  await upsertTwoFactor(env.DB, {
    userId,
    atype: EMAIL_LOGIN_CHALLENGE_ATYPE,
    enabled: true,
    data: JSON.stringify({ code, createdAt: Date.now(), attempts: 0 }),
    lastUsed: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  // Send code — failure MUST surface.
  const sender = buildEmailSenderFromEnv(env);
  if (!sender) return errorResponse('Email sender not configured', 503);
  try {
    await sender.send({
      to: targetEmail,
      subject: 'Your NodeWarden verification code',
      text: [
        `Your NodeWarden verification code is: ${code}`,
        '',
        `This code expires in ${CODE_TTL_S / 60} minutes and can only be used once.`,
        'If you did not request this code, please secure your account immediately.',
      ].join('\n'),
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ Message: `Failed to send verification email: ${err instanceof Error ? err.message : String(err)}` }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
}

/**
 * PUT /api/two-factor/email
 * Enable Email 2FA: verify the code sent to the target email, then enroll.
 *
 * Body: { email, masterPasswordHash, token }
 */
export async function handleEnableEmailTwoFactor(request: Request, env: Env, userId: string): Promise<Response> {
  if (!env.RESEND_API_KEY || !env.MFA_EMAIL_FROM) {
    return errorResponse('Email 2FA is not configured on this server', 503);
  }

  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid request body', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const targetEmail = String(body.email ?? '').trim().toLowerCase();
  if (!targetEmail || !targetEmail.includes('@')) return errorResponse('Valid email is required', 400);

  const token = String(body.token ?? '').trim();
  if (!token) return errorResponse('Verification token is required', 400);

  // Verify the pending setup challenge.
  const challengeRow = await getTwoFactor(env.DB, userId, EMAIL_LOGIN_CHALLENGE_ATYPE);
  if (!challengeRow) return errorResponse('No pending verification code. Please request a new code.', 400);

  const challenge = JSON.parse(challengeRow.data) as { code: string; createdAt: number; attempts: number };
  const ageMs = Date.now() - challenge.createdAt;
  if (ageMs > CODE_TTL_S * 1000) {
    await deleteTwoFactor(env.DB, userId, EMAIL_LOGIN_CHALLENGE_ATYPE);
    return errorResponse('Verification code has expired. Please request a new code.', 400);
  }

  // Constant-time comparison.
  const enc = new TextEncoder();
  const { timingSafeEqual } = await import('../utils/passkey');
  const match = await timingSafeEqual(enc.encode(token), enc.encode(challenge.code));
  if (!match) {
    const newAttempts = challenge.attempts + 1;
    if (newAttempts >= 3) {
      await deleteTwoFactor(env.DB, userId, EMAIL_LOGIN_CHALLENGE_ATYPE);
    } else {
      await upsertTwoFactor(env.DB, {
        ...challengeRow,
        data: JSON.stringify({ ...challenge, attempts: newAttempts }),
        updatedAt: new Date().toISOString(),
      });
    }
    return errorResponse('Invalid verification code', 400);
  }

  // Delete the setup challenge and enroll.
  await deleteTwoFactor(env.DB, userId, EMAIL_LOGIN_CHALLENGE_ATYPE);
  await upsertTwoFactor(env.DB, {
    userId,
    atype: EMAIL_ENROLLMENT_ATYPE,
    enabled: true,
    data: JSON.stringify({ email: targetEmail }),
    lastUsed: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  // Ensure account-level recovery code exists.
  // H4: Store hash only; the user retrieves plaintext via the recover endpoint.
  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = await hashRecoveryCode(createRecoveryCode());
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
  }

  // C1: Revoke existing sessions after enabling a new 2FA provider so that stale
  // sessions (which pre-date this factor) must re-authenticate with the new factor.
  await storage.deleteRefreshTokensByUserId(userId);
  AuthService.invalidateUserCache(userId);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.email2fa.enable',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    enabled: true,
    email: maskEmail(targetEmail),
    object: 'twoFactorEmail',
  });
}

/**
 * DELETE /api/two-factor/email
 * Disable Email 2FA for this user.
 *
 * Body: { masterPasswordHash }
 */
export async function handleDisableEmailTwoFactor(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid request body', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  // Reversible disable: set enabled=0 but keep the enrollment row so the
  // user can re-enable (handleReenableEmailTwoFactor) without re-setup.
  const enrollmentRow = await getTwoFactor(env.DB, userId, EMAIL_ENROLLMENT_ATYPE);
  if (enrollmentRow) {
    await upsertTwoFactor(env.DB, {
      ...enrollmentRow,
      enabled: false,
      updatedAt: new Date().toISOString(),
    });
  }
  // Clean up any stale challenge row.
  await deleteTwoFactor(env.DB, userId, EMAIL_LOGIN_CHALLENGE_ATYPE);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.email2fa.disable',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: auditRequestMetadata(request),
  });

  // configured=true signals that enrollment data is retained for re-enable.
  const configured = !!enrollmentRow;
  return jsonResponse({ enabled: false, configured, email: null, object: 'twoFactorEmail' });
}

/**
 * POST /api/two-factor/email/reenable
 * Re-enable Email 2FA after a reversible disable.
 * Requires masterPasswordHash. The enrolled email is preserved — no re-setup needed.
 *
 * Body: { masterPasswordHash: string }
 */
export async function handleReenableEmailTwoFactor(request: Request, env: Env, userId: string): Promise<Response> {
  if (!env.RESEND_API_KEY || !env.MFA_EMAIL_FROM) {
    return errorResponse('Email 2FA is not configured on this server', 503);
  }

  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid request body', 400);
  }

  const masterPasswordHash = String(body.masterPasswordHash ?? body.master_password_hash ?? '').trim();
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const enrollmentRow = await getTwoFactor(env.DB, userId, EMAIL_ENROLLMENT_ATYPE);
  if (!enrollmentRow) {
    return errorResponse('Email 2FA is not configured. Please set it up first.', 400);
  }

  // Restore enabled flag — enrollment data (email address) is already there.
  await upsertTwoFactor(env.DB, {
    ...enrollmentRow,
    enabled: true,
    updatedAt: new Date().toISOString(),
  });

  const enrollment = JSON.parse(enrollmentRow.data) as { email: string };
  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.email2fa.reenable',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    enabled: true,
    email: maskEmail(enrollment.email),
    object: 'twoFactorEmail',
  });
}

// Generate a random alphanumeric string of the given length using crypto.getRandomValues.
function randomStringAlphanum(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const maxUnbiased = Math.floor(256 / chars.length) * chars.length;
  const bytes = new Uint8Array(Math.max(16, length));

  while (result.length < length) {
    crypto.getRandomValues(bytes);
    for (const value of bytes) {
      if (value >= maxUnbiased) continue;
      result += chars[value % chars.length];
      if (result.length >= length) break;
    }
  }

  return result;
}
