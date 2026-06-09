import { Env, TokenResponse } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse, identityErrorResponse } from '../utils/response';
import { LIMITS } from '../config/limits';
import { createRefreshToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo } from '../utils/device';
import { recoveryCodeEquals, hashRecoveryCode, createRecoveryCode, sha256Hex } from '../utils/recovery-code';
import { generateUUID } from '../utils/uuid';
import { issueSendAccessToken } from './sends';
import {
  buildAccountKeys,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { getAvailableProviders, getProvider } from '../services/two-factor/registry';
import { TwoFactorType } from '../services/two-factor/types';
import type { TwoFactorProvider } from '../services/two-factor/types';
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

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TWO_FACTOR_PROVIDER_REMEMBER = 5;
const WEB_REFRESH_COOKIE = 'nodewarden_web_refresh';
// Android client (2026.2.x) deserializes TwoFactorProviders2 keys with -1 for recovery code.
// Keep request parsing backward-compatible with historical provider values (8 / 100).
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE = '-1';
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_LEGACY = 8;
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST = 100;
// #10: short-lived D1 row (two_factors) holding the freshly-rotated recovery code in
// plaintext so the user can retrieve it once via GET /api/two-factor/recover.
const RECOVERY_PENDING_ATYPE = 1005;
const RECOVERY_PENDING_TTL_MS = 15 * 60 * 1000;

async function resolveDeviceSession(
  storage: StorageService,
  userId: string,
  deviceInfo: ReturnType<typeof readAuthRequestDeviceInfo>
): Promise<{ identifier: string; sessionStamp: string } | null> {
  if (!deviceInfo.deviceIdentifier) return null;
  const existingDevice = await storage.getDevice(userId, deviceInfo.deviceIdentifier);
  const sessionStamp = String(existingDevice?.sessionStamp || '').trim() || generateUUID();
  return { identifier: deviceInfo.deviceIdentifier, sessionStamp };
}

function shouldUseWebSession(request: Request): boolean {
  return String(request.headers.get('X-NodeWarden-Web-Session') || '').trim() === '1';
}

function parseCookieValue(request: Request, name: string): string | null {
  const rawCookie = String(request.headers.get('Cookie') || '').trim();
  if (!rawCookie) return null;
  for (const part of rawCookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key !== name) continue;
    const value = rest.join('=').trim();
    return value ? decodeURIComponent(value) : null;
  }
  return null;
}

function constantTimeEquals(a: string, b: string): boolean {
  const encA = new TextEncoder().encode(a);
  const encB = new TextEncoder().encode(b);
  if (encA.length !== encB.length) return false;

  let diff = 0;
  for (let i = 0; i < encA.length; i++) {
    diff |= encA[i] ^ encB[i];
  }
  return diff === 0;
}

function buildRefreshCookie(request: Request, refreshToken: string, maxAgeSeconds: number): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const parts = [
    `${WEB_REFRESH_COOKIE}=${encodeURIComponent(refreshToken)}`,
    'Path=/identity/connect',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

function buildClearedRefreshCookie(request: Request): string {
  return buildRefreshCookie(request, '', 0);
}

function withWebRefreshCookie(request: Request, response: Response, refreshToken: string | null): Response {
  const headers = new Headers(response.headers);
  headers.append(
    'Set-Cookie',
    refreshToken
      ? buildRefreshCookie(request, refreshToken, Math.floor(LIMITS.auth.refreshTokenTtlMs / 1000))
      : buildClearedRefreshCookie(request)
  );
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function buildPreloginResponse(
  email: string,
  kdfType: number,
  kdfIterations: number,
  kdfMemory: number | null,
  kdfParallelism: number | null
): Record<string, unknown> {
  return {
    kdf: kdfType,
    kdfIterations,
    kdfMemory,
    kdfParallelism,
    KdfSettings: {
      KdfType: kdfType,
      Iterations: kdfIterations,
      Memory: kdfMemory,
      Parallelism: kdfParallelism,
    },
    Salt: email.toLowerCase(),
  };
}

/**
 * Build the 2FA challenge response (HTTP 400 invalid_grant).
 *
 * `enabledProviders` is the list of providers that are active for this user
 * (already filtered by isAvailable + isEnabledForUser).
 * `challengeData` maps provider type → the value for TwoFactorProviders2[type]
 * (null for Authenticator, an options-object for WebAuthn, etc.).
 * `includeRecoveryCode` appends the -1 recovery-code entry when the user has one.
 */
function twoFactorRequiredResponse(
  enabledProviders: TwoFactorProvider[],
  challengeData: Map<number, unknown>,
  message: string = 'Two factor required.',
  includeRecoveryCode: boolean = false
): Response {
  // Build TwoFactorProviders list (string keys, matching Bitwarden protocol).
  const providerKeys: string[] = enabledProviders.map(p => String(p.type));
  if (includeRecoveryCode) {
    providerKeys.push(TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE);
  }

  // Build TwoFactorProviders2 map (type string → challenge payload or null).
  const providers2: Record<string, unknown> = {};
  for (const p of enabledProviders) {
    providers2[String(p.type)] = challengeData.get(p.type) ?? null;
  }
  if (includeRecoveryCode) {
    providers2[TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE] = null;
  }

  const customResponse = {
    TwoFactorProviders: providerKeys,
    TwoFactorProviders2: providers2,
    SsoEmail2faSessionToken: null,
    MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
  };

  // Bitwarden clients rely on these fields to trigger the 2FA UI flow.
  return jsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      Error: 'invalid_grant',
      ErrorDescription: message,
      ErrorMessage: message,
      TwoFactorProviders: customResponse.TwoFactorProviders,
      TwoFactorProviders2: customResponse.TwoFactorProviders2,
      // Required by current Android parser (nullable value is acceptable).
      SsoEmail2faSessionToken: customResponse.SsoEmail2faSessionToken,
      MasterPasswordPolicy: customResponse.MasterPasswordPolicy,
      CustomResponse: customResponse,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    400
  );
}

async function recordFailedLoginAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string,
  message: string
): Promise<Response> {
  const result = await rateLimit.recordFailedLogin(loginIdentifier);
  if (result.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(result.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse(message, 'invalid_grant', 400);
}

async function recordFailedTwoFactorAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string
): Promise<Response> {
  const failed = await rateLimit.recordFailedLogin(loginIdentifier);
  if (failed.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(failed.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse('Two-step token is invalid. Try again.', 'invalid_grant', 400);
}

// POST /identity/connect/token
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return identityErrorResponse('Invalid request payload', 'invalid_request', 400);
  }

  const grantType = body.grant_type;
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return identityErrorResponse('Client IP is required', 'invalid_request', 403);
  }

  if (grantType === 'password') {
    // Login with password
    const email = body.username?.toLowerCase();
    const passwordHash = body.password;
    const twoFactorToken = body.twoFactorToken;
    const twoFactorProvider = body.twoFactorProvider;
    const twoFactorRemember = body.twoFactorRemember;
    const loginIdentifier = clientIdentifier;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    if (!email || !passwordHash) {
      // Bitwarden clients expect OAuth-style error fields.
      return identityErrorResponse('Email and password are required', 'invalid_request', 400);
    }

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUser(email);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Username or password is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    const valid = await auth.verifyPassword(passwordHash, user.masterPasswordHash, user.email);
    if (!valid) {
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.bad_password',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    // Optional 2FA: driven by provider registry + legacy TOTP column (conservative dual-track).
    let trustedTwoFactorTokenToReturn: string | undefined;

    // Fetch two_factors rows for this user (for WebAuthn/Email/YubiKey providers in future phases).
    // TOTP uses users.totp_secret (legacy column) directly inside TotpTwoFactorProvider.
    const twoFactorRows = await storage.getTwoFactorsByUserId(user.id);

    // Determine which providers are enabled for this user.
    const availableProviders = getAvailableProviders(env);
    const enabledProviders = availableProviders.filter(p => p.isEnabledForUser(user, twoFactorRows));

    if (enabledProviders.length > 0) {
      // Recovery code is account-level, not TOTP-specific: any user with at least one
      // 2FA provider enabled can use their recovery code to disable all 2FA at once.
      const canUseRecoveryCode = !!user.totpRecoveryCode;
      const normalizedTwoFactorProvider = String(twoFactorProvider ?? '').trim();
      const normalizedTwoFactorToken = String(twoFactorToken ?? '').trim();
      let rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(String(twoFactorRemember || '').trim());
      const hasProvider = normalizedTwoFactorProvider.length > 0;
      const hasToken = normalizedTwoFactorToken.length > 0;

      // Upstream-compatible behavior: if 2FA is required and either provider or token is missing,
      // respond with a 2FA challenge payload driven by the enabled-providers list.
      if (!hasProvider || !hasToken) {
        const challengeCtx = { user, env, db: env.DB, twoFactorRows, request };
        const challengeData = new Map<number, unknown>();
        // H2: per-provider try-catch — a failing provider (e.g. Email backend outage) must not
        // block other providers. Only skip the failing provider; log server-side.
        const availableForChallenge: TwoFactorProvider[] = [];
        for (const p of enabledProviders) {
          try {
            challengeData.set(p.type, await p.buildChallenge(challengeCtx));
            availableForChallenge.push(p);
          } catch (err) {
            console.error(`[2FA] buildChallenge failed for provider ${p.type}:`, err);
            // Provider unavailable — omit from challenge list but continue for others.
          }
        }
        // Fall back to full list for any provider whose challenge we could not build
        // (they won't have data but the UI can still prompt for TOTP/WebAuthn).
        const challengeProviders = availableForChallenge.length > 0 ? availableForChallenge : enabledProviders;
        return twoFactorRequiredResponse(challengeProviders, challengeData, 'Two factor required.', canUseRecoveryCode);
      }

      let passedByRememberToken = false;
      if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_REMEMBER)) {
        if (deviceInfo.deviceIdentifier) {
          const trustedUserId = await storage.getTrustedTwoFactorDeviceTokenUserId(
            normalizedTwoFactorToken,
            deviceInfo.deviceIdentifier
          );
          passedByRememberToken = trustedUserId === user.id;
        }

        // Remember token missing/invalid/expired should re-enter the 2FA challenge flow.
        if (!passedByRememberToken) {
          const challengeCtx = { user, env, db: env.DB, twoFactorRows, request };
          const challengeData = new Map<number, unknown>();
          // H2: per-provider try-catch — same resilience as the initial challenge flow.
          const availableForChallenge: TwoFactorProvider[] = [];
          for (const p of enabledProviders) {
            try {
              challengeData.set(p.type, await p.buildChallenge(challengeCtx));
              availableForChallenge.push(p);
            } catch (err) {
              console.error(`[2FA] buildChallenge failed for provider ${p.type}:`, err);
            }
          }
          const challengeProviders = availableForChallenge.length > 0 ? availableForChallenge : enabledProviders;
          return twoFactorRequiredResponse(challengeProviders, challengeData, 'Two factor required.', canUseRecoveryCode);
        }
      } else if (
        normalizedTwoFactorProvider === TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE_LEGACY) ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST)
      ) {
        // Recovery code is the account-level "escape hatch": it disables ALL 2FA
        // providers at once (TOTP + WebAuthn + Email + YubiKey), matching Bitwarden
        // semantics. The recovery code is then rotated so it can only be used once.
        //
        // H4: recoveryCodeEquals now compares against a SHA-256 hash (new format) or
        // falls back to plaintext comparison for legacy rows, returning an upgradedHash
        // to persist when the row was still plaintext (lazy migration).
        // H5: capture stored code BEFORE comparison to close TOCTOU window.
        // The atomic UPDATE uses the exact stored value as the WHERE predicate;
        // if another request consumed it concurrently, changes===0 → fail-closed.
        const oldStoredCode = user.totpRecoveryCode;
        const rcResult = await recoveryCodeEquals(normalizedTwoFactorToken, oldStoredCode);
        if (!rcResult.match) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        // H5: atomic consume — sets totp_recovery_code = NULL and totp_secret = NULL
        // in a single UPDATE WHERE totp_recovery_code = <oldStoredCode>.
        // Returns false (changes === 0) when a concurrent request beat us to it.
        const consumed = await storage.atomicConsumeRecoveryCode(user.id, oldStoredCode!);
        if (!consumed) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        // Disable all non-TOTP 2FA providers stored in two_factors table.
        await storage.deleteAllTwoFactorsByUserId(user.id);
        await storage.deleteRefreshTokensByUserId(user.id);

        // #10: rotate the recovery code so the account is never left without one
        // (avoids permanent lockout). Store the new hash on the user and stash the
        // plaintext in a short-lived D1 row, retrievable once via
        // GET /api/two-factor/recover.
        const rotatedRecoveryCode = createRecoveryCode();
        const rotatedUser = await storage.getUserById(user.id);
        if (rotatedUser) {
          rotatedUser.totpRecoveryCode = await hashRecoveryCode(rotatedRecoveryCode);
          rotatedUser.updatedAt = new Date().toISOString();
          await storage.saveUser(rotatedUser);
        }
        await upsertTwoFactor(env.DB, {
          userId: user.id,
          atype: RECOVERY_PENDING_ATYPE,
          enabled: true,
          data: JSON.stringify({ code: rotatedRecoveryCode, createdAt: Date.now() }),
          lastUsed: null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });

        rememberRequested = false;
      } else {
        // Dispatch to the provider identified by twoFactorProvider.
        const providerType = Number(normalizedTwoFactorProvider);
        const provider = Number.isFinite(providerType)
          ? getProvider(providerType, env)
          : null;

        if (!provider || !provider.isEnabledForUser(user, twoFactorRows)) {
          // Unknown or not-enabled provider → treat as invalid 2FA attempt.
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }

        const verifyCtx = { user, env, db: env.DB, twoFactorRows, request };
        const ok = await provider.verify(verifyCtx, normalizedTwoFactorToken);
        if (!ok) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      }

      // Upstream behavior: do not issue a new remember token when auth itself used remember provider.
      if (rememberRequested && !passedByRememberToken && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
        await storage.saveTrustedTwoFactorDeviceToken(
          trustedTwoFactorTokenToReturn,
          user.id,
          deviceInfo.deviceIdentifier,
          Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
        );
      }
    }

    // Persist device only after successful password + (optional) 2FA verification.
    const deviceSession = await resolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await storage.upsertDevice(
        user.id,
        deviceSession.identifier,
        deviceInfo.deviceName,
        deviceInfo.deviceType,
        deviceSession.sessionStamp
      );
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    // C4: Clean up any transient login-challenge rows (atype >= 1000, e.g. Email OTP).
    // Prevents a previously-sent Email OTP code from being replayed through provider=1
    // after the user authenticated successfully with a different factor (TOTP/WebAuthn).
    await storage.deleteTransientTwoFactorsByUserId(user.id);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user.id, deviceSession);
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      ...(trustedTwoFactorTokenToReturn ? { TwoFactorToken: trustedTwoFactorTokenToReturn } : {}),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: {
        Object: 'masterPasswordPolicy',
      },
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = jsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'client_credentials') {
    // Login with client credentials
    const clientId = body.client_id;
    const clientSecret = body.client_secret;
    const scope = body.scope;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    const loginIdentifier = clientIdentifier;
    const parmValid = checkClientCredentialsParam(clientId, clientSecret, scope);
    if (!parmValid) {
      return identityErrorResponse('Parameter error', 'invalid_request', 400);
    }

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const uid = clientId.slice(5);
    const user = await storage.getUserById(uid);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    if (!user.apiKey || !constantTimeEquals(clientSecret, user.apiKey)) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.bad_api_key',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }

    // Persist device only after successful client credential verification.
    const deviceSession = await resolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await storage.upsertDevice(
        user.id,
        deviceSession.identifier,
        deviceInfo.deviceName,
        deviceInfo.deviceType,
        deviceSession.sessionStamp
      );
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user.id, deviceSession);
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: {
        Object: 'masterPasswordPolicy',
      },
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = jsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'send_access') {
    const sendAccessLimit = await rateLimit.consumeBudget(`${clientIdentifier}:public`, LIMITS.rateLimit.publicRequestsPerMinute);
    if (!sendAccessLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${sendAccessLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    const sendId = String(body.send_id || body.sendId || '').trim();
    if (!sendId) {
      return jsonResponse(
        {
          error: 'invalid_request',
          error_description: 'send_id is required',
          send_access_error_type: 'invalid_send_id',
          ErrorModel: {
            Message: 'send_id is required',
            Object: 'error',
          },
        },
        400
      );
    }

    const passwordHashB64 = String(
      body.password_hash_b64 || body.passwordHashB64 || body.passwordHash || body.password_hash || ''
    ).trim() || null;
    const password = String(body.password || '').trim() || null;

    const result = await issueSendAccessToken(
      env,
      sendId,
      passwordHashB64,
      password,
      rateLimit,
      `${clientIdentifier}:send-password`
    );
    if ('error' in result) {
      return result.error;
    }

    return jsonResponse({
      access_token: result.token,
      expires_in: LIMITS.auth.sendAccessTokenTtlSeconds,
      token_type: 'Bearer',
      scope: 'api.send',
      unofficialServer: true,
    });
  } else if (grantType === 'refresh_token') {
    const refreshLimit = await rateLimit.consumeBudget(
      `${clientIdentifier}:identity-refresh`,
      LIMITS.rateLimit.refreshTokenRequestsPerMinute
    );
    if (!refreshLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${refreshLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    // Refresh token
    const refreshToken = String(body.refresh_token || '').trim() || (
      shouldUseWebSession(request)
        ? parseCookieValue(request, WEB_REFRESH_COOKIE)
        : null
    );
    if (!refreshToken) {
      return identityErrorResponse('Refresh token is required', 'invalid_request', 400);
    }

    const result = await auth.refreshAccessTokenDetailed(refreshToken);
    if (!result.ok) {
      await safeWriteAuditEvent(env, {
        actorUserId: result.userId ?? null,
        action: `auth.refresh.failed.${result.reason}`,
        category: 'auth',
        level: 'warn',
        targetType: result.deviceIdentifier ? 'device' : 'refreshToken',
        targetId: result.deviceIdentifier ?? null,
        metadata: {
          grantType,
          reason: result.reason,
          webSession: shouldUseWebSession(request),
          ...auditRequestMetadata(request),
        },
      });
      const invalidResponse = identityErrorResponse('Invalid refresh token', 'invalid_grant', 400);
      return shouldUseWebSession(request)
        ? withWebRefreshCookie(request, invalidResponse, null)
        : invalidResponse;
    }

    // Keep a short overlap window for old refresh token to absorb
    // concurrent refresh requests from multiple client contexts.
    await storage.constrainRefreshTokenExpiry(
      refreshToken,
      Date.now() + LIMITS.auth.refreshTokenOverlapGraceMs
    );

    const { accessToken, user, device } = result;
    if (device?.identifier) {
      await storage.touchDeviceLastSeen(user.id, device.identifier);
    }
    const newRefreshToken = await auth.generateRefreshToken(user.id, device);
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: newRefreshToken }),
      Key: user.key,
      PrivateKey: user.privateKey,
      AccountKeys: accountKeys,
      accountKeys: accountKeys,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      MasterPasswordPolicy: {
        Object: 'masterPasswordPolicy',
      },
      ApiUseKeyConnector: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = jsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, newRefreshToken)
      : baseResponse;
  }

  return identityErrorResponse('Unsupported grant type', 'unsupported_grant_type', 400);
}

// POST /identity/accounts/prelogin
export async function handlePrelogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const user = await storage.getUser(email);

  // Return default KDF settings even if user doesn't exist (to prevent user enumeration)
  const kdfType = user?.kdfType ?? 0;
  const kdfIterations = user?.kdfIterations ?? LIMITS.auth.defaultKdfIterations;
  // Use ?? null so non-existent users return null (not undefined/omitted) for these fields,
  // matching the response shape of real PBKDF2 users and reducing enumeration signal.
  const kdfMemory = user?.kdfMemory ?? null;
  const kdfParallelism = user?.kdfParallelism ?? null;

  return jsonResponse(buildPreloginResponse(email, kdfType, kdfIterations, kdfMemory, kdfParallelism));
}

// POST /identity/connect/revocation
// Best-effort OAuth token revocation endpoint.
// RFC 7009 allows returning 200 even if token is unknown.
export async function handleRevocation(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return new Response(null, { status: 200 });
  }

  const token = String(body.token || '').trim() || (
    shouldUseWebSession(request)
      ? (parseCookieValue(request, WEB_REFRESH_COOKIE) || '')
      : ''
  );
  if (token) {
    await storage.deleteRefreshToken(token);
  }

  const baseResponse = new Response(null, { status: 200 });
  return shouldUseWebSession(request)
    ? withWebRefreshCookie(request, baseResponse, null)
    : baseResponse;
}

export function checkClientCredentialsParam(clientId: string, clientSecret: string, scope: string): boolean {
  if (scope !== 'api') {
    return false;
  }
  if (!clientId.startsWith('user.')) {
    return false;
  }
  if (!clientSecret) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// POST /api/two-factor/send-email-login (P2 Email 2FA)
// ---------------------------------------------------------------------------

/**
 * Unauthenticated endpoint: 2025.5+ clients call this during the login 2FA
 * challenge to trigger sending a fresh verification code.
 *
 * Security:
 *  - Requires masterPasswordHash to prevent arbitrary code triggers.
 *  - Always returns 200 regardless of whether the user/email exists (anti-enumeration).
 *  - Rate-limited via the standard login rate-limit bucket.
 *  - Send failures are logged but the caller receives HTTP 500 (explicit, not silent).
 */
export async function handleSendEmailLogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);
  const clientId = getClientIdentifier(request);

  // Rate limit check. If a client IP is available use the per-IP login bucket;
  // if no IP header is present, skip IP-based limiting only — we always fall back
  // to per-account limiting below (after user is resolved) to prevent exploitation
  // via clients that strip forwarding headers.
  if (clientId) {
    const rl = await rateLimit.checkLoginAttempt(clientId);
    if (!rl.allowed) {
      // Anti-enumeration: still 200, but don't send.
      return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
  }

  let body: Record<string, unknown> = {};
  try {
    const ct = request.headers.get('content-type') ?? '';
    if (ct.includes('application/x-www-form-urlencoded')) {
      const fd = await request.formData();
      body = Object.fromEntries(fd.entries());
    } else {
      body = await request.json();
    }
  } catch {
    // Silently treat malformed body as missing credentials.
  }

  const email = String(body.email ?? body.Email ?? '').trim().toLowerCase();
  const masterPasswordHash = String(body.masterPasswordHash ?? body.MasterPasswordHash ?? '').trim();

  // Always return 200 for unknown email (anti-enumeration).
  if (!email || !masterPasswordHash) {
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  const user = await storage.getUser(email);
  if (!user) {
    // Anti-enumeration: don't reveal whether the email exists.
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  // Validate master password hash — prevents arbitrary triggering for other users' emails.
  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    if (clientId) {
      await rateLimit.recordFailedLogin(clientId);
    }
    // Anti-enumeration: still 200 on bad password.
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  // Per-account send budget: limit to 5 sends per 10 minutes regardless of IP.
  // This applies whether or not a client IP was available, closing the vector where
  // an attacker strips forwarding headers to bypass IP-based limiting.
  const accountSendKey = `${user.id}:email-otp-send`;
  const accountBudget = await rateLimit.consumeBudgetWithWindow(accountSendKey, 5, 600);
  if (!accountBudget.allowed) {
    // Anti-enumeration: 200 on rate limit too.
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  // Look up the enrolled email address.
  const enrollmentRow = await getTwoFactor(env.DB, user.id, EMAIL_ENROLLMENT_ATYPE);
  if (!enrollmentRow?.enabled) {
    // Email 2FA not enrolled — return 200 (anti-enumeration, provider may be in challenge
    // list only because env is configured and some other flow is in progress).
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  const targetEmail = (JSON.parse(enrollmentRow.data) as { email: string }).email;

  // Check sender is configured before writing anything to DB.
  // Avoids leaving an orphan challenge row when the sender is not available.
  const sender = buildEmailSenderFromEnv(env);
  if (!sender) {
    return new Response(
      JSON.stringify({ Message: 'Email sender not configured on this server' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Generate + store challenge (only after confirming sender is ready).
  const code = generateNumericCode();
  await upsertTwoFactor(env.DB, {
    userId: user.id,
    atype: EMAIL_LOGIN_CHALLENGE_ATYPE,
    enabled: true,
    data: JSON.stringify({ code: await sha256Hex(code), createdAt: Date.now(), attempts: 0, targetEmail }),
    lastUsed: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  // Send code — failures are surfaced as 500 (not silently swallowed).
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
    // Send failed: remove the challenge row we just persisted so no stale (unsent)
    // code is left behind to confuse retries. Explicit failure — never swallow.
    await deleteTwoFactor(env.DB, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
    return new Response(
      JSON.stringify({ Message: `Failed to send verification email: ${err instanceof Error ? err.message : String(err)}` }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
}

/**
 * GET /api/two-factor/recover
 * #10: one-time retrieval of the freshly-rotated recovery code (plaintext) after a
 * recovery-code login. Returns the code once, then deletes the pending D1 row.
 */
export async function handleGetRotatedRecoveryCode(_request: Request, env: Env, userId: string): Promise<Response> {
  const row = await getTwoFactor(env.DB, userId, RECOVERY_PENDING_ATYPE);
  if (!row) return jsonResponse({ code: null, object: 'twoFactorRecover' });

  let parsed: { code: string; createdAt: number };
  try {
    parsed = JSON.parse(row.data) as { code: string; createdAt: number };
  } catch {
    await deleteTwoFactor(env.DB, userId, RECOVERY_PENDING_ATYPE);
    return jsonResponse({ code: null, object: 'twoFactorRecover' });
  }

  // Consume on read (one-time), regardless of expiry.
  await deleteTwoFactor(env.DB, userId, RECOVERY_PENDING_ATYPE);
  if (Date.now() - parsed.createdAt > RECOVERY_PENDING_TTL_MS) {
    return jsonResponse({ code: null, object: 'twoFactorRecover' });
  }
  return jsonResponse({ code: parsed.code, object: 'twoFactorRecover' });
}
