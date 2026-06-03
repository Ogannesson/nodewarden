/**
 * Backup 2FA correctness tests (H5/H6)
 *
 * Tests cover:
 *   H5 - Export must NOT include transient challenge rows (atype >= 1000).
 *   H6 - Import must preserve two_factors rows; transient rows rejected at
 *        validation time; shadow-count check covers two_factors.
 *
 * Strategy: use `validateBackupPayloadContents` (pure validation logic, no DB)
 * for H5 and H6 validation tests. We stub a minimal BackupPayload that
 * satisfies all other fields and only vary the two_factors rows.
 */

import { describe, it, expect } from 'vitest';
import { validateBackupPayloadContents, type BackupPayload } from '../backup-archive';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid BackupPayload with the given two_factors rows. */
function makePayload(twoFactors: Array<Record<string, string | number | null>>): BackupPayload {
  const userId = 'user-001';
  return {
    manifest: {
      version: 1,
      createdAt: '2024-01-01T00:00:00Z',
      serverVersion: '1.0.0',
      hostname: 'example.com',
      tableCounts: {
        config: 1,
        users: 1,
        domain_settings: 0,
        user_revisions: 1,
        folders: 0,
        ciphers: 0,
        attachments: 0,
        two_factors: twoFactors.length,
      },
      includes: { attachments: false },
      blobSummary: { attachmentFiles: 0, totalBytes: 0, largestObjectBytes: 0 },
    },
    db: {
      config: [{ key: 'registered', value: 'true' }],
      users: [{
        id: userId,
        email: 'test@example.com',
        name: 'Test',
        master_password_hint: null,
        master_password_hash: 'hash',
        key: 'key',
        private_key: null,
        public_key: null,
        kdf_type: 0,
        kdf_iterations: 600000,
        kdf_memory: null,
        kdf_parallelism: null,
        security_stamp: 'stamp',
        role: 'user',
        status: 'active',
        verify_devices: 1,
        totp_secret: null,
        totp_enabled: 1,
        totp_recovery_code: null,
        api_key: null,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      }],
      domain_settings: [],
      user_revisions: [{ user_id: userId, revision_date: '2024-01-01T00:00:00Z' }],
      folders: [],
      ciphers: [],
      attachments: [],
      two_factors: twoFactors,
    },
  } as unknown as BackupPayload;
}

const emptyFiles: Record<string, Uint8Array> = {};

// ---------------------------------------------------------------------------
// H5: Export filter tests (validateBackupPayloadContents rejects atype >= 1000)
// ---------------------------------------------------------------------------

describe('validateBackupPayloadContents – H5/H6: transient row rejection', () => {
  it('H5: atype=1002 (Email OTP challenge) causes validation to throw', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 1002,
      enabled: 1,
      data: '{"code":"123456","createdAt":1700000000000,"attempts":0}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(
      /transient two_factor row.*atype=1002/
    );
  });

  it('H5: atype=1003 (WebAuthn login challenge) causes validation to throw', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 1003,
      enabled: 1,
      data: '{}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(
      /transient two_factor row.*atype=1003/
    );
  });

  it('H5: atype=1004 causes validation to throw', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 1004,
      enabled: 1,
      data: '{}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(
      /transient two_factor row.*atype=1004/
    );
  });

  it('H5: any atype >= 1000 is rejected (e.g. 9999)', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 9999,
      enabled: 1,
      data: '{}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(/transient/);
  });

  it('H5: persistent atype=1 (Email enrollment) is accepted', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 1,
      enabled: 1,
      data: '{"email":"test@example.com"}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    // Should not throw
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).not.toThrow();
  });

  it('H5: persistent atype=7 (WebAuthn credential) is accepted', () => {
    const payload = makePayload([{
      user_id: 'user-001',
      atype: 7,
      enabled: 1,
      data: '{"credentials":[]}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).not.toThrow();
  });

  it('H5: empty two_factors array is accepted', () => {
    const payload = makePayload([]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).not.toThrow();
  });

  it('H6: two_factors row referencing unknown user_id is rejected', () => {
    const payload = makePayload([{
      user_id: 'unknown-user',
      atype: 7,
      enabled: 1,
      data: '{}',
      last_used: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(/unknown user/);
  });

  it('H6: mix of valid and transient rows — throws on first transient row', () => {
    const payload = makePayload([
      // First a valid row
      {
        user_id: 'user-001',
        atype: 7,
        enabled: 1,
        data: '{"credentials":[]}',
        last_used: null,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
      // Then a transient row
      {
        user_id: 'user-001',
        atype: 1002,
        enabled: 1,
        data: '{"code":"123456","createdAt":1700000000000,"attempts":0}',
        last_used: null,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
    ]);
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).toThrow(/transient/);
  });
});

// ---------------------------------------------------------------------------
// H6: Round-trip test (export filter → import preserved)
// Test logic: if two_factors contains only persistent rows, validation passes.
// This simulates a "round-trip" where export filtered transient rows and import
// receives only persistent rows, which then pass validation.
// ---------------------------------------------------------------------------

describe('validateBackupPayloadContents – H6: round-trip after export filter', () => {
  it('H6: backup with Email enrollment + WebAuthn credential passes validation', () => {
    const payload = makePayload([
      {
        user_id: 'user-001',
        atype: 1, // Email enrollment (persistent)
        enabled: 1,
        data: '{"email":"test@example.com"}',
        last_used: null,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
      {
        user_id: 'user-001',
        atype: 7, // WebAuthn credential (persistent)
        enabled: 1,
        data: '{"credentials":[{"id":"cred-01","publicKey":"...","signCount":0}]}',
        last_used: null,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
    ]);
    // Both persistent rows pass validation
    expect(() => validateBackupPayloadContents(payload, emptyFiles)).not.toThrow();
  });
});
