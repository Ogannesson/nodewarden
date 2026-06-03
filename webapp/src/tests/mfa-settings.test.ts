/**
 * mfa-settings.test.ts
 *
 * 前端逻辑单元测试，覆盖：
 *  1. 派生总状态（mfaEnabled / activeMethodCount）计算
 *  2. 关闭最后一个启用方式时触发 last-method 确认逻辑
 *  3. getKeyType (classifyKey) WebAuthn 密钥类型分类
 */

import { describe, it, expect } from 'vitest';
import type { WebAuthnKeyInfo } from '@/lib/api/auth';

// ---------------------------------------------------------------------------
// 1. 派生总状态计算（纯逻辑，提取自 SettingsPage）
// ---------------------------------------------------------------------------

/**
 * 与 SettingsPage 中相同的派生计算逻辑：
 * mfaEnabled = totpEnabled || hasWebAuthnKeys || emailTwoFactorEnabled
 * activeMethodCount = sum of active methods
 */
function deriveMfaStatus(opts: {
  totpEnabled: boolean;
  webAuthnKeyCount: number;
  emailTwoFactorEnabled: boolean;
}): { mfaEnabled: boolean; activeMethodCount: number } {
  const { totpEnabled, webAuthnKeyCount, emailTwoFactorEnabled } = opts;
  const mfaEnabled = totpEnabled || webAuthnKeyCount > 0 || emailTwoFactorEnabled;
  const activeMethodCount = (totpEnabled ? 1 : 0) + (webAuthnKeyCount > 0 ? 1 : 0) + (emailTwoFactorEnabled ? 1 : 0);
  return { mfaEnabled, activeMethodCount };
}

describe('派生 MFA 总状态', () => {
  it('全部禁用时 mfaEnabled=false, count=0', () => {
    const result = deriveMfaStatus({ totpEnabled: false, webAuthnKeyCount: 0, emailTwoFactorEnabled: false });
    expect(result.mfaEnabled).toBe(false);
    expect(result.activeMethodCount).toBe(0);
  });

  it('仅 TOTP 启用时 mfaEnabled=true, count=1', () => {
    const result = deriveMfaStatus({ totpEnabled: true, webAuthnKeyCount: 0, emailTwoFactorEnabled: false });
    expect(result.mfaEnabled).toBe(true);
    expect(result.activeMethodCount).toBe(1);
  });

  it('仅安全密钥启用时 mfaEnabled=true, count=1', () => {
    const result = deriveMfaStatus({ totpEnabled: false, webAuthnKeyCount: 2, emailTwoFactorEnabled: false });
    expect(result.mfaEnabled).toBe(true);
    expect(result.activeMethodCount).toBe(1);
  });

  it('仅 Email 2FA 启用时 mfaEnabled=true, count=1', () => {
    const result = deriveMfaStatus({ totpEnabled: false, webAuthnKeyCount: 0, emailTwoFactorEnabled: true });
    expect(result.mfaEnabled).toBe(true);
    expect(result.activeMethodCount).toBe(1);
  });

  it('全部三种方式启用时 count=3', () => {
    const result = deriveMfaStatus({ totpEnabled: true, webAuthnKeyCount: 1, emailTwoFactorEnabled: true });
    expect(result.mfaEnabled).toBe(true);
    expect(result.activeMethodCount).toBe(3);
  });

  it('多个安全密钥仍只算 1 个方法', () => {
    const result = deriveMfaStatus({ totpEnabled: false, webAuthnKeyCount: 5, emailTwoFactorEnabled: false });
    expect(result.activeMethodCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 2. 关闭最后一个方式时触发 last-method 确认逻辑
// ---------------------------------------------------------------------------

/**
 * 与 SettingsPage.withLastMethodCheck 相同的逻辑：
 * 若 activeMethodCount <= 1，不直接执行 action，而是先触发确认框。
 */
function withLastMethodCheck(
  activeMethodCount: number,
  action: () => void,
  onShowConfirm: (pendingAction: () => void) => void,
): void {
  if (activeMethodCount <= 1) {
    onShowConfirm(action);
  } else {
    action();
  }
}

describe('关闭最后一个 MFA 方式时的确认逻辑', () => {
  it('count=1 时：调 onShowConfirm，不直接执行 action', () => {
    let actionCalled = false;
    let confirmCalled = false;
    let capturedAction: (() => void) | null = null;

    withLastMethodCheck(
      1,
      () => { actionCalled = true; },
      (pending) => { confirmCalled = true; capturedAction = pending; },
    );

    expect(actionCalled).toBe(false);
    expect(confirmCalled).toBe(true);
    // 用户点击"确认"后才执行 action
    capturedAction?.();
    expect(actionCalled).toBe(true);
  });

  it('count=0 时同样先触发确认', () => {
    let confirmCalled = false;
    withLastMethodCheck(0, () => {}, () => { confirmCalled = true; });
    expect(confirmCalled).toBe(true);
  });

  it('count=2 时直接执行 action，不弹确认', () => {
    let actionCalled = false;
    let confirmCalled = false;

    withLastMethodCheck(
      2,
      () => { actionCalled = true; },
      () => { confirmCalled = true; },
    );

    expect(actionCalled).toBe(true);
    expect(confirmCalled).toBe(false);
  });

  it('count=3 时直接执行 action', () => {
    let actionCalled = false;
    withLastMethodCheck(3, () => { actionCalled = true; }, () => {});
    expect(actionCalled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. getKeyType (classifyKey) —— WebAuthn 密钥类型分类
// ---------------------------------------------------------------------------

/**
 * 与 SettingsPage.getKeyType 相同的分类逻辑：
 * attachment=platform 或 transport=internal → platform
 * transport=usb → usb
 * transport=nfc → nfc
 * transport=ble|hybrid → ble
 * 其他 → generic
 */
function classifyKey(key: Pick<WebAuthnKeyInfo, 'attachment' | 'transports'>): string {
  if (key.attachment === 'platform' || key.transports?.includes('internal')) return 'txt_webauthn_type_platform';
  if (key.transports?.includes('usb')) return 'txt_webauthn_type_usb';
  if (key.transports?.includes('nfc')) return 'txt_webauthn_type_nfc';
  if (key.transports?.includes('ble') || key.transports?.includes('hybrid')) return 'txt_webauthn_type_ble';
  return 'txt_webauthn_type_generic';
}

describe('classifyKey / getKeyType 密钥类型分类', () => {
  it('attachment=platform → platform', () => {
    expect(classifyKey({ attachment: 'platform', transports: [] })).toBe('txt_webauthn_type_platform');
  });

  it('transport=internal → platform（即使 attachment 未设）', () => {
    expect(classifyKey({ transports: ['internal'] })).toBe('txt_webauthn_type_platform');
  });

  it('transport=usb → usb', () => {
    expect(classifyKey({ transports: ['usb'] })).toBe('txt_webauthn_type_usb');
  });

  it('transport=nfc → nfc', () => {
    expect(classifyKey({ transports: ['nfc'] })).toBe('txt_webauthn_type_nfc');
  });

  it('transport=ble → ble', () => {
    expect(classifyKey({ transports: ['ble'] })).toBe('txt_webauthn_type_ble');
  });

  it('transport=hybrid → ble', () => {
    expect(classifyKey({ transports: ['hybrid'] })).toBe('txt_webauthn_type_ble');
  });

  it('无 transports，无 attachment → generic', () => {
    expect(classifyKey({})).toBe('txt_webauthn_type_generic');
  });

  it('空 transports 数组，无 attachment → generic', () => {
    expect(classifyKey({ transports: [] })).toBe('txt_webauthn_type_generic');
  });

  it('attachment=cross-platform，transport=usb → usb（平台分类不命中时继续检测）', () => {
    expect(classifyKey({ attachment: 'cross-platform', transports: ['usb'] })).toBe('txt_webauthn_type_usb');
  });
});
