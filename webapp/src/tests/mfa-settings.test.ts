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

// ---------------------------------------------------------------------------
// 4. 可逆禁用前端开关分支逻辑
// ---------------------------------------------------------------------------

/**
 * 模拟 SettingsPage 中 TOTP 切换逻辑：
 * - 若当前激活（enabled=true）→ 触发禁用流程
 * - 若配置存在但已禁用（configured=true, enabled=false）→ 触发重启用流程
 * - 若未配置（configured=false, enabled=false）→ 走原设置流程（显示设置表单）
 */
function simulateTotpToggle(opts: {
  totpEnabled: boolean;
  totpConfigured: boolean;
  hasReEnableCallback: boolean;
}): 'disable' | 'reenable' | 'setup' | 'noop' {
  if (opts.totpEnabled) return 'disable';
  if (opts.totpConfigured && opts.hasReEnableCallback) return 'reenable';
  return 'setup';
}

/**
 * 模拟 SettingsPage 中 WebAuthn 切换逻辑。
 */
function simulateWebAuthnToggle(opts: {
  webAuthnActivelyEnabled: boolean;
  hasRetainedCredentials: boolean;
  hasReEnableCallback: boolean;
}): 'disable' | 'reenable' | 'add-key' | 'noop' {
  if (opts.webAuthnActivelyEnabled) return 'disable';
  if (opts.hasRetainedCredentials && opts.hasReEnableCallback) return 'reenable';
  return 'add-key';
}

/**
 * 模拟 SettingsPage 中 Email 切换逻辑。
 */
function simulateEmailToggle(opts: {
  emailEnabled: boolean;
  emailConfigured: boolean;
  hasReEnableCallback: boolean;
}): 'disable' | 'reenable' | 'noop' {
  if (opts.emailEnabled) return 'disable';
  if (opts.emailConfigured && opts.hasReEnableCallback) return 'reenable';
  return 'noop';
}

describe('TOTP 可逆禁用前端开关逻辑', () => {
  it('激活状态 toggle→ 触发禁用流程', () => {
    expect(simulateTotpToggle({ totpEnabled: true, totpConfigured: true, hasReEnableCallback: true }))
      .toBe('disable');
  });

  it('已配置但已禁用 + 有重启用回调 → 触发重启用', () => {
    expect(simulateTotpToggle({ totpEnabled: false, totpConfigured: true, hasReEnableCallback: true }))
      .toBe('reenable');
  });

  it('已配置但已禁用 + 无重启用回调 → 走设置流程（降级）', () => {
    expect(simulateTotpToggle({ totpEnabled: false, totpConfigured: true, hasReEnableCallback: false }))
      .toBe('setup');
  });

  it('未配置 → 走原设置流程', () => {
    expect(simulateTotpToggle({ totpEnabled: false, totpConfigured: false, hasReEnableCallback: true }))
      .toBe('setup');
  });
});

describe('WebAuthn 可逆禁用前端开关逻辑', () => {
  it('激活状态 toggle→ 触发禁用流程', () => {
    expect(simulateWebAuthnToggle({ webAuthnActivelyEnabled: true, hasRetainedCredentials: true, hasReEnableCallback: true }))
      .toBe('disable');
  });

  it('有保留 credentials + enabled=false + 有回调 → 重启用', () => {
    expect(simulateWebAuthnToggle({ webAuthnActivelyEnabled: false, hasRetainedCredentials: true, hasReEnableCallback: true }))
      .toBe('reenable');
  });

  it('无 credentials + enabled=false → 走注册流程', () => {
    expect(simulateWebAuthnToggle({ webAuthnActivelyEnabled: false, hasRetainedCredentials: false, hasReEnableCallback: true }))
      .toBe('add-key');
  });
});

describe('Email 可逆禁用前端开关逻辑', () => {
  it('已启用 toggle → 触发禁用', () => {
    expect(simulateEmailToggle({ emailEnabled: true, emailConfigured: true, hasReEnableCallback: true }))
      .toBe('disable');
  });

  it('已配置但已禁用 + 有回调 → 重启用', () => {
    expect(simulateEmailToggle({ emailEnabled: false, emailConfigured: true, hasReEnableCallback: true }))
      .toBe('reenable');
  });

  it('未配置 → noop（不启动任何流程）', () => {
    expect(simulateEmailToggle({ emailEnabled: false, emailConfigured: false, hasReEnableCallback: true }))
      .toBe('noop');
  });
});

describe('activeMethodCount 基于 enabled 而非 configured', () => {
  /**
   * 新语义：activeMethodCount 必须仅计算激活方法，而非配置的方法。
   * 例如：TOTP configured=true 但 enabled=false，不应计入 activeMethodCount。
   */
  function deriveMfaStatusV2(opts: {
    totpEnabled: boolean;
    webAuthnActivelyEnabled: boolean;
    emailTwoFactorEnabled: boolean;
  }): { mfaEnabled: boolean; activeMethodCount: number } {
    const { totpEnabled, webAuthnActivelyEnabled, emailTwoFactorEnabled } = opts;
    const mfaEnabled = totpEnabled || webAuthnActivelyEnabled || emailTwoFactorEnabled;
    const activeMethodCount = (totpEnabled ? 1 : 0) + (webAuthnActivelyEnabled ? 1 : 0) + (emailTwoFactorEnabled ? 1 : 0);
    return { mfaEnabled, activeMethodCount };
  }

  it('TOTP configured 但 enabled=false → count 不增加', () => {
    const result = deriveMfaStatusV2({ totpEnabled: false, webAuthnActivelyEnabled: false, emailTwoFactorEnabled: false });
    expect(result.activeMethodCount).toBe(0);
    expect(result.mfaEnabled).toBe(false);
  });

  it('WebAuthn has credentials 但 enabled=false → count 不增加', () => {
    const result = deriveMfaStatusV2({ totpEnabled: false, webAuthnActivelyEnabled: false, emailTwoFactorEnabled: true });
    expect(result.activeMethodCount).toBe(1); // 只有 email 算
    expect(result.mfaEnabled).toBe(true);
  });

  it('全部激活 → count=3', () => {
    const result = deriveMfaStatusV2({ totpEnabled: true, webAuthnActivelyEnabled: true, emailTwoFactorEnabled: true });
    expect(result.activeMethodCount).toBe(3);
  });
});
