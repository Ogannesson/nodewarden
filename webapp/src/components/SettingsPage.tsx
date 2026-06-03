import { useEffect, useMemo, useState } from 'preact/hooks';
import { Clipboard, KeyRound, RefreshCw, ShieldCheck, ShieldOff, Trash2, UsbIcon } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import qrcode from 'qrcode-generator';
import type { Profile } from '@/lib/types';
import { AVAILABLE_LOCALES, getLocale, setLocale, t, type Locale } from '@/lib/i18n';
import ConfirmDialog from '@/components/ConfirmDialog';
import type { WebAuthnKeyInfo } from '@/lib/api/auth';

interface SettingsPageProps {
  profile: Profile;
  totpEnabled: boolean;
  lockTimeoutMinutes: 0 | 1 | 5 | 15 | 30;
  sessionTimeoutAction: 'lock' | 'logout';
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onSavePasswordHint: (masterPasswordHint: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string) => Promise<void>;
  onOpenDisableTotp: () => void;
  onGetRecoveryCode: (masterPassword: string) => Promise<string>;
  onGetApiKey: (masterPassword: string) => Promise<string>;
  onRotateApiKey: (masterPassword: string) => Promise<string>;
  onLockTimeoutChange: (minutes: 0 | 1 | 5 | 15 | 30) => void;
  onSessionTimeoutActionChange: (action: 'lock' | 'logout') => void;
  onNotify?: (type: 'success' | 'error', text: string) => void;
  webAuthnKeys?: WebAuthnKeyInfo[];
  webAuthnKeysLoading?: boolean;
  onRegisterWebAuthnKey?: (masterPassword: string, keyName: string) => Promise<WebAuthnKeyInfo[]>;
  onDeleteWebAuthnKey?: (masterPassword: string, keyId: string) => Promise<void>;
}

const LOCK_TIMEOUT_OPTIONS = [
  { value: 1, labelKey: 'txt_timeout_1_minute' },
  { value: 5, labelKey: 'txt_timeout_5_minutes' },
  { value: 15, labelKey: 'txt_timeout_15_minutes' },
  { value: 30, labelKey: 'txt_timeout_30_minutes' },
  { value: 0, labelKey: 'txt_timeout_never' },
] as const;

function randomBase32Secret(length: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let out = '';
  const maxUnbiasedByte = Math.floor(256 / alphabet.length) * alphabet.length;
  while (out.length < length) {
    const random = crypto.getRandomValues(new Uint8Array(length));
    for (const x of random) {
      if (x >= maxUnbiasedByte) continue;
      out += alphabet[x % alphabet.length];
      if (out.length >= length) break;
    }
  }
  return out;
}

function buildOtpUri(email: string, secret: string): string {
  const issuer = 'NodeWarden';
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function clearLegacyTotpSetupSecrets(): void {
  if (typeof window === 'undefined') return;
  const prefix = 'nodewarden.totp.secret.';
  const keys: string[] = [];
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    if (key?.startsWith(prefix)) keys.push(key);
  }
  for (const key of keys) {
    window.localStorage.removeItem(key);
  }
}

export default function SettingsPage(props: SettingsPageProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [passwordHint, setPasswordHint] = useState(props.profile.masterPasswordHint || '');
  const [secret, setSecret] = useState(() => randomBase32Secret(32));
  const [token, setToken] = useState('');
  const [totpLocked, setTotpLocked] = useState(props.totpEnabled);
  const [recoveryCode, setRecoveryCode] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [rotateApiKeyConfirmOpen, setRotateApiKeyConfirmOpen] = useState(false);
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false);
  const [masterPasswordPrompt, setMasterPasswordPrompt] = useState<null | 'recovery' | 'apiKey' | 'rotateApiKey'>(null);
  const [masterPasswordPromptValue, setMasterPasswordPromptValue] = useState('');
  const [masterPasswordPromptSubmitting, setMasterPasswordPromptSubmitting] = useState(false);
  const [selectedLocale, setSelectedLocale] = useState<Locale>(() => getLocale());

  // WebAuthn state
  const [webAuthnKeyName, setWebAuthnKeyName] = useState('');
  const [webAuthnRegistering, setWebAuthnRegistering] = useState(false);
  const [webAuthnMasterPasswordPrompt, setWebAuthnMasterPasswordPrompt] = useState<null | 'register' | 'delete'>(null);
  const [webAuthnMasterPasswordValue, setWebAuthnMasterPasswordValue] = useState('');
  const [webAuthnMasterPasswordSubmitting, setWebAuthnMasterPasswordSubmitting] = useState(false);
  const [webAuthnDeleteKeyId, setWebAuthnDeleteKeyId] = useState<string | null>(null);
  const [webAuthnDeleteKeyName, setWebAuthnDeleteKeyName] = useState('');
  const webAuthnSupported = typeof window !== 'undefined' && !!(window.PublicKeyCredential);

  useEffect(() => {
    clearLegacyTotpSetupSecrets();
  }, []);

  useEffect(() => {
    if (!props.totpEnabled) {
      setTotpLocked(false);
      return;
    }
    setTotpLocked(true);
  }, [props.totpEnabled]);

  useEffect(() => {
    setPasswordHint(props.profile.masterPasswordHint || '');
  }, [props.profile.masterPasswordHint]);

  const qrDataUrl = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(buildOtpUri(props.profile.email, secret));
    qr.make();
    // Keep a visible quiet zone so authenticator apps can scan reliably in both themes.
    const svg = qr.createSvgTag({ scalable: true, margin: 4 });
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  }, [props.profile.email, secret]);

  async function enableTotp(): Promise<void> {
    try {
      await props.onEnableTotp(secret, token);
      setTotpLocked(true);
    } catch {
      // Keep inputs editable after a failed attempt.
    }
  }

  function openMasterPasswordPrompt(action: 'recovery' | 'apiKey' | 'rotateApiKey'): void {
    setMasterPasswordPrompt(action);
    setMasterPasswordPromptValue('');
  }

  function closeMasterPasswordPrompt(): void {
    if (masterPasswordPromptSubmitting) return;
    setMasterPasswordPrompt(null);
    setMasterPasswordPromptValue('');
  }

  async function submitMasterPasswordPrompt(): Promise<void> {
    if (!masterPasswordPrompt || masterPasswordPromptSubmitting) return;
    const masterPassword = masterPasswordPromptValue;
    setMasterPasswordPromptSubmitting(true);
    try {
      if (masterPasswordPrompt === 'recovery') {
        const code = await props.onGetRecoveryCode(masterPassword);
        setRecoveryCode(code);
        props.onNotify?.('success', t('txt_recovery_code_loaded'));
      } else if (masterPasswordPrompt === 'apiKey') {
        const key = await props.onGetApiKey(masterPassword);
        setApiKey(key);
        setApiKeyDialogOpen(true);
      } else {
        const key = await props.onRotateApiKey(masterPassword);
        setApiKey(key);
        setApiKeyDialogOpen(true);
        props.onNotify?.('success', t('txt_api_key_rotated'));
      }
      setMasterPasswordPrompt(null);
      setMasterPasswordPromptValue('');
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_master_password_is_required_2'));
    } finally {
      setMasterPasswordPromptSubmitting(false);
    }
  }

  const masterPasswordPromptTitle =
    masterPasswordPrompt === 'recovery'
      ? t('txt_view_recovery_code')
      : masterPasswordPrompt === 'rotateApiKey'
        ? t('txt_rotate_api_key')
        : t('txt_view_api_key');

  function formatDateTime(value: string | null | undefined): string {
    if (!value) return t('txt_dash');
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleString();
  }

  async function changeLocale(next: Locale): Promise<void> {
    if (next === getLocale()) return;
    setSelectedLocale(next);
    await setLocale(next);
    window.location.reload();
  }

  function openWebAuthnMasterPasswordPrompt(action: 'register'): void;
  function openWebAuthnMasterPasswordPrompt(action: 'delete', keyId: string, keyName: string): void;
  function openWebAuthnMasterPasswordPrompt(action: 'register' | 'delete', keyId?: string, keyName?: string): void {
    setWebAuthnMasterPasswordPrompt(action);
    setWebAuthnMasterPasswordValue('');
    if (action === 'delete') {
      setWebAuthnDeleteKeyId(keyId ?? null);
      setWebAuthnDeleteKeyName(keyName ?? '');
    }
  }

  function closeWebAuthnMasterPasswordPrompt(): void {
    if (webAuthnMasterPasswordSubmitting) return;
    setWebAuthnMasterPasswordPrompt(null);
    setWebAuthnMasterPasswordValue('');
    setWebAuthnDeleteKeyId(null);
    setWebAuthnDeleteKeyName('');
  }

  async function submitWebAuthnMasterPassword(): Promise<void> {
    if (!webAuthnMasterPasswordPrompt || webAuthnMasterPasswordSubmitting) return;
    const masterPassword = webAuthnMasterPasswordValue;
    setWebAuthnMasterPasswordSubmitting(true);
    try {
      if (webAuthnMasterPasswordPrompt === 'register') {
        setWebAuthnRegistering(true);
        try {
          await props.onRegisterWebAuthnKey?.(masterPassword, webAuthnKeyName);
          props.onNotify?.('success', t('txt_webauthn_register_success'));
          setWebAuthnKeyName('');
        } finally {
          setWebAuthnRegistering(false);
        }
      } else if (webAuthnMasterPasswordPrompt === 'delete' && webAuthnDeleteKeyId) {
        await props.onDeleteWebAuthnKey?.(masterPassword, webAuthnDeleteKeyId);
        props.onNotify?.('success', t('txt_webauthn_delete_success'));
      }
      setWebAuthnMasterPasswordPrompt(null);
      setWebAuthnMasterPasswordValue('');
      setWebAuthnDeleteKeyId(null);
      setWebAuthnDeleteKeyName('');
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_webauthn_register_failed'));
    } finally {
      setWebAuthnMasterPasswordSubmitting(false);
    }
  }

  return (
    <div className="settings-modules-grid">
      <section className="card settings-module">
        <h3>{t('txt_session_timeout')}</h3>
        <div className="session-timeout-fields">
          <label className="field">
            <span>{t('txt_timeout_time')}</span>
            <select
              className="input"
              value={String(props.lockTimeoutMinutes)}
              onInput={(e) => props.onLockTimeoutChange(Number((e.currentTarget as HTMLSelectElement).value) as 0 | 1 | 5 | 15 | 30)}
            >
              {LOCK_TIMEOUT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {t(option.labelKey)}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('txt_timeout_action')}</span>
            <select
              className="input"
              value={props.sessionTimeoutAction}
              onInput={(e) => props.onSessionTimeoutActionChange((e.currentTarget as HTMLSelectElement).value === 'logout' ? 'logout' : 'lock')}
            >
              <option value="logout">{t('txt_timeout_action_logout')}</option>
              <option value="lock">{t('txt_timeout_action_lock')}</option>
            </select>
          </label>
        </div>
      </section>

      <section className="card settings-module">
        <h3>{t('txt_language')}</h3>
        <label className="field">
          <span>{t('txt_display_language')}</span>
          <select
            className="input"
            value={selectedLocale}
            onInput={(e) => void changeLocale((e.currentTarget as HTMLSelectElement).value as Locale)}
          >
            {AVAILABLE_LOCALES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <div className="field-help">{t('txt_language_saved_locally')}</div>
        </label>
      </section>

      <section className="card settings-module">
        <h3>{t('txt_change_master_password')}</h3>
        <label className="field">
          <span>{t('txt_current_password')}</span>
          <input
            className="input"
            type="password"
            value={currentPassword}
            onInput={(e) => setCurrentPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <div className="field-grid">
          <label className="field">
            <span>{t('txt_new_password')}</span>
            <input className="input" type="password" value={newPassword} onInput={(e) => setNewPassword((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>{t('txt_confirm_password')}</span>
            <input className="input" type="password" value={newPassword2} onInput={(e) => setNewPassword2((e.currentTarget as HTMLInputElement).value)} />
          </label>
        </div>
        <button
          type="button"
          className="btn btn-danger"
          onClick={() => void props.onChangePassword(currentPassword, newPassword, newPassword2)}
        >
          <KeyRound size={14} className="btn-icon" />
          {t('txt_change_password')}
        </button>
      </section>

      <section className="card settings-module">
        <h3>{t('txt_password_hint_optional')}</h3>
        <label className="field">
          <span>{t('txt_password_hint')}</span>
          <input
            className="input"
            maxLength={120}
            value={passwordHint}
            placeholder={t('txt_password_hint_placeholder')}
            onInput={(e) => setPasswordHint((e.currentTarget as HTMLInputElement).value)}
          />
          <div className="field-help">{t('txt_password_hint_register_help')}</div>
        </label>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void props.onSavePasswordHint(passwordHint)}
        >
          {t('txt_save_profile')}
        </button>
      </section>

      <section className="card settings-module">
        <div className="settings-module-head">
          <h3>{t('txt_totp')}</h3>
          {totpLocked && (
            <span className="totp-status-pill">
              <ShieldCheck size={14} aria-hidden="true" />
              {t('txt_enabled')}
            </span>
          )}
        </div>
        <div className="totp-grid">
          <div className="totp-qr">
            <img src={qrDataUrl} alt="TOTP QR" />
          </div>
          <div>
            <div>
              <label className="field">
                <span>{t('txt_authenticator_key')}</span>
                <div className="totp-secret-input-wrap">
                  <input className="input totp-secret-input" value={secret} disabled={totpLocked} onInput={(e) => setSecret((e.currentTarget as HTMLInputElement).value.toUpperCase())} />
                  <div className="totp-secret-actions">
                    <button
                      type="button"
                      className="btn btn-secondary small totp-secret-icon-btn"
                      disabled={totpLocked}
                      title={t('txt_regenerate')}
                      aria-label={t('txt_regenerate')}
                      onClick={() => setSecret(randomBase32Secret(32))}
                    >
                      <RefreshCw size={14} className="btn-icon" />
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small totp-secret-icon-btn"
                      disabled={totpLocked}
                      title={t('txt_copy_secret')}
                      aria-label={t('txt_copy_secret')}
                      onClick={() => {
                        void copyTextToClipboard(secret, { successMessage: t('txt_secret_copied') });
                      }}
                    >
                      <Clipboard size={14} className="btn-icon" />
                    </button>
                  </div>
                </div>
              </label>
              <label className="field">
                <span>{t('txt_verification_code')}</span>
                <input className="input" value={token} disabled={totpLocked} onInput={(e) => setToken((e.currentTarget as HTMLInputElement).value)} />
              </label>
              <div className="actions">
                <button type="button" className="btn btn-primary" disabled={totpLocked} onClick={() => void enableTotp()}>
                  <ShieldCheck size={14} className="btn-icon" />
                  {totpLocked ? t('txt_enabled') : t('txt_enable_totp')}
                </button>
                <button type="button" className="btn btn-danger" disabled={!totpLocked} onClick={props.onOpenDisableTotp}>
                  <ShieldOff size={14} className="btn-icon" />
                  {t('txt_disable_totp')}
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="card settings-module">
        <div className="settings-module-head">
          <h3>{t('txt_webauthn')}</h3>
          {(props.webAuthnKeys ?? []).length > 0 && (
            <span className="totp-status-pill">
              <ShieldCheck size={14} aria-hidden="true" />
              {t('txt_webauthn_enabled')}
            </span>
          )}
        </div>

        {!webAuthnSupported && (
          <p className="muted-inline settings-field-note">{t('txt_webauthn_not_supported')}</p>
        )}

        {webAuthnSupported && (
          <>
            {(props.webAuthnKeys ?? []).length > 0 && (
              <div className="webauthn-keys-list">
                <div className="field-label">{t('txt_webauthn_keys')}</div>
                {(props.webAuthnKeys ?? []).map((key) => (
                  <div key={key.id} className="webauthn-key-row">
                    <div className="webauthn-key-info">
                      <UsbIcon size={14} className="webauthn-key-icon" aria-hidden="true" />
                      <span className="webauthn-key-name">{key.name}</span>
                      <span className="webauthn-key-date muted-inline">
                        {t('txt_webauthn_created_at', { date: formatDateTime(key.createdAt) })}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn btn-danger small"
                      onClick={() => openWebAuthnMasterPasswordPrompt('delete', key.id, key.name)}
                    >
                      <Trash2 size={12} className="btn-icon" />
                      {t('txt_webauthn_delete_key')}
                    </button>
                  </div>
                ))}
              </div>
            )}

            {(props.webAuthnKeys ?? []).length === 0 && !props.webAuthnKeysLoading && (
              <p className="muted-inline settings-field-note">{t('txt_webauthn_no_keys')}</p>
            )}

            <div className="webauthn-add-section">
              <label className="field">
                <span>{t('txt_webauthn_key_name')}</span>
                <input
                  className="input"
                  value={webAuthnKeyName}
                  placeholder={t('txt_webauthn_key_name_placeholder')}
                  onInput={(e) => setWebAuthnKeyName((e.currentTarget as HTMLInputElement).value)}
                  disabled={webAuthnRegistering}
                />
              </label>
              <button
                type="button"
                className="btn btn-primary"
                disabled={webAuthnRegistering || !props.onRegisterWebAuthnKey}
                onClick={() => openWebAuthnMasterPasswordPrompt('register')}
              >
                <ShieldCheck size={14} className="btn-icon" />
                {webAuthnRegistering ? t('txt_webauthn_registering') : t('txt_webauthn_add_key')}
              </button>
            </div>
          </>
        )}
      </section>

      <section className="settings-module sensitive-actions-module">
        <div className="sensitive-actions-grid">
          <div className="sensitive-action">
            <div>
              <h4>{t('txt_recovery_code')}</h4>
              <p className="muted-inline settings-field-note">
                {t('txt_this_is_a_one_time_code_after_it_is_used_a_new_code_is_generated_automatically')}
              </p>
            </div>
            <div className="actions">
              <button type="button" className="btn btn-secondary" onClick={() => openMasterPasswordPrompt('recovery')}>
                <ShieldCheck size={14} className="btn-icon" />
                {t('txt_view_recovery_code')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!recoveryCode}
                onClick={() => {
                  void copyTextToClipboard(recoveryCode, { successMessage: t('txt_recovery_code_copied') });
                }}
              >
                <Clipboard size={14} className="btn-icon" />
                {t('txt_copy_code')}
              </button>
            </div>
            {recoveryCode && (
              <div className="recovery-code-card">
                <div className="recovery-code-value">{recoveryCode}</div>
              </div>
            )}
          </div>

          <div className="sensitive-action">
            <div>
              <h4>{t('txt_api_key')}</h4>
              <p className="muted-inline settings-field-note">{t('txt_api_key_dialog_intro')}</p>
            </div>
            <div className="actions">
              <button type="button" className="btn btn-secondary" onClick={() => openMasterPasswordPrompt('apiKey')}>
                <KeyRound size={14} className="btn-icon" />
                {t('txt_view_api_key')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setRotateApiKeyConfirmOpen(true)}
              >
                <RefreshCw size={14} className="btn-icon" />
                {t('txt_rotate_api_key')}
              </button>
            </div>
          </div>
        </div>
      </section>
      <ConfirmDialog
        open={masterPasswordPrompt !== null}
        title={masterPasswordPromptTitle}
        message={t('txt_enter_master_password_to_continue')}
        confirmText={t('txt_continue')}
        cancelText={t('txt_cancel')}
        confirmDisabled={masterPasswordPromptSubmitting || !masterPasswordPromptValue.trim()}
        cancelDisabled={masterPasswordPromptSubmitting}
        onConfirm={() => void submitMasterPasswordPrompt()}
        onCancel={closeMasterPasswordPrompt}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={masterPasswordPromptValue}
            onInput={(e) => setMasterPasswordPromptValue((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>
      <ConfirmDialog
        open={apiKeyDialogOpen}
        title={t('txt_api_key')}
        message={t('txt_api_key_dialog_intro')}
        hideCancel
        confirmText={t('txt_close')}
        onConfirm={() => setApiKeyDialogOpen(false)}
        onCancel={() => setApiKeyDialogOpen(false)}
      >
        <div className="api-key-warning-panel">
          <div className="api-key-warning-title">{t('txt_warning')}</div>
          <div className="api-key-warning-body">{t('txt_api_key_warning_body')}</div>
        </div>

        <div className="api-key-credentials-panel">
          <div className="api-key-credentials-title">
            <KeyRound size={15} />
            <span>{t('txt_oauth_client_credentials')}</span>
          </div>
          {([
            [t('txt_client_id'), `user.${props.profile.id}`],
            [t('txt_client_secret'), apiKey],
            [t('txt_scope'), 'api'],
            [t('txt_grant_type'), 'client_credentials'],
          ] as [string, string][]).map(([label, value]) => (
            <label key={label} className="field">
              <span>{label}</span>
              <div className="api-key-credential-row">
                <input className="input" readOnly value={value} onFocus={(e) => (e.currentTarget as HTMLInputElement).select()} />
                <button
                  type="button"
                  className="btn btn-secondary small"
                  onClick={() => void copyTextToClipboard(value, { successMessage: t('txt_copied') })}
                >
                  <Clipboard size={14} className="btn-icon" />
                  {t('txt_copy')}
                </button>
              </div>
            </label>
          ))}
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        open={rotateApiKeyConfirmOpen}
        title={t('txt_rotate_api_key')}
        message={t('txt_rotate_api_key_confirm')}
        danger
        onConfirm={() => {
          setRotateApiKeyConfirmOpen(false);
          openMasterPasswordPrompt('rotateApiKey');
        }}
        onCancel={() => setRotateApiKeyConfirmOpen(false)}
      />
      <ConfirmDialog
        open={webAuthnMasterPasswordPrompt !== null}
        title={webAuthnMasterPasswordPrompt === 'delete'
          ? t('txt_webauthn_delete_key_confirm_title')
          : t('txt_webauthn_add_key')}
        message={webAuthnMasterPasswordPrompt === 'delete'
          ? t('txt_webauthn_delete_key_confirm_msg', { name: webAuthnDeleteKeyName })
          : t('txt_enter_master_password_to_continue')}
        confirmText={webAuthnMasterPasswordPrompt === 'delete' ? t('txt_webauthn_delete_key') : t('txt_continue')}
        cancelText={t('txt_cancel')}
        danger={webAuthnMasterPasswordPrompt === 'delete'}
        confirmDisabled={webAuthnMasterPasswordSubmitting || !webAuthnMasterPasswordValue.trim()}
        cancelDisabled={webAuthnMasterPasswordSubmitting}
        onConfirm={() => void submitWebAuthnMasterPassword()}
        onCancel={closeWebAuthnMasterPasswordPrompt}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={webAuthnMasterPasswordValue}
            onInput={(e) => setWebAuthnMasterPasswordValue((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        {webAuthnMasterPasswordPrompt === 'register' && webAuthnRegistering && (
          <p className="muted-inline">{t('txt_webauthn_registering')}</p>
        )}
      </ConfirmDialog>
    </div>
  );
}
