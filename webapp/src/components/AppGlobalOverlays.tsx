import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import { t } from '@/lib/i18n';
import type { ToastMessage } from '@/lib/types';

export interface AppConfirmState {
  title: string;
  message: string;
  danger?: boolean;
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  hideCancel?: boolean;
  onConfirm: () => void;
}

interface AppGlobalOverlaysProps {
  toasts: ToastMessage[];
  onCloseToast: (id: string) => void;
  confirm: AppConfirmState | null;
  onCancelConfirm: () => void;
  pendingTotpOpen: boolean;
  totpCode: string;
  rememberDevice: boolean;
  onTotpCodeChange: (value: string) => void;
  onRememberDeviceChange: (checked: boolean) => void;
  onConfirmTotp: () => void;
  onCancelTotp: () => void;
  onUseRecoveryCode: () => void;
  totpSubmitting: boolean;
  /** Whether Email (provider 1) is available as a fallback from the TOTP dialog */
  totpHasEmailFallback?: boolean;
  /** Switch from TOTP dialog to Email OTP dialog */
  onSwitchFromTotpToEmail?: () => void;
  disableTotpOpen: boolean;
  disableTotpPassword: string;
  onDisableTotpPasswordChange: (value: string) => void;
  onConfirmDisableTotp: () => void;
  onCancelDisableTotp: () => void;
  disableTotpSubmitting: boolean;
  /** WebAuthn 2FA challenge flow */
  pendingWebAuthnOpen: boolean;
  webAuthnSubmitting: boolean;
  webAuthnHasTotpFallback: boolean;
  /** Whether Email (provider 1) is available as WebAuthn fallback */
  webAuthnHasEmailFallback?: boolean;
  onConfirmWebAuthn: () => void;
  onCancelWebAuthn: () => void;
  onSwitchToTotp: () => void;
  /** Switch from WebAuthn dialog to Email OTP dialog */
  onSwitchToEmail?: () => void;
  /** Email 2FA OTP flow (provider 1) */
  pendingEmailOpen: boolean;
  emailOtpCode: string;
  emailOtpMaskedAddress: string;
  emailOtpRememberDevice: boolean;
  onEmailOtpCodeChange: (value: string) => void;
  onEmailOtpRememberDeviceChange: (checked: boolean) => void;
  onConfirmEmailOtp: () => void;
  onCancelEmailOtp: () => void;
  onResendEmailOtp: () => void;
  emailOtpSubmitting: boolean;
  emailOtpResending: boolean;
}

export default function AppGlobalOverlays(props: AppGlobalOverlaysProps) {
  return (
    <>
      <ConfirmDialog
        open={!!props.confirm}
        title={props.confirm?.title || ''}
        message={props.confirm?.message || ''}
        danger={props.confirm?.danger}
        showIcon={props.confirm?.showIcon}
        confirmText={props.confirm?.confirmText}
        cancelText={props.confirm?.cancelText}
        hideCancel={props.confirm?.hideCancel}
        onConfirm={() => props.confirm?.onConfirm()}
        onCancel={props.onCancelConfirm}
      />

      <ConfirmDialog
        open={props.pendingTotpOpen}
        title={t('txt_two_step_verification')}
        message={t('txt_password_is_already_verified')}
        confirmText={t('txt_verify')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={props.totpSubmitting}
        cancelDisabled={props.totpSubmitting}
        onConfirm={props.onConfirmTotp}
        onCancel={props.onCancelTotp}
        afterActions={(
          <div className="dialog-extra">
            <div className="dialog-divider" />
            {props.totpHasEmailFallback && props.onSwitchFromTotpToEmail && (
              <button type="button" className="btn btn-secondary dialog-btn" disabled={props.totpSubmitting} onClick={props.onSwitchFromTotpToEmail}>
                {t('txt_use_email_code')}
              </button>
            )}
            <button type="button" className="btn btn-secondary dialog-btn" disabled={props.totpSubmitting} onClick={props.onUseRecoveryCode}>
              {t('txt_use_recovery_code')}
            </button>
          </div>
        )}
      >
        <label className="field">
          <span>{t('txt_totp_code')}</span>
          <input className="input" value={props.totpCode} autoComplete="one-time-code" onInput={(e) => props.onTotpCodeChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
        <label className="check-line check-line-compact">
          <input type="checkbox" checked={props.rememberDevice} onChange={(e) => props.onRememberDeviceChange((e.currentTarget as HTMLInputElement).checked)} />
          <span>{t('txt_trust_this_device_for_30_days')}</span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.disableTotpOpen}
        title={t('txt_disable_totp')}
        message={t('txt_enter_master_password_to_disable_two_step_verification')}
        confirmText={t('txt_disable_totp')}
        cancelText={t('txt_cancel')}
        danger
        showIcon={false}
        confirmDisabled={props.disableTotpSubmitting}
        cancelDisabled={props.disableTotpSubmitting}
        onConfirm={props.onConfirmDisableTotp}
        onCancel={props.onCancelDisableTotp}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" autoComplete="current-password" value={props.disableTotpPassword} onInput={(e) => props.onDisableTotpPasswordChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.pendingWebAuthnOpen}
        title={t('txt_two_step_verification')}
        message={t('txt_webauthn_waiting')}
        confirmText={props.webAuthnSubmitting ? t('txt_webauthn_waiting') : t('txt_webauthn_use_key')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={props.webAuthnSubmitting}
        cancelDisabled={props.webAuthnSubmitting}
        onConfirm={props.onConfirmWebAuthn}
        onCancel={props.onCancelWebAuthn}
        afterActions={(
          <div className="dialog-extra">
            <div className="dialog-divider" />
            {props.webAuthnHasTotpFallback && (
              <button type="button" className="btn btn-secondary dialog-btn" disabled={props.webAuthnSubmitting} onClick={props.onSwitchToTotp}>
                {t('txt_use_totp_instead')}
              </button>
            )}
            {props.webAuthnHasEmailFallback && props.onSwitchToEmail && (
              <button type="button" className="btn btn-secondary dialog-btn" disabled={props.webAuthnSubmitting} onClick={props.onSwitchToEmail}>
                {t('txt_use_email_code')}
              </button>
            )}
            <button type="button" className="btn btn-secondary dialog-btn" disabled={props.webAuthnSubmitting} onClick={props.onUseRecoveryCode}>
              {t('txt_use_recovery_code')}
            </button>
          </div>
        )}
      />

      <ConfirmDialog
        open={props.pendingEmailOpen}
        title={t('txt_two_step_verification')}
        message={props.emailOtpMaskedAddress ? t('txt_email_otp_sent_to', { email: props.emailOtpMaskedAddress }) : t('txt_two_step_verification')}
        confirmText={t('txt_verify')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={props.emailOtpSubmitting || props.emailOtpResending}
        cancelDisabled={props.emailOtpSubmitting}
        onConfirm={props.onConfirmEmailOtp}
        onCancel={props.onCancelEmailOtp}
        afterActions={(
          <div className="dialog-extra">
            <div className="dialog-divider" />
            <button
              type="button"
              className="btn btn-secondary dialog-btn"
              disabled={props.emailOtpSubmitting || props.emailOtpResending}
              onClick={props.onResendEmailOtp}
            >
              {props.emailOtpResending ? t('txt_email_mfa_setup_sending') : t('txt_email_otp_resend')}
            </button>
            <button type="button" className="btn btn-secondary dialog-btn" disabled={props.emailOtpSubmitting} onClick={props.onUseRecoveryCode}>
              {t('txt_use_recovery_code')}
            </button>
          </div>
        )}
      >
        <label className="field">
          <span>{t('txt_email_otp_code')}</span>
          <input
            className="input"
            value={props.emailOtpCode}
            autoComplete="one-time-code"
            inputMode="numeric"
            onInput={(e) => props.onEmailOtpCodeChange((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <label className="check-line check-line-compact">
          <input
            type="checkbox"
            checked={props.emailOtpRememberDevice}
            onChange={(e) => props.onEmailOtpRememberDeviceChange((e.currentTarget as HTMLInputElement).checked)}
          />
          <span>{t('txt_trust_this_device_for_30_days')}</span>
        </label>
      </ConfirmDialog>

      <ToastHost toasts={props.toasts} onClose={props.onCloseToast} />
    </>
  );
}
