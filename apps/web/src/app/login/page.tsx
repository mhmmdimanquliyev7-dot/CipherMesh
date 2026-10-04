'use client';

import { loginResponseSchema, z } from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type SyntheticEvent } from 'react';
import { Alert, Button, Field, SecondaryButton } from '../../components/ui';
import { api, describeError, formText } from '../../lib/api';

const authenticatedSchema = z.strictObject({ status: z.literal('authenticated') });
const recoverySchema = z.strictObject({ status: z.literal('authenticated'), recoveryCodesRemaining: z.number() });

/**
 * Login (DF-01). After the password, an MFA account receives only a short-lived pre-authentication
 * cookie; the session cookie is issued after the second factor. Both cookies are HttpOnly and
 * invisible to this page.
 */
export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<'password' | 'totp' | 'recovery'>('password');
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  function onPassword(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const target = event.currentTarget;
    void run(async () => {
      const result = await api('POST', '/auth/login', loginResponseSchema, {
        email: formText(form, 'email'),
        password: formText(form, 'password'),
      });
      target.reset();
      if (result.status === 'mfa_required') setStep('totp');
      else router.push('/account');
    });
  }

  function onSecondFactor(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = formText(new FormData(event.currentTarget), 'code').trim();
    void run(async () => {
      if (step === 'totp') {
        await api('POST', '/auth/mfa/verify', authenticatedSchema, { code: value });
      } else {
        await api('POST', '/auth/mfa/recovery', recoverySchema, { recoveryCode: value });
      }
      router.push('/account');
    });
  }

  return (
    <div className="mx-auto max-w-md space-y-6">
      <h1 className="text-2xl font-semibold">Sign in</h1>
      {step === 'password' ? (
        <form className="space-y-4" onSubmit={onPassword} noValidate>
          <Field label="Email address" name="email" type="email" autoComplete="username" required />
          <Field label="Account password" name="password" type="password" autoComplete="current-password" required />
          {error === undefined ? null : <Alert kind="error">{error}</Alert>}
          <Button type="submit" disabled={busy}>
            Continue
          </Button>
        </form>
      ) : (
        <form className="space-y-4" onSubmit={onSecondFactor} noValidate>
          <Alert kind="info">
            {step === 'totp'
              ? 'Enter the six-digit code from your authenticator app.'
              : 'Enter one of your recovery codes. Each code works once; your other sessions will be signed out.'}
          </Alert>
          <Field
            key={step}
            label={step === 'totp' ? 'Authentication code' : 'Recovery code'}
            name="code"
            autoComplete="one-time-code"
            inputMode={step === 'totp' ? 'numeric' : 'text'}
            required
          />
          {error === undefined ? null : <Alert kind="error">{error}</Alert>}
          <div className="flex gap-3">
            <Button type="submit" disabled={busy}>
              Verify
            </Button>
            <SecondaryButton
              type="button"
              onClick={() => {
                setStep(step === 'totp' ? 'recovery' : 'totp');
              }}
            >
              {step === 'totp' ? 'Use a recovery code' : 'Use the authenticator app'}
            </SecondaryButton>
          </div>
        </form>
      )}
      <p className="text-sm text-slate-400">
        No account?{' '}
        <Link className="text-sky-400 underline" href="/register">
          Create one
        </Link>
      </p>
    </div>
  );
}
