'use client';

import { stepUpResponseSchema } from '@ciphermesh/validation';
import { useState, type SyntheticEvent } from 'react';
import { api, describeError, formText } from '../lib/api';
import { Alert, Button, Card, Field } from './ui';

/**
 * Step-up with the ACCOUNT PASSWORD (and a TOTP code when MFA is on), CM-T021. The server records
 * the confirmation on the session; the browser cannot claim it. This form never asks for, or
 * accepts, the Vault Passphrase: the two secrets are separate (CD-01).
 */
export function StepUpForm({
  mfaEnabled,
  reason,
  onDone,
}: {
  readonly mfaEnabled: boolean;
  readonly reason: string;
  readonly onDone: () => void;
}) {
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    setBusy(true);
    try {
      await api('POST', '/auth/step-up', stepUpResponseSchema, {
        password: formText(form, 'password'),
        ...(mfaEnabled ? { code: formText(form, 'code') } : {}),
      });
      setError(undefined);
      onDone();
    } catch (e) {
      setError(describeError(e));
    } finally {
      target.reset();
      setBusy(false);
    }
  }

  return (
    <Card title="Confirm your account">
      <p className="text-sm text-slate-400">{reason}</p>
      <form className="space-y-3" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Account password" name="password" type="password" autoComplete="current-password" />
        {mfaEnabled ? (
          <Field label="Authentication code" name="code" autoComplete="one-time-code" inputMode="numeric" />
        ) : null}
        {error === undefined ? null : <Alert kind="error">{error}</Alert>}
        <Button type="submit" disabled={busy}>
          Confirm account
        </Button>
      </form>
    </Card>
  );
}
