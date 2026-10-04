'use client';

import { PASSWORD_POLICY } from '@ciphermesh/shared';
import { registerResponseSchema } from '@ciphermesh/validation';
import Link from 'next/link';
import { useState, type SyntheticEvent } from 'react';
import { Alert, Button, Card, Field } from '../../components/ui';
import { api, describeError, formText } from '../../lib/api';

export default function RegisterPage() {
  const [error, setError] = useState<string | undefined>();
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    // The form is never submitted by the browser: fetch() sends JSON with the real Origin.
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const password = formText(form, 'password');
    if (password !== formText(form, 'confirm')) {
      setError('The two passwords do not match.');
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await api('POST', '/auth/register', registerResponseSchema, {
        email: formText(form, 'email'),
        displayName: formText(form, 'displayName'),
        password,
      });
      target.reset();
      setDone(true);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Card title="Account created">
        <Alert kind="info">Your account exists. Sign in to continue.</Alert>
        <Link className="text-sky-400 underline" href="/login">
          Sign in
        </Link>
      </Card>
    );
  }

  return (
    <div className="mx-auto max-w-md space-y-6">
      <h1 className="text-2xl font-semibold">Create an account</h1>
      <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Email address" name="email" type="email" autoComplete="email" required />
        <Field label="Display name" name="displayName" autoComplete="nickname" maxLength={80} required />
        <Field
          label="Account password"
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={PASSWORD_POLICY.minLength}
          maxLength={PASSWORD_POLICY.maxLength}
          hint="12 to 128 characters. A long passphrase is best. Breached passwords are refused."
          required
        />
        <Field label="Repeat the password" name="confirm" type="password" autoComplete="new-password" required />
        <p className="text-xs text-slate-400">
          This password signs you in to CipherMesh. Your Vault Passphrase, which protects your encryption keys, is a
          separate secret you will create later; never reuse this password for it.
        </p>
        {error === undefined ? null : <Alert kind="error">{error}</Alert>}
        <Button type="submit" disabled={busy}>
          Create account
        </Button>
      </form>
      <p className="text-sm text-slate-400">
        Already registered?{' '}
        <Link className="text-sky-400 underline" href="/login">
          Sign in
        </Link>
      </p>
    </div>
  );
}
