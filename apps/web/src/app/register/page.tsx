'use client';

import { PASSWORD_POLICY } from '@ciphermesh/shared';
import { registerResponseSchema } from '@ciphermesh/validation';
import Link from 'next/link';
import { useState, type SyntheticEvent } from 'react';
import { AuthLayout } from '../../components/auth-layout';
import { Alert, Button, buttonClass, Field } from '../../components/ui';
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
      <AuthLayout
        title="Account created"
        description="Next, sign in and set up your vault."
        footer="Set up two-step sign-in from your account settings after signing in."
      >
        <Alert kind="success">Your account exists. Sign in to continue.</Alert>
        <Link className={buttonClass.primary} href="/login">
          Sign in
        </Link>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout
      title="Create an account"
      description="Synthetic data only: this is a development build of a university security project."
      footer={
        <>
          Already registered?{' '}
          <Link className="font-medium text-accent-300 hover:text-accent-200" href="/login">
            Sign in
          </Link>
        </>
      }
    >
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
        <p className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs leading-relaxed text-slate-400">
          This password signs you in to CipherMesh. Your Vault Passphrase, which protects your encryption keys, is a
          separate secret you will create later; never reuse this password for it.
        </p>
        {error === undefined ? null : <Alert kind="error">{error}</Alert>}
        <Button type="submit" disabled={busy}>
          Create account
        </Button>
      </form>
    </AuthLayout>
  );
}
