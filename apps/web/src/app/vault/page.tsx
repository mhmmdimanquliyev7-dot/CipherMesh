'use client';

import { checkVaultPassphrase, VAULT_PASSPHRASE_POLICY } from '@ciphermesh/crypto';
import Link from 'next/link';
import { useState, type ReactNode, type SyntheticEvent } from 'react';
import { StepUpForm } from '../../components/step-up-form';
import { Alert, Button, Card, Field, SecondaryButton } from '../../components/ui';
import { formText } from '../../lib/api';
import {
  vaultController,
  StepUpRequired,
  type AccountView,
  type DirectoryResult,
  type IdentityView,
  type LockReason,
  type VaultView,
} from '../../vault/controller';
import { describeVaultError, PASSPHRASE_PROBLEM_TEXT } from '../../vault/messages';
import { useVault } from '../../vault/use-vault';

/**
 * The Vault page (Phase 4, CM-T025 to CM-T028). Every cryptographic step runs in this browser
 * through @ciphermesh/crypto; this page only collects input and shows real state.
 *
 * Passphrases are read from the form on submit and the form is reset right after; they are never
 * kept in React state, never logged and never written to storage. Private keys are never shown:
 * there is no "show private key" feature.
 */
export default function VaultPage() {
  const view = useVault();
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Vault</h1>
      <VaultContent view={view} />
    </div>
  );
}

function VaultContent({ view }: { readonly view: VaultView }) {
  switch (view.kind) {
    case 'loading':
      return <p className="text-slate-400">Loading…</p>;
    case 'signed-out':
      return (
        <Alert kind="info">
          Sign in first.{' '}
          <Link className="underline" href="/login">
            Go to sign in
          </Link>
        </Alert>
      );
    case 'failed':
      return <Alert kind="error">{describeVaultError({ code: view.code })}</Alert>;
    case 'not-configured':
      return <Setup account={view.account} />;
    case 'locked':
      return <Locked account={view.account} identity={view.identity} lockReason={view.lockReason} />;
    case 'unlocked':
      return <Unlocked account={view.account} identity={view.identity} />;
  }
}

/** The two secrets, side by side (CD-01, security-ui section 2.8). */
function TwoSecrets() {
  return (
    <Card title="Two different secrets">
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="font-medium text-slate-200">Account password</dt>
          <dd className="text-slate-400">
            Proves to the CipherMesh server who you are. You type it when you sign in and when you confirm your account.
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-200">Vault Passphrase</dt>
          <dd className="text-slate-400">
            Protects your private keys. It never leaves this browser: the server never receives it, cannot check it and
            cannot recover it. Do not reuse your account password.
          </dd>
        </div>
      </dl>
    </Card>
  );
}

const STEP_UP_MS = { standard: 15 * 60_000, strict: 5 * 60_000 } as const;
const stepUpFresh = (account: AccountView, window: 'standard' | 'strict'): boolean =>
  account.stepUpAt !== null && Date.now() - new Date(account.stepUpAt).getTime() < STEP_UP_MS[window] - 30_000;

/** Runs a vault action with a busy flag; maps errors to messages; clears the form afterwards. */
function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [stepUpNeeded, setStepUpNeeded] = useState(false);
  async function run(form: HTMLFormElement, action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      if (e instanceof StepUpRequired) setStepUpNeeded(true);
      setError(describeVaultError(e));
    } finally {
      form.reset();
      setBusy(false);
    }
  }
  return { busy, error, setError, stepUpNeeded, setStepUpNeeded, run };
}

function PassphraseField({
  label,
  name,
  hint,
}: {
  readonly label: string;
  readonly name: string;
  readonly hint?: string;
}) {
  return (
    <Field
      label={label}
      name={name}
      type="password"
      autoComplete="off"
      spellCheck={false}
      {...(hint === undefined ? {} : { hint })}
    />
  );
}

function policyProblems(passphrase: string, repeat: string, account: AccountView): string | undefined {
  if (passphrase !== repeat) return 'The two Vault Passphrases do not match.';
  const check = checkVaultPassphrase(passphrase, { email: account.email, displayName: account.displayName });
  return check.ok ? undefined : check.problems.map((p) => PASSPHRASE_PROBLEM_TEXT[p]).join(' ');
}

function Progress({ children }: { readonly children: ReactNode }) {
  return (
    <p role="status" className="text-sm text-sky-200">
      {children}
    </p>
  );
}

// ------------------------------------------------------------------------------------- setup
function Setup({ account }: { readonly account: AccountView }) {
  const action = useAction();
  const fresh = stepUpFresh(account, 'standard');

  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const passphrase = formText(form, 'vaultPassphrase');
    const problem = policyProblems(passphrase, formText(form, 'vaultPassphraseRepeat'), account);
    if (problem !== undefined || form.get('acknowledge') !== 'yes') {
      target.reset();
      action.setError(problem ?? 'Confirm that you understand the Vault Passphrase cannot be recovered.');
      return;
    }
    void action.run(target, () => vaultController.setup(passphrase));
  }

  return (
    <div className="space-y-6">
      <TwoSecrets />
      <Card title="Set up your vault">
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
          <li>
            This browser creates your cryptographic identity: an encryption key pair and a signing key pair. Their
            private halves are encrypted here, with a key derived from your Vault Passphrase (Argon2id), before anything
            is uploaded.
          </li>
          <li>
            If you lose the Vault Passphrase, nobody can recover your private keys: not you, not an administrator, not
            CipherMesh. You could only replace your identity with a new one.
          </li>
          <li>
            Anyone who obtains a copy of the database could try to guess a weak passphrase offline. Use at least{' '}
            {VAULT_PASSPHRASE_POLICY.minLength} characters; several random words are easy to remember and hard to guess.
          </li>
        </ul>
      </Card>
      {!fresh || action.stepUpNeeded ? (
        <StepUpForm
          mfaEnabled={account.mfaEnabled}
          reason="Creating a vault changes how your account is protected, so the server asks you to confirm your account first."
          onDone={() => {
            action.setStepUpNeeded(false);
            action.setError(undefined);
            void vaultController.noteStepUp();
          }}
        />
      ) : (
        <Card title="Choose a Vault Passphrase">
          <form className="space-y-3" onSubmit={onSubmit} noValidate>
            <PassphraseField
              label="Vault Passphrase (not your account password)"
              name="vaultPassphrase"
              hint={`${String(VAULT_PASSPHRASE_POLICY.minLength)} to ${String(VAULT_PASSPHRASE_POLICY.maxLength)} characters, checked only in this browser.`}
            />
            <PassphraseField label="Repeat the Vault Passphrase" name="vaultPassphraseRepeat" />
            <label className="flex items-start gap-2 text-sm text-slate-300">
              <input type="checkbox" name="acknowledge" value="yes" className="mt-1" />
              <span>I understand that CipherMesh cannot recover a lost Vault Passphrase.</span>
            </label>
            {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
            {action.busy ? (
              <Progress>
                Creating your keys and deriving the vault key in this browser. This takes a few seconds.
              </Progress>
            ) : null}
            <Button type="submit" disabled={action.busy}>
              Create vault
            </Button>
          </form>
        </Card>
      )}
    </div>
  );
}

// ------------------------------------------------------------------------------------ locked
const LOCK_REASONS: Readonly<Record<LockReason, string>> = {
  manual: 'The vault was locked.',
  inactivity: 'The vault locked itself after 15 minutes without activity.',
  logout: 'The vault was locked when you signed out.',
  'session-ended': 'The vault was locked because your session ended.',
  'page-hidden': 'The vault was locked when the page was closed or hidden.',
  'identity-changed': 'The vault was locked because a different identity was found on the server.',
};

function Locked({
  account,
  identity,
  lockReason,
}: {
  readonly account: AccountView;
  readonly identity: IdentityView;
  readonly lockReason: LockReason | undefined;
}) {
  const action = useAction();
  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const passphrase = formText(new FormData(target), 'vaultPassphrase');
    void action.run(target, () => vaultController.unlock(passphrase));
  }
  return (
    <div className="space-y-6">
      {lockReason === undefined ? null : <Alert kind="info">{LOCK_REASONS[lockReason]}</Alert>}
      <Card title="Unlock your vault">
        <p className="text-sm text-slate-400">
          The Vault Passphrase is checked only in this browser. The server does not learn whether you typed it
          correctly.
        </p>
        <form className="space-y-3" onSubmit={onSubmit} noValidate>
          <PassphraseField label="Vault Passphrase (not your account password)" name="vaultPassphrase" />
          {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
          {action.busy ? <Progress>Deriving the vault key in this browser…</Progress> : null}
          <Button type="submit" disabled={action.busy}>
            Unlock
          </Button>
        </form>
      </Card>
      <Fingerprint identity={identity} />
      <TwoSecrets />
      <Reset account={account} />
    </div>
  );
}

// ---------------------------------------------------------------------------------- unlocked
function Unlocked({ account, identity }: { readonly account: AccountView; readonly identity: IdentityView }) {
  return (
    <div className="space-y-6">
      <Card title="Vault unlocked">
        <p className="text-sm text-slate-300">
          Your private keys are available in this tab only, as keys the page can use but cannot read or export. The
          vault locks after 15 minutes without activity, when you sign out, when your session ends and when you close
          the tab.
        </p>
        <SecondaryButton
          onClick={() => {
            vaultController.lock('manual');
          }}
        >
          Lock now
        </SecondaryButton>
      </Card>
      <Fingerprint identity={identity} />
      {identity.upgradeAvailable ? <Upgrade account={account} identity={identity} /> : null}
      <ChangePassphrase account={account} />
      <Directory />
      <Reset account={account} />
    </div>
  );
}

function Fingerprint({ identity }: { readonly identity: IdentityView }) {
  return (
    <Card title="Your identity fingerprint">
      <p className="text-sm text-slate-400">
        Computed in this browser from your public keys after checking their signature. It is public, not a secret. When
        someone needs to confirm that they have your real keys, compare all 64 characters with them in person or by
        voice.
      </p>
      <p className="grid grid-cols-4 gap-x-4 gap-y-1 font-mono text-base sm:grid-cols-8" data-testid="own-fingerprint">
        {identity.fingerprintGroups.map((group, index) => (
          <span key={`${String(index)}-${group}`}>{group}</span>
        ))}
      </p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-xs text-slate-400">
        <dt>Key ID</dt>
        <dd className="font-mono">{identity.keyId}</dd>
        <dt>Created</dt>
        <dd>{new Date(identity.createdAt).toLocaleString()}</dd>
        <dt>Passphrase last changed</dt>
        <dd>{identity.rewrappedAt === null ? 'Never' : new Date(identity.rewrappedAt).toLocaleString()}</dd>
        <dt>Key derivation</dt>
        <dd>
          Argon2id, {String(identity.kdf.memoryKiB / 1024)} MiB, {String(identity.kdf.iterations)} passes
        </dd>
      </dl>
    </Card>
  );
}

function ChangePassphrase({ account }: { readonly account: AccountView }) {
  const action = useAction();
  const [done, setDone] = useState(false);
  const fresh = stepUpFresh(account, 'standard');
  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const current = formText(form, 'currentVaultPassphrase');
    const next = formText(form, 'newVaultPassphrase');
    const problem = policyProblems(next, formText(form, 'newVaultPassphraseRepeat'), account);
    if (problem !== undefined) {
      target.reset();
      action.setError(problem);
      return;
    }
    setDone(false);
    void action.run(target, async () => {
      await vaultController.changePassphrase(current, next);
      setDone(true);
    });
  }
  if (!fresh || action.stepUpNeeded) {
    return (
      <StepUpForm
        mfaEnabled={account.mfaEnabled}
        reason="Changing the Vault Passphrase replaces the encrypted copy of your private keys, so the server asks you to confirm your account first."
        onDone={() => {
          action.setStepUpNeeded(false);
          action.setError(undefined);
          void vaultController.noteStepUp();
        }}
      />
    );
  }
  return (
    <Card title="Change the Vault Passphrase">
      <p className="text-sm text-slate-400">
        Your keys and fingerprint stay the same; only their encrypted copy changes. This does not help if someone
        already has an old copy of your vault and your old passphrase: in that case replace your identity instead.
      </p>
      <form className="space-y-3" onSubmit={onSubmit} noValidate>
        <PassphraseField label="Current Vault Passphrase" name="currentVaultPassphrase" />
        <PassphraseField label="New Vault Passphrase" name="newVaultPassphrase" />
        <PassphraseField label="Repeat the new Vault Passphrase" name="newVaultPassphraseRepeat" />
        {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
        {done ? <Alert kind="info">The Vault Passphrase was changed.</Alert> : null}
        {action.busy ? <Progress>Deriving the old and the new vault keys in this browser…</Progress> : null}
        <Button type="submit" disabled={action.busy}>
          Change Vault Passphrase
        </Button>
      </form>
    </Card>
  );
}

function Upgrade({ account, identity }: { readonly account: AccountView; readonly identity: IdentityView }) {
  const action = useAction();
  if (!stepUpFresh(account, 'standard') || action.stepUpNeeded) {
    return (
      <StepUpForm
        mfaEnabled={account.mfaEnabled}
        reason="Your vault uses older key-derivation settings. Confirm your account to upgrade them."
        onDone={() => {
          action.setStepUpNeeded(false);
          void vaultController.noteStepUp();
        }}
      />
    );
  }
  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const passphrase = formText(new FormData(target), 'vaultPassphrase');
    void action.run(target, () => vaultController.upgradeProtection(passphrase));
  }
  return (
    <Card title="Upgrade the vault protection">
      <p className="text-sm text-slate-400">
        Your vault uses Argon2id with {String(identity.kdf.memoryKiB / 1024)} MiB and {String(identity.kdf.iterations)}{' '}
        passes, below the current setting. Re-enter your Vault Passphrase to re-encrypt your keys with the stronger
        setting. Your fingerprint does not change.
      </p>
      <form className="space-y-3" onSubmit={onSubmit} noValidate>
        <PassphraseField label="Vault Passphrase" name="vaultPassphrase" />
        {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
        <Button type="submit" disabled={action.busy}>
          Upgrade
        </Button>
      </form>
    </Card>
  );
}

function Directory() {
  const [result, setResult] = useState<{ email: string; entry: DirectoryResult } | undefined>();
  const [error, setError] = useState<string | undefined>();
  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const email = formText(new FormData(event.currentTarget), 'email');
    setError(undefined);
    setResult(undefined);
    try {
      setResult({ email, entry: await vaultController.lookup(email) });
    } catch (e) {
      setError(describeVaultError(e));
    }
  }
  return (
    <Card title="Look up a user's public identity">
      <form className="space-y-3" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Exact email address" name="email" type="email" autoComplete="off" />
        <Button type="submit">Look up</Button>
      </form>
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
      {result === undefined ? null : (
        <div className="space-y-2 text-sm" data-testid="directory-result">
          <p>
            <span className="font-medium">{result.entry.displayName}</span> ·{' '}
            <span className="text-amber-300">{result.email} (email not verified)</span> · account created{' '}
            {new Date(result.entry.accountCreatedAt).toLocaleDateString()}
          </p>
          <p className="grid grid-cols-4 gap-x-4 gap-y-1 font-mono sm:grid-cols-8">
            {result.entry.fingerprintGroups.map((group, index) => (
              <span key={`${String(index)}-${group}`}>{group}</span>
            ))}
          </p>
          <p className="text-xs text-slate-400">
            Verified and computed in this browser. Email addresses are not verified, and the server distributes these
            keys: compare all 64 characters with the person through a channel you trust before relying on them. A match
            shows that you see the keys their device holds; it does not prove who registered the address.
          </p>
        </div>
      )}
    </Card>
  );
}

function Reset({ account }: { readonly account: AccountView }) {
  const action = useAction();
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <Card title="Lost your Vault Passphrase?">
        <p className="text-sm text-slate-400">
          It cannot be recovered. You can replace your identity with a new one instead.
        </p>
        <SecondaryButton
          onClick={() => {
            setOpen(true);
          }}
        >
          Replace my identity
        </SecondaryButton>
      </Card>
    );
  }
  if (!stepUpFresh(account, 'strict') || action.stepUpNeeded) {
    return (
      <StepUpForm
        mfaEnabled={account.mfaEnabled}
        reason="Replacing your identity cannot be undone, so the server asks for a confirmation from the last 5 minutes."
        onDone={() => {
          action.setStepUpNeeded(false);
          void vaultController.noteStepUp();
        }}
      />
    );
  }
  function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const passphrase = formText(form, 'vaultPassphrase');
    const problem = policyProblems(passphrase, formText(form, 'vaultPassphraseRepeat'), account);
    if (problem !== undefined || form.get('acknowledge') !== 'yes') {
      target.reset();
      action.setError(problem ?? 'Confirm that you understand the consequences.');
      return;
    }
    void action.run(target, () => vaultController.reset(passphrase));
  }
  return (
    <Card title="Replace my identity">
      <Alert kind="error">
        A new identity with a new fingerprint replaces the current one. The encrypted copy of your current private keys
        is deleted from the server, so anything encrypted only for them can no longer be opened. Your other sessions are
        signed out. People who compared your old fingerprint will see a new one.
      </Alert>
      <form className="space-y-3" onSubmit={onSubmit} noValidate>
        <PassphraseField label="New Vault Passphrase (not your account password)" name="vaultPassphrase" />
        <PassphraseField label="Repeat the new Vault Passphrase" name="vaultPassphraseRepeat" />
        <label className="flex items-start gap-2 text-sm text-slate-300">
          <input type="checkbox" name="acknowledge" value="yes" className="mt-1" />
          <span>I understand that my current identity and what was encrypted only for it cannot be restored.</span>
        </label>
        {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
        {action.busy ? <Progress>Creating a new identity in this browser…</Progress> : null}
        <div className="flex gap-3">
          <Button type="submit" disabled={action.busy}>
            Replace identity
          </Button>
          <SecondaryButton
            type="button"
            onClick={() => {
              action.setError(undefined);
              setOpen(false);
            }}
          >
            Cancel
          </SecondaryButton>
        </div>
      </form>
    </Card>
  );
}
