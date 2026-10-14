'use client';

import { checkVaultPassphrase, VAULT_PASSPHRASE_POLICY } from '@ciphermesh/crypto';
import Link from 'next/link';
import { useState, type ReactNode, type SyntheticEvent } from 'react';
import { StepUpForm } from '../../components/step-up-form';
import { Icon, type IconName } from '../../components/icons';
import { Alert, Badge, Button, Card, Field, Loading, PageHeader, SecondaryButton } from '../../components/ui';
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
    <div className="space-y-8">
      <PageHeader
        eyebrow="Security"
        title="Vault"
        description="Your cryptographic identity: an encryption key pair and a signing key pair whose private halves are encrypted in this browser under your Vault Passphrase."
      />
      {view.kind === 'locked' || view.kind === 'unlocked' || view.kind === 'not-configured' ? (
        <VaultStatus kind={view.kind} />
      ) : null}
      <VaultContent view={view} />
    </div>
  );
}

const STATUS: Readonly<
  Record<'locked' | 'unlocked' | 'not-configured', { icon: IconName; title: string; text: string; tone: string }>
> = {
  unlocked: {
    icon: 'unlock',
    title: 'Unlocked in this tab',
    text: 'Your private keys are in memory as non-extractable keys. Room keys and content can be opened here.',
    tone: 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300',
  },
  locked: {
    icon: 'lock',
    title: 'Locked',
    text: 'Your private keys exist on the server only in encrypted form. Unlock to open room keys in this tab.',
    tone: 'border-slate-700 bg-slate-900/50 text-slate-300',
  },
  'not-configured': {
    icon: 'key',
    title: 'Not set up',
    text: 'Create your vault to get a cryptographic identity. Rooms, files, notes and secrets need it.',
    tone: 'border-amber-500/30 bg-amber-500/5 text-amber-300',
  },
};

/** How the vault protects the private keys (CP-04, CP-27). Fixed facts, not live measurements. */
const VAULT_FLOW: readonly { readonly label: string; readonly detail: string }[] = [
  { label: 'Vault Passphrase', detail: 'Typed here, never sent' },
  { label: 'Argon2id', detail: 'Memory-hard, in a Web Worker' },
  { label: 'HKDF-SHA-256', detail: 'One wrapping key per private key' },
  { label: 'AES-256-GCM', detail: 'Unwraps your private keys' },
  { label: 'Non-extractable keys', detail: 'Usable, never readable' },
];

function VaultStatus({ kind }: { readonly kind: 'locked' | 'unlocked' | 'not-configured' }) {
  const status = STATUS[kind];
  return (
    <section
      aria-label="Vault status"
      className="grid gap-6 rounded-2xl border border-line bg-surface/90 p-5 sm:p-6 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]"
    >
      <div className={`flex items-start gap-4 rounded-xl border p-4 ${status.tone}`}>
        <Icon name={status.icon} className="size-7" />
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-400">Vault status</p>
          <p className="text-lg font-semibold text-white">{status.title}</p>
          <p className="text-sm leading-relaxed text-slate-300">{status.text}</p>
        </div>
      </div>
      <div className="space-y-3">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-400">How your keys are protected</p>
        <ol className="grid gap-2 sm:grid-cols-5">
          {VAULT_FLOW.map((step, index) => (
            <li key={step.label} className="relative rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="font-mono text-[11px] text-accent-300">{String(index + 1).padStart(2, '0')}</p>
              <p className="mt-1 text-sm font-medium text-white">{step.label}</p>
              <p className="text-xs text-slate-400">{step.detail}</p>
            </li>
          ))}
        </ol>
        <p className="text-xs text-slate-500">
          Nobody can recover a lost Vault Passphrase. A compromised device or browser can still read what you decrypt
          (L-01).
        </p>
      </div>
    </section>
  );
}

function VaultContent({ view }: { readonly view: VaultView }) {
  switch (view.kind) {
    case 'loading':
      return <Loading />;
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
    <Card title="Two different secrets" icon="layers">
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <dt className="font-medium text-slate-200">Account password</dt>
          <dd className="text-slate-400">
            Proves to the CipherMesh server who you are. You type it when you sign in and when you confirm your account.
          </dd>
        </div>
        <div className="rounded-lg border border-accent-500/30 bg-accent-500/5 p-3">
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
    <p
      role="status"
      className="flex items-center gap-2 rounded-lg border border-accent-500/30 bg-accent-500/10 px-3 py-2 text-sm text-accent-100"
    >
      <span className="size-2 animate-pulse rounded-full bg-accent-300 motion-reduce:animate-none" aria-hidden="true" />
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
      <Card title="Set up your vault" icon="vault">
        <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed text-slate-300 marker:text-accent-400">
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
        <Card title="Choose a Vault Passphrase" icon="key">
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
      <Card title="Unlock your vault" icon="unlock">
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
      <Card
        title="Vault unlocked"
        icon="unlock"
        actions={
          <Badge tone="success" icon="checkCircle">
            Pair checks passed
          </Badge>
        }
      >
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
    <Card title="Your identity fingerprint" icon="fingerprint">
      <p className="text-sm text-slate-400">
        Computed in this browser from your public keys after checking their signature. It is public, not a secret. When
        someone needs to confirm that they have your real keys, compare all 64 characters with them in person or by
        voice.
      </p>
      <p
        className="grid grid-cols-4 gap-x-4 gap-y-1.5 rounded-xl border border-slate-800 bg-slate-950/60 p-4 font-mono text-base text-white sm:grid-cols-8"
        data-testid="own-fingerprint"
      >
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
    <Card title="Change the Vault Passphrase" icon="key">
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
    <Card title="Upgrade the vault protection" icon="trust" tone="warning">
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
    <Card title="Look up a user's public identity" icon="members">
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
          <p className="grid grid-cols-4 gap-x-4 gap-y-1 rounded-lg border border-slate-800 bg-slate-950/60 p-3 font-mono sm:grid-cols-8">
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
      <Card title="Lost your Vault Passphrase?" icon="alert">
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
    const compromised = form.get('compromised') === 'yes';
    void action.run(target, () => vaultController.reset(passphrase, compromised));
  }
  return (
    <Card title="Replace my identity" icon="alert" tone="danger">
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
        <label className="flex items-start gap-2 text-sm text-slate-300">
          <input type="checkbox" name="compromised" value="yes" className="mt-1" />
          <span>
            Someone else may have my current keys or this device (not only a forgotten passphrase). Every room I am in
            is then locked until its owner or an admin rotates the room key.
          </span>
        </label>
        {action.error === undefined ? null : <Alert kind="error">{action.error}</Alert>}
        {action.busy ? <Progress>Creating a new identity in this browser…</Progress> : null}
        <div className="flex gap-3">
          <Button type="submit" tone="danger" disabled={action.busy}>
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
