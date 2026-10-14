'use client';

import {
  recoveryCodesResponseSchema,
  sessionInfoResponseSchema,
  sessionListResponseSchema,
  statusOkResponseSchema,
  stepUpResponseSchema,
  totpEnrollResponseSchema,
  type SessionInfoResponse,
  type z,
} from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import { QrCode } from '../../components/qr-code';
import {
  Alert,
  Badge,
  Button,
  Card,
  DetailList,
  Field,
  Loading,
  PageHeader,
  SecondaryButton,
} from '../../components/ui';
import { api, ApiError, describeError, formText } from '../../lib/api';
import { vaultController } from '../../vault/controller';

type SessionList = z.infer<typeof sessionListResponseSchema>['sessions'];

/**
 * Account and security settings (Phase 3): session details, sessions, step-up, MFA, recovery codes
 * and password change. Sensitive material (the TOTP secret and recovery codes) lives only in
 * component state for as long as it is displayed and is never written to browser storage.
 * Every protection is enforced by the API; this page only reflects what the server answers.
 */
export default function AccountPage() {
  const router = useRouter();
  const [info, setInfo] = useState<SessionInfoResponse | undefined>();
  const [sessions, setSessions] = useState<SessionList>([]);
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();

  const load = useCallback(async () => {
    try {
      setInfo(await api('GET', '/auth/session', sessionInfoResponseSchema));
      setSessions((await api('GET', '/auth/sessions', sessionListResponseSchema)).sessions);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'UNAUTHENTICATED') router.replace('/login');
      else setMessage({ kind: 'error', text: describeError(e) });
    }
  }, [router]);

  useEffect(() => {
    void load();
  }, [load]);

  async function act(action: () => Promise<void>) {
    setMessage(undefined);
    try {
      await action();
      await load();
    } catch (e) {
      setMessage({ kind: 'error', text: describeError(e) });
    }
  }

  if (info === undefined) return <Loading />;

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Settings"
        title="Account"
        description="Sign-in security for your account. Every protection here is enforced by the server; this page shows what it answers."
        actions={
          <SecondaryButton
            onClick={() =>
              void act(async () => {
                // The vault is locked before the session ends (session-and-csrf.md section 5).
                await vaultController.logout();
                router.replace('/login');
              })
            }
          >
            Sign out
          </SecondaryButton>
        }
      />
      {message === undefined ? null : <Alert kind={message.kind}>{message.text}</Alert>}

      <div className="grid items-start gap-6 xl:grid-cols-2">
        <div className="space-y-6">
          <Card
            title="Signed in"
            icon="account"
            actions={
              info.user.mfaEnabled ? (
                <Badge tone="success" icon="checkCircle">
                  Two-step sign-in on
                </Badge>
              ) : (
                <Badge tone="warning" icon="alert">
                  Two-step sign-in off
                </Badge>
              )
            }
          >
            <DetailList
              items={[
                { term: 'Name', value: info.user.displayName },
                { term: 'Email (not verified)', value: info.user.email },
                { term: 'Multi-factor authentication', value: info.user.mfaEnabled ? 'On' : 'Off' },
                {
                  term: 'Session ends at the latest',
                  value: new Date(info.session.absoluteExpiresAt).toLocaleString(),
                },
                {
                  term: 'Last identity confirmation',
                  value:
                    info.session.stepUpAt === null
                      ? 'None in this session'
                      : new Date(info.session.stepUpAt).toLocaleString(),
                },
              ]}
            />
          </Card>

          <Card title="Vault" icon="vault">
            <p className="text-sm text-slate-400">
              Your Vault holds your cryptographic identity, protected by a Vault Passphrase that is separate from this
              account password and never leaves your browser.{' '}
              <Link className="font-medium text-accent-300 hover:text-accent-200" href="/vault">
                Open the vault
              </Link>
            </p>
          </Card>
          <Mfa info={info} act={act} />
        </div>
        <div className="space-y-6">
          <StepUp
            mfaEnabled={info.user.mfaEnabled}
            onDone={() => {
              setMessage(undefined);
              void load();
            }}
          />
          <PasswordChange mfaEnabled={info.user.mfaEnabled} act={act} />

          <Card
            title="Sessions"
            icon="browser"
            description="Opaque tokens in HttpOnly cookies; the server stores only their digests."
          >
            <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800 text-sm">
              {sessions.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">
                  <span className="min-w-0 break-words text-slate-200">
                    {s.userAgent ?? 'Unknown browser'} · last active {new Date(s.lastSeenAt).toLocaleString()}
                    {s.current ? ' · this session' : ''}
                  </span>
                  {s.current ? null : (
                    <SecondaryButton
                      onClick={() =>
                        void act(async () => {
                          await api('POST', '/auth/sessions/revoke', statusOkResponseSchema, { sessionId: s.id });
                        })
                      }
                    >
                      Sign out
                    </SecondaryButton>
                  )}
                </li>
              ))}
            </ul>
            <SecondaryButton
              onClick={() =>
                void act(async () => {
                  await api('POST', '/auth/sessions/revoke-others', statusOkResponseSchema);
                })
              }
            >
              Sign out all other sessions
            </SecondaryButton>
          </Card>
        </div>
      </div>
    </div>
  );
}

function StepUp({ mfaEnabled, onDone }: { readonly mfaEnabled: boolean; readonly onDone: () => void }) {
  const [error, setError] = useState<string | undefined>();
  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      await api('POST', '/auth/step-up', stepUpResponseSchema, {
        password: formText(form, 'password'),
        ...(mfaEnabled ? { code: formText(form, 'code') } : {}),
      });
      target.reset();
      setError(undefined);
      onDone();
    } catch (e) {
      setError(describeError(e));
    }
  }
  return (
    <Card title="Confirm your identity" icon="fingerprint">
      <p className="text-sm text-slate-400">
        Sensitive changes need a confirmation within the last 15 minutes. The server checks it; it cannot be skipped
        from the browser.
      </p>
      <form className="space-y-3" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Account password" name="password" type="password" autoComplete="current-password" />
        {mfaEnabled ? (
          <Field label="Authentication code" name="code" autoComplete="one-time-code" inputMode="numeric" />
        ) : null}
        {error === undefined ? null : <Alert kind="error">{error}</Alert>}
        <Button type="submit">Confirm</Button>
      </form>
    </Card>
  );
}

function Mfa({
  info,
  act,
}: {
  readonly info: SessionInfoResponse;
  readonly act: (a: () => Promise<void>) => Promise<void>;
}) {
  const [enrollment, setEnrollment] = useState<{ otpauthUri: string; secret: string } | undefined>();
  const [codes, setCodes] = useState<readonly string[] | undefined>();

  if (codes !== undefined) {
    return (
      <Card title="Recovery codes" icon="key" tone="warning">
        <Alert kind="info">
          Store these codes somewhere safe and offline. Each works once. They are shown only now; CipherMesh keeps only
          one-way digests of them.
        </Alert>
        <ul className="grid grid-cols-2 gap-2 rounded-lg border border-slate-800 bg-slate-950/60 p-4 font-mono text-sm">
          {codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <Button
          onClick={() => {
            setCodes(undefined);
          }}
        >
          I have stored them
        </Button>
      </Card>
    );
  }

  if (enrollment !== undefined) {
    const confirm = (event: SyntheticEvent<HTMLFormElement>) => {
      event.preventDefault();
      const code = formText(new FormData(event.currentTarget), 'code');
      void act(async () => {
        const result = await api('POST', '/mfa/totp/confirm', recoveryCodesResponseSchema, { code });
        setEnrollment(undefined);
        setCodes(result.recoveryCodes);
      });
    };
    return (
      <Card title="Set up the authenticator app" icon="fingerprint">
        <p className="text-sm text-slate-400">
          Scan the code with an authenticator app, or enter the key manually. It is shown once and is not activated
          until you enter a valid code.
        </p>
        <QrCode value={enrollment.otpauthUri} label="QR code for the authenticator app" />
        <p className="break-all rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-sm">
          {enrollment.secret}
        </p>
        <form className="space-y-3" onSubmit={confirm} noValidate>
          <Field label="Code from the app" name="code" autoComplete="one-time-code" inputMode="numeric" />
          <div className="flex gap-3">
            <Button type="submit">Turn on</Button>
            <SecondaryButton
              type="button"
              onClick={() => {
                setEnrollment(undefined);
              }}
            >
              Cancel
            </SecondaryButton>
          </div>
        </form>
      </Card>
    );
  }

  return (
    <Card
      title="Multi-factor authentication"
      id="mfa"
      icon="lock"
      description="A time-based code from an authenticator app. Confidential and restricted rooms require it."
    >
      {info.user.mfaEnabled ? (
        <div className="flex flex-wrap gap-3">
          <SecondaryButton
            onClick={() =>
              void act(async () => {
                setCodes(
                  (await api('POST', '/mfa/recovery-codes/regenerate', recoveryCodesResponseSchema)).recoveryCodes,
                );
              })
            }
          >
            New recovery codes
          </SecondaryButton>
          <SecondaryButton
            onClick={() =>
              void act(async () => {
                await api('POST', '/mfa/totp/disable', statusOkResponseSchema);
              })
            }
          >
            Turn off
          </SecondaryButton>
        </div>
      ) : (
        <Button
          onClick={() =>
            void act(async () => {
              setEnrollment(await api('POST', '/mfa/totp/enroll', totpEnrollResponseSchema));
            })
          }
        >
          Set up an authenticator app
        </Button>
      )}
    </Card>
  );
}

function PasswordChange({
  mfaEnabled,
  act,
}: {
  readonly mfaEnabled: boolean;
  readonly act: (a: () => Promise<void>) => Promise<void>;
}) {
  const onSubmit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    void act(async () => {
      await api('POST', '/auth/password', statusOkResponseSchema, {
        currentPassword: formText(form, 'currentPassword'),
        newPassword: formText(form, 'newPassword'),
        ...(mfaEnabled ? { code: formText(form, 'code') } : {}),
      });
      target.reset();
    });
  };
  return (
    <Card title="Change the account password" icon="key">
      <p className="text-sm text-slate-400">All your other sessions are signed out after the change.</p>
      <form className="space-y-3" onSubmit={onSubmit} noValidate>
        <Field label="Current password" name="currentPassword" type="password" autoComplete="current-password" />
        <Field label="New password" name="newPassword" type="password" autoComplete="new-password" />
        {mfaEnabled ? (
          <Field label="Authentication code" name="code" autoComplete="one-time-code" inputMode="numeric" />
        ) : null}
        <Button type="submit">Change password</Button>
      </form>
    </Card>
  );
}
