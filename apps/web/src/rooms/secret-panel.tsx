'use client';

import { roomRuleFor, SECRET_LIMITS, type ProfilePolicy, type RoomRole } from '@ciphermesh/shared';
import type { RoomMember, SecretMetadataView } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import { Alert, Button, Card, SecondaryButton } from '../components/ui';
import { ApiError } from '../lib/api';
import { useVault } from '../vault/use-vault';
import { describeSecretError, SECRET_REVEAL_WARNING, SECRETS_EXPLANATION } from './messages';
import { mayAttempt } from './permissions';
import { listSecrets, revealSecret, revokeSecret, SECRET_MAX_KIB, secretFits, sendSecret } from './secrets';

/**
 * The Secrets section of a room (Phase 9, CM-T043, CM-T044). A secret is encrypted here for one
 * member and revealed only by an explicit button, never when the page loads: a burn-after-reading
 * secret is destroyed on the server in the transaction that releases it (DF-09). Revealed text is
 * untrusted and rendered as plain text only (React escaping, T-12); it lives in this component's
 * state and is dropped on "Hide", when the vault locks and when the page is left. Controls follow
 * the shared matrix as UX only: the API authorizes every request (INV-05).
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const formatDate = (iso: string | null): string => (iso === null ? '' : new Date(iso).toLocaleString());

/** Lifetime choices the profile allows (PC-09), with its default first. */
function lifetimeChoices(policy: ProfilePolicy): { readonly label: string; readonly ms: number }[] {
  const rules = policy.secrets;
  const all = [
    { label: '15 minutes', ms: 15 * MINUTE },
    { label: '1 hour', ms: HOUR },
    { label: '24 hours', ms: 24 * HOUR },
    { label: '72 hours', ms: 72 * HOUR },
    { label: '7 days', ms: 7 * 24 * HOUR },
  ].filter((c) => c.ms >= SECRET_LIMITS.minLifetimeMs && c.ms <= rules.maxLifetimeMs);
  return [...all].sort((a, b) => (a.ms === rules.defaultLifetimeMs ? -1 : b.ms === rules.defaultLifetimeMs ? 1 : 0));
}

const STATUS_LABEL: Readonly<Record<SecretMetadataView['status'], string>> = {
  ACTIVE: 'Waiting to be revealed',
  REVEALED: 'Revealed and destroyed',
  EXPIRED: 'Expired',
  REVOKED: 'Revoked',
};

const inputClass =
  'w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 focus:border-sky-500 focus:outline-none';

export function SecretPanel({
  roomId,
  role,
  policy,
  keyState,
  selfId,
  members,
  onStepUp,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  /** The room's policy, resolved from its stored profile and version (CM-T046). */
  readonly policy: ProfilePolicy;
  readonly keyState: string;
  readonly selfId: string;
  readonly members: readonly RoomMember[];
  /** Asks the page for a step-up (PC-03 in RESTRICTED rooms), then runs `retry`. */
  readonly onStepUp: (reason: string, retry: () => Promise<void>) => void;
}) {
  const vault = useVault();
  const unlocked = vault.kind === 'unlocked';
  const [secrets, setSecrets] = useState<SecretMetadataView[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();
  const [busy, setBusy] = useState<string | undefined>();
  const [composing, setComposing] = useState(false);
  const [text, setText] = useState('');
  const [confirmReveal, setConfirmReveal] = useState<string | undefined>();
  const [confirmRevoke, setConfirmRevoke] = useState<string | undefined>();
  /** Revealed text by secret ID: memory only, never persisted. */
  const [revealed, setRevealed] = useState<ReadonlyMap<string, string>>(new Map());

  const load = useCallback(async () => {
    try {
      const page = await listSecrets(roomId);
      setSecrets(page.secrets);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeSecretError(error) });
    } finally {
      setLoaded(true);
    }
  }, [roomId]);

  useEffect(() => {
    void load();
  }, [load]);
  // A vault lock drops every revealed text and any unsent draft at once.
  useEffect(() => {
    if (unlocked) return;
    setRevealed(new Map());
    setText('');
    setComposing(false);
    setConfirmReveal(undefined);
  }, [unlocked]);

  const rules = policy.secrets;
  const writable = keyState === 'ACTIVE';
  const canCreate = mayAttempt('AZ-23', role);
  const mayRevoke = (senderId: string): boolean => {
    const rule = roomRuleFor('AZ-25', role);
    return rule.kind === 'allow' || (rule.kind === 'own' && senderId === selfId);
  };
  const nameOf = (id: string): string =>
    id === selfId ? 'you' : (members.find((m) => m.userId === id)?.displayName ?? 'a former member');
  const recipients = members.filter((m) => m.userId !== selfId && m.status === 'ACTIVE');

  // Leaving the page with an unsent secret asks first; the text itself is never stored anywhere.
  useEffect(() => {
    if (!composing || text === '') return;
    const warn = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => {
      window.removeEventListener('beforeunload', warn);
    };
  }, [composing, text]);

  async function run(key: string, action: () => Promise<void>): Promise<void> {
    setMessage(undefined);
    setBusy(key);
    try {
      await action();
    } catch (error) {
      if (error instanceof ApiError && error.code === 'STEP_UP_REQUIRED') {
        // PC-03: nothing was released or burned; the reveal runs again after the step-up.
        onStepUp('Revealing a secret in a restricted room requires confirming your identity.', () => run(key, action));
      } else {
        setMessage({ kind: 'error', text: describeSecretError(error) });
      }
    } finally {
      setBusy(undefined);
    }
  }

  const upsert = (view: SecretMetadataView): void => {
    setSecrets((list) => {
      const index = list.findIndex((s) => s.id === view.id);
      return index === -1 ? [view, ...list] : list.map((s) => (s.id === view.id ? view : s));
    });
  };

  async function onSend(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget.elements;
    const recipient = form.namedItem('recipient');
    const lifetime = form.namedItem('lifetime');
    const burn = form.namedItem('burn');
    if (!(recipient instanceof HTMLSelectElement) || recipient.value === '') {
      setMessage({ kind: 'error', text: 'Choose who the secret is for.' });
      return;
    }
    if (text === '') {
      setMessage({ kind: 'error', text: 'Write the secret first.' });
      return;
    }
    const ms = lifetime instanceof HTMLSelectElement ? Number(lifetime.value) : rules.defaultLifetimeMs;
    const burnAfterReading = rules.burnMandatory || !(burn instanceof HTMLInputElement) || burn.checked;
    await run('send', async () => {
      const view = await sendSecret({
        roomId,
        recipientUserId: recipient.value,
        text,
        expiresAt: new Date(Date.now() + ms).toISOString(),
        burnAfterReading,
      });
      upsert(view);
      setText('');
      setComposing(false);
      setMessage({
        kind: 'info',
        text: `The secret was encrypted in your browser for ${nameOf(view.recipientUserId)} and sent. It expires ${formatDate(view.expiresAt)}.`,
      });
    });
  }

  const onReveal = (view: SecretMetadataView) =>
    run(`reveal-${view.id}`, async () => {
      setConfirmReveal(undefined);
      try {
        const result = await revealSecret(roomId, view);
        upsert(result.secret);
        setRevealed((map) => new Map(map).set(view.id, result.text));
      } catch (error) {
        // The server's state decides what the list shows (already revealed, expired, revoked).
        void load();
        throw error;
      }
    });

  const hide = (id: string): void => {
    setRevealed((map) => {
      const next = new Map(map);
      next.delete(id);
      return next;
    });
  };

  const onRevoke = (id: string) =>
    run(`revoke-${id}`, async () => {
      await revokeSecret(roomId, id);
      setConfirmRevoke(undefined);
      await load();
      setMessage({ kind: 'info', text: 'The secret was revoked. Its ciphertext and wrapped key were deleted.' });
    });

  async function loadMore(): Promise<void> {
    if (nextCursor === null) return;
    try {
      const page = await listSecrets(roomId, nextCursor);
      setSecrets((list) => [...list, ...page.secrets]);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeSecretError(error) });
    }
  }

  const describe = (view: SecretMetadataView): string =>
    view.recipientUserId === selfId
      ? `From ${nameOf(view.senderId)}`
      : view.senderId === selfId
        ? `To ${nameOf(view.recipientUserId)}`
        : `From ${nameOf(view.senderId)} to ${nameOf(view.recipientUserId)}`;

  return (
    <Card title="Secrets">
      <div data-testid="secrets-card" className="space-y-4">
        <p className="text-xs text-slate-500">{SECRETS_EXPLANATION}</p>
        {message === undefined ? null : (
          <div data-testid="secret-message">
            <Alert kind={message.kind}>{message.text}</Alert>
          </div>
        )}

        {!unlocked ? (
          <p className="text-sm text-slate-400" data-testid="secrets-locked">
            Secrets are encrypted and decrypted on this device.{' '}
            <Link className="text-sky-400 underline" href="/vault">
              Unlock your vault
            </Link>{' '}
            to send or reveal them.
          </p>
        ) : !canCreate ? null : !writable ? (
          <p className="text-sm text-slate-400">New secrets cannot be sent until the room key is rotated.</p>
        ) : composing ? (
          <form className="space-y-3" onSubmit={(e) => void onSend(e)} noValidate aria-label="New secret">
            <label className="block space-y-1">
              <span className="text-sm text-slate-300">For</span>
              <select name="recipient" data-testid="secret-recipient" className={inputClass} defaultValue="">
                <option value="" disabled>
                  Choose a member
                </option>
                {recipients.map((m) => (
                  <option key={m.userId} value={m.userId}>
                    {m.displayName}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-1">
              <span className="text-sm text-slate-300">
                Secret (encrypted plain text, at most {SECRET_MAX_KIB} KiB)
              </span>
              <textarea
                name="secret"
                value={text}
                rows={4}
                disabled={busy !== undefined}
                onChange={(e) => {
                  setText(e.target.value);
                }}
                data-testid="secret-text-input"
                className={`${inputClass} font-mono text-sm`}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            {secretFits(text) || text === '' ? null : (
              <p className="text-sm text-red-300" role="alert">
                This secret is longer than {SECRET_MAX_KIB} KiB and cannot be sent.
              </p>
            )}
            <label className="block space-y-1">
              <span className="text-sm text-slate-300">Expires after</span>
              <select
                name="lifetime"
                data-testid="secret-lifetime"
                className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                {lifetimeChoices(policy).map((choice) => (
                  <option key={choice.label} value={String(choice.ms)}>
                    {choice.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                name="burn"
                defaultChecked
                disabled={rules.burnMandatory}
                data-testid="secret-burn"
              />
              Destroy after the first reveal
              {rules.burnMandatory ? ' (always on in restricted rooms)' : ''}
            </label>
            <p className="text-xs text-amber-200">
              Once this secret is revealed, it cannot be retrieved again through CipherMesh. The recipient can still
              copy what they see.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                type="submit"
                disabled={busy !== undefined || !secretFits(text) || recipients.length === 0}
                data-testid="secret-send"
              >
                {busy === 'send' ? 'Encrypting and sending…' : 'Encrypt and send'}
              </Button>
              <SecondaryButton
                type="button"
                onClick={() => {
                  setComposing(false);
                  setText('');
                }}
              >
                Cancel
              </SecondaryButton>
            </div>
          </form>
        ) : (
          <SecondaryButton
            type="button"
            onClick={() => {
              setComposing(true);
            }}
            data-testid="secret-new"
          >
            New secret
          </SecondaryButton>
        )}

        {!loaded ? (
          <p className="text-sm text-slate-400" role="status">
            Loading secrets…
          </p>
        ) : secrets.length === 0 ? (
          <p className="text-sm text-slate-400" data-testid="secrets-empty">
            No secrets sent to or from you in this room.
          </p>
        ) : (
          <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Secrets">
            {secrets.map((view) => {
              const mine = view.recipientUserId === selfId;
              const shown = revealed.get(view.id);
              return (
                <li key={view.id} className="space-y-3 px-4 py-3" data-testid="secret-row" data-secret-id={view.id}>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <span className="block font-medium">{describe(view)}</span>
                      <span className="block text-xs text-slate-400" data-testid="secret-status">
                        {STATUS_LABEL[view.status]}
                        {view.burnAfterReading ? ' · destroyed after the first reveal' : ' · can be revealed again'}
                        {view.status === 'ACTIVE' ? ` · expires ${formatDate(view.expiresAt)}` : ''}
                        {view.revealedAt === null ? '' : ` · revealed ${formatDate(view.revealedAt)}`}
                      </span>
                    </div>
                    <span className="flex flex-wrap items-center gap-2">
                      {mine && view.status === 'ACTIVE' && unlocked && shown === undefined ? (
                        confirmReveal === view.id ? null : (
                          <Button
                            type="button"
                            disabled={busy !== undefined}
                            onClick={() => {
                              if (view.burnAfterReading) setConfirmReveal(view.id);
                              else void onReveal(view);
                            }}
                            data-testid="secret-reveal"
                          >
                            Reveal
                          </Button>
                        )
                      ) : null}
                      {view.status === 'ACTIVE' && mayRevoke(view.senderId) ? (
                        confirmRevoke === view.id ? (
                          <>
                            <span className="text-sm text-red-200">Revoke for the recipient?</span>
                            <SecondaryButton
                              type="button"
                              disabled={busy !== undefined}
                              onClick={() => void onRevoke(view.id)}
                              data-testid="secret-revoke-confirm"
                            >
                              Revoke
                            </SecondaryButton>
                            <SecondaryButton
                              type="button"
                              onClick={() => {
                                setConfirmRevoke(undefined);
                              }}
                            >
                              Keep
                            </SecondaryButton>
                          </>
                        ) : (
                          <SecondaryButton
                            type="button"
                            disabled={busy !== undefined}
                            onClick={() => {
                              setConfirmRevoke(view.id);
                            }}
                            data-testid="secret-revoke"
                          >
                            Revoke
                          </SecondaryButton>
                        )
                      ) : null}
                    </span>
                  </div>
                  {confirmReveal === view.id ? (
                    <div className="space-y-2" data-testid="secret-reveal-warning">
                      <Alert kind="info">{SECRET_REVEAL_WARNING}</Alert>
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          disabled={busy !== undefined}
                          onClick={() => void onReveal(view)}
                          data-testid="secret-reveal-confirm"
                          autoFocus
                        >
                          {busy === `reveal-${view.id}` ? 'Revealing…' : 'Reveal now'}
                        </Button>
                        <SecondaryButton
                          type="button"
                          onClick={() => {
                            setConfirmReveal(undefined);
                          }}
                        >
                          Not now
                        </SecondaryButton>
                      </div>
                    </div>
                  ) : null}
                  {shown === undefined ? null : (
                    <div className="space-y-2" data-testid="secret-view">
                      {/* Untrusted text: React renders it as text, never as HTML or Markdown (T-12). */}
                      <div
                        className="whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-3 font-mono text-sm"
                        data-testid="secret-view-text"
                        tabIndex={-1}
                      >
                        {shown}
                      </div>
                      <p className="text-xs text-amber-200">
                        {view.burnAfterReading
                          ? 'This secret is gone from the server. It disappears from this page when you hide it, lock your vault or leave the page.'
                          : 'This secret stays available until it expires or is revoked.'}
                      </p>
                      <SecondaryButton
                        type="button"
                        onClick={() => {
                          hide(view.id);
                        }}
                        data-testid="secret-hide"
                      >
                        Hide
                      </SecondaryButton>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {nextCursor === null ? null : (
          <SecondaryButton type="button" onClick={() => void loadMore()}>
            Show more secrets
          </SecondaryButton>
        )}
      </div>
    </Card>
  );
}
