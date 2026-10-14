'use client';

import { formatFingerprint, type OpenedRoomKey, type SafetyCode } from '@ciphermesh/crypto';
import type { SecurityProfile } from '@ciphermesh/shared';
import { recordedResponseSchema, type RoomMember } from '@ciphermesh/validation';
import Link from 'next/link';
import { useEffect, useState, useSyncExternalStore } from 'react';
import { Icon } from '../components/icons';
import { Alert, Badge, Card, SecondaryButton } from '../components/ui';
import { api } from '../lib/api';
import { useVault } from '../vault/use-vault';
import { roomKeys } from './keys';
import { describeRoomError, SAFETY_CODE_EXPLANATION, SAFETY_CODE_GUIDANCE, SAFETY_CODE_MISMATCH } from './messages';

/**
 * The room key on this device and the Room Safety Code (Phase 6, CM-T036, CM-T085; security-ui.md
 * sections 2.3 and 2.6). Every indicator reflects a check this browser ran: "verified on this
 * device" appears only after the ADR-015 verification rule passed. The Safety Code is computed
 * here from the verified key, shown with its key version, and never sent, stored or logged
 * (INV-18). The panel forgets everything when the vault locks.
 */
type KeyState =
  | { readonly kind: 'locked' }
  | { readonly kind: 'opening' }
  | { readonly kind: 'open'; readonly key: OpenedRoomKey; readonly code: SafetyCode }
  | { readonly kind: 'failed'; readonly message: string };

const notOpen = (): boolean => false;

export function RoomKeyPanel({
  roomId,
  profile,
  members,
  refreshKey = 0,
}: {
  readonly roomId: string;
  readonly profile: SecurityProfile;
  readonly members: readonly RoomMember[];
  /** Changes after a room change (Phase 11: a new key version), so the keys are opened again. */
  readonly refreshKey?: number;
}) {
  const vault = useVault();
  // Re-render when the opened keys change: dropped on a lock, the code must disappear at once.
  const held = useSyncExternalStore(roomKeys.subscribe, () => roomKeys.isOpen(roomId), notOpen);
  const [state, setState] = useState<KeyState>({ kind: 'locked' });

  useEffect(() => {
    // A plain object, so the cleanup below can mark a stale run as cancelled.
    const run = { cancelled: false };
    if (vault.kind !== 'unlocked') {
      setState({ kind: 'locked' });
      return;
    }
    setState({ kind: 'opening' });
    void (async () => {
      try {
        const opened = await roomKeys.open(roomId);
        const key = opened.at(-1);
        const code = key === undefined ? undefined : await roomKeys.safetyCode(roomId);
        if (run.cancelled) return;
        if (key === undefined || code === undefined) setState({ kind: 'locked' });
        else setState({ kind: 'open', key, code });
      } catch (error) {
        if (!run.cancelled) setState({ kind: 'failed', message: describeRoomError(error) });
      }
    })();
    return () => {
      run.cancelled = true;
    };
  }, [roomId, vault.kind, refreshKey]);

  if (vault.kind !== 'unlocked' || state.kind === 'locked' || (state.kind === 'open' && !held)) {
    return (
      <Card title="Room key" icon="key">
        <p className="text-sm text-slate-400">
          The room key is opened only on this device, with your unlocked vault.{' '}
          <Link className="text-accent-400 underline" href="/vault">
            Unlock your vault
          </Link>{' '}
          to open it.
        </p>
      </Card>
    );
  }
  if (state.kind === 'opening') {
    return (
      <Card title="Room key" icon="key">
        <p className="text-sm text-slate-400" role="status">
          Verifying the room key on this device…
        </p>
      </Card>
    );
  }
  if (state.kind === 'failed') {
    return (
      <Card title="Room key" icon="key" tone="danger">
        <Alert kind="error">{state.message}</Alert>
      </Card>
    );
  }
  const creatorName = members.find((m) => m.userId === state.key.creator.userId)?.displayName ?? 'a former member';
  return (
    <>
      <Card
        title="Room key"
        icon="key"
        actions={
          <Badge tone="success" icon="checkCircle">
            Signature verified
          </Badge>
        }
      >
        <p className="flex items-center gap-2 text-sm text-slate-200" data-testid="room-key-status">
          <Icon name="checkCircle" className="size-4 text-emerald-300" />
          Room key version {state.key.keyVersion} verified on this device.
        </p>
        <p className="text-xs text-slate-400">
          Signed by {creatorName}. Their fingerprint, to compare out of band if you have not:
        </p>
        <p
          className="break-all rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-xs leading-relaxed text-slate-200"
          data-testid="room-key-creator-fingerprint"
        >
          {formatFingerprint(state.key.creator.fingerprint).join(' ')}
        </p>
        <p className="text-xs text-slate-500">
          {state.key.authorization.kind === 'grant'
            ? 'You hold this key through a membership grant signed by an owner or admin.'
            : 'You are named in the signed recipient list of this key version.'}{' '}
          A verified key means an owner or admin signed it; it cannot show that their identity was not substituted,
          which only fingerprint comparison can.
        </p>
      </Card>
      <SafetyCodePanel roomId={roomId} profile={profile} code={state.code} />
    </>
  );
}

function SafetyCodePanel({
  roomId,
  profile,
  code,
}: {
  readonly roomId: string;
  readonly profile: SecurityProfile;
  readonly code: SafetyCode;
}) {
  const [numeric, setNumeric] = useState(false);
  const [recorded, setRecorded] = useState<'MATCH' | 'MISMATCH' | undefined>();
  const [promptOpen, setPromptOpen] = useState(profile === 'RESTRICTED');
  const [error, setError] = useState<string | undefined>();

  async function record(result: 'MATCH' | 'MISMATCH') {
    setError(undefined);
    try {
      // The key version only: the code itself never leaves this browser (INV-18, AZ-30).
      await api('POST', `/rooms/${roomId}/safety-code`, recordedResponseSchema, {
        keyVersion: code.keyVersion,
        result,
      });
      setRecorded(result);
    } catch (e) {
      setError(describeRoomError(e));
    }
  }

  const rows = [code.words.slice(0, 3), code.words.slice(3, 6)];
  const groups = code.digits.match(/.{1,4}/g) ?? [];
  return (
    <Card
      title="Room Safety Code"
      icon="fingerprint"
      description="Computed in this browser from the verified room key. It is never sent to the server, stored or logged."
    >
      {profile === 'CONFIDENTIAL' ? (
        <p className="w-fit rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-200">
          Reminder: compare the Safety Code for this key version
        </p>
      ) : null}
      {promptOpen ? (
        <div
          role="dialog"
          aria-label="Compare the Safety Code"
          className="space-y-2 rounded-lg border border-sky-500/40 bg-sky-500/10 p-3"
        >
          <p className="text-sm text-sky-100">
            This RESTRICTED room asks members to compare the Safety Code for every key version. This is advice:
            CipherMesh cannot check that you did.
          </p>
          <SecondaryButton
            type="button"
            onClick={() => {
              setPromptOpen(false);
            }}
          >
            Dismiss
          </SecondaryButton>
        </div>
      ) : null}
      <p className="text-sm text-slate-300">Key version {code.keyVersion}</p>
      {numeric ? (
        <p
          className="tabular rounded-xl border border-accent-500/30 bg-slate-950/70 px-4 py-3 font-mono text-xl tracking-[0.2em] text-white"
          data-testid="safety-code-digits"
        >
          {groups.join(' ')}
        </p>
      ) : (
        <div
          className="space-y-1 rounded-xl border border-accent-500/30 bg-slate-950/70 px-4 py-3 font-mono text-xl text-white"
          data-testid="safety-code-words"
        >
          {rows.map((row) => (
            <p key={row.join('-')} className="tracking-wide">
              {row.join(' ')}
            </p>
          ))}
        </div>
      )}
      <SecondaryButton
        type="button"
        onClick={() => {
          setNumeric(!numeric);
        }}
      >
        {numeric ? 'Show words' : 'Show as numbers'}
      </SecondaryButton>
      <p className="text-sm text-slate-400">{SAFETY_CODE_GUIDANCE}</p>
      <p className="text-xs text-slate-500">{SAFETY_CODE_EXPLANATION}</p>
      <div className="flex flex-wrap gap-2">
        <SecondaryButton type="button" onClick={() => void record('MATCH')}>
          We compared, they match
        </SecondaryButton>
        <SecondaryButton type="button" onClick={() => void record('MISMATCH')}>
          They don&apos;t match
        </SecondaryButton>
      </div>
      {recorded === 'MATCH' ? (
        <Alert kind="info">
          You recorded a comparison for version {code.keyVersion}. This is your statement, not a check by the system.
        </Alert>
      ) : null}
      {recorded === 'MISMATCH' ? <Alert kind="error">{SAFETY_CODE_MISMATCH}</Alert> : null}
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
    </Card>
  );
}
