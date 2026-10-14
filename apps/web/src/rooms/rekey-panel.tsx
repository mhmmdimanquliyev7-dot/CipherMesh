'use client';

import type { VerifiedIdentity } from '@ciphermesh/crypto';
import { formatFingerprint } from '@ciphermesh/crypto';
import type { ProfilePolicy, RoomRole } from '@ciphermesh/shared';
import type { RoomKeyStateResponse, RoomMember } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Loading, SecondaryButton } from '../components/ui';
import { ApiError } from '../lib/api';
import { useVault } from '../vault/use-vault';
import { roomKeys, type RekeyRecipientView } from './keys';
import { describeRoomError } from './messages';
import { mayAttempt, ROLE_LABEL } from './permissions';

/**
 * Room key rotation (Phase 11, CM-T050 to CM-T053; ADR-013, DF-10, security-ui.md). An OWNER or ADMIN
 * starts a rotation, reviews the server's recipient snapshot with fingerprints computed here, and
 * confirms; the new key version is made, wrapped and signed in this browser, and "verified" appears
 * only after the room's keys were opened again from what the server serves (ADR-015 section 4).
 * The room counts as unlocked only when the server reports it ACTIVE after an atomic finalize. The
 * panel holds no key material: the review keeps public identities in roomKeys, dropped on lock.
 */

const REASON_TEXT: Readonly<Record<string, string>> = {
  MEMBER_REMOVED: 'a member was removed',
  MEMBER_LEFT: 'a member left',
  MEMBER_SUSPENDED: "a member's account was disabled",
  MEMBER_DELETED: "a member's account was deleted",
  IDENTITY_KEY_COMPROMISED: 'a member reported that their identity key may be compromised',
  CRYPTOPERIOD_EXPIRED: "the key reached the end of this profile's cryptoperiod",
  WRAP_LIMIT_REACHED: 'the key protected the most items it may',
};

type Phase =
  | { readonly kind: 'idle' }
  | { readonly kind: 'starting' }
  | { readonly kind: 'review'; readonly operationId: string; readonly recipients: readonly RekeyRecipientView[] }
  | { readonly kind: 'working'; readonly step: string }
  | { readonly kind: 'done'; readonly keyVersion: number };

const time = (iso: string): string => new Date(iso).toLocaleString();

export function RekeyPanel({
  roomId,
  role,
  selfId,
  members,
  policy,
  refreshKey,
  onChanged,
  onStepUp,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly selfId: string;
  readonly members: readonly RoomMember[];
  readonly policy: ProfilePolicy;
  readonly refreshKey: number;
  readonly onChanged: () => Promise<void>;
  readonly onStepUp: (reason: string, retry: () => Promise<void>) => void;
}) {
  const vault = useVault();
  const [state, setState] = useState<RoomKeyStateResponse | undefined>();
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const [error, setError] = useState<string | undefined>();
  const [confirmed, setConfirmed] = useState<ReadonlySet<string>>(new Set());

  const load = useCallback(async () => {
    try {
      setState(await roomKeys.keyState(roomId));
    } catch (e) {
      setError(describeRoomError(e));
    }
  }, [roomId]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  // A locked vault drops the reviewed snapshot (roomKeys.clear), so the review cannot continue.
  useEffect(() => {
    if (vault.kind !== 'unlocked') setPhase((p) => (p.kind === 'review' ? { kind: 'idle' } : p));
  }, [vault.kind]);

  if (state === undefined) {
    return (
      <Card title="Room key rotation" icon="rotate">
        {error === undefined ? <Loading /> : <Alert kind="error">{error}</Alert>}
      </Card>
    );
  }

  const nameOf = (userId: string): string => members.find((m) => m.userId === userId)?.displayName ?? 'a former member';
  const canRotate = mayAttempt('AZ-13', role);
  const operation = state.operation;
  const leaseOver = operation !== null && new Date(operation.leaseExpiresAt).getTime() <= Date.now();
  const busyElsewhere = operation !== null && !leaseOver && operation.startedByUserId !== selfId;
  const mayCancel = operation !== null && (operation.startedByUserId === selfId || role === 'OWNER');

  async function start(): Promise<void> {
    setError(undefined);
    setConfirmed(new Set());
    setPhase({ kind: 'starting' });
    try {
      const { started, recipients } = await roomKeys.startRekey(roomId);
      setPhase({ kind: 'review', operationId: started.operation.id, recipients });
      await load();
    } catch (e) {
      setPhase({ kind: 'idle' });
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        onStepUp('Starting a key rotation in a restricted room needs a recent identity confirmation.', start);
        return;
      }
      setError(describeRoomError(e));
      await load();
    }
  }

  async function confirm(operationId: string): Promise<void> {
    setError(undefined);
    setPhase({ kind: 'working', step: 'Creating the new room key and wrapping it for each member on this device…' });
    try {
      const keyVersion = await roomKeys.finalizeRekey(roomId, operationId);
      setPhase({ kind: 'done', keyVersion });
      await onChanged();
    } catch (e) {
      setPhase({ kind: 'idle' });
      setError(describeRoomError(e));
      await onChanged();
    }
  }

  async function cancel(operationId: string): Promise<void> {
    setError(undefined);
    try {
      await roomKeys.cancelRekey(roomId, operationId);
      setPhase({ kind: 'idle' });
      await onChanged();
    } catch (e) {
      setError(describeRoomError(e));
      await load();
    }
  }

  const locked = state.keyState !== 'ACTIVE';
  const review = phase.kind === 'review' ? phase : undefined;
  const unconfirmed = review?.recipients.filter((r) => !r.knownHolder && !confirmed.has(r.userId)) ?? [];

  return (
    <Card title="Room key rotation" icon="rotate">
      <p className="text-sm text-slate-300" data-testid="rekey-state">
        Key version {state.currentKeyVersion} is current.{' '}
        {state.keyState === 'ACTIVE'
          ? 'New content can be added.'
          : state.keyState === 'REKEY_REQUIRED'
            ? `Locked until the room key is rotated, because ${state.rekeyReasons.map((r) => REASON_TEXT[r] ?? r).join(' and ')}.`
            : 'Locked while a key rotation is in progress.'}
      </p>
      {state.cryptoperiodReminder && state.cryptoperiodEndsAt !== null ? (
        <Alert kind="info">
          The current key reaches the end of this profile&apos;s cryptoperiod on {time(state.cryptoperiodEndsAt)}.
          Rotate it before then; afterwards the room is locked until someone does.
        </Alert>
      ) : null}
      {operation === null ? null : (
        <p className="text-xs text-slate-400" data-testid="rekey-operation">
          {operation.mode === 'MANUAL' ? 'A planned rotation' : 'A required rotation'} to version{' '}
          {operation.targetVersion} was started by{' '}
          {operation.startedByUserId === selfId ? 'you' : nameOf(operation.startedByUserId)}
          {leaseOver
            ? ' and has expired; anyone allowed to rotate can start again.'
            : `, open until ${time(operation.leaseExpiresAt)}.`}
        </p>
      )}
      <p className="text-xs text-slate-500">
        A rotation protects content added afterwards. It cannot take back anything a former member already read or
        downloaded, or room keys they received before.
      </p>
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}

      {canRotate && vault.kind !== 'unlocked' ? (
        <p className="text-sm text-slate-400">
          Room keys are made on this device.{' '}
          <Link className="text-accent-400 underline" href="/vault">
            Unlock your vault
          </Link>{' '}
          to rotate the room key.
        </p>
      ) : null}

      {canRotate && vault.kind === 'unlocked' && (phase.kind === 'idle' || phase.kind === 'done') ? (
        <div className="flex flex-wrap gap-2">
          <Button type="button" disabled={busyElsewhere} onClick={() => void start()}>
            {locked ? 'Rotate the room key now' : 'Rotate the room key'}
          </Button>
          {operation !== null && mayCancel && !leaseOver ? (
            <SecondaryButton type="button" onClick={() => void cancel(operation.id)}>
              Cancel this rotation
            </SecondaryButton>
          ) : null}
        </div>
      ) : null}
      {phase.kind === 'starting' ? (
        <p className="text-sm text-slate-400">Checking the members and their keys…</p>
      ) : null}

      {review === undefined ? null : (
        <div
          className="space-y-3 rounded-lg border border-accent-500/40 bg-accent-500/5 p-4"
          data-testid="rekey-review"
        >
          <p className="text-sm text-accent-200">
            The new key will be made on this device and wrapped for exactly these people. The server chose this list
            from its records; check it before you confirm.
          </p>
          <ul
            className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800"
            aria-label="Recipients of the new key"
          >
            {review.recipients.map((r) => (
              <li key={r.userId} className="space-y-1 px-3 py-2" data-testid="rekey-recipient">
                <p className="text-sm">
                  <span className="font-medium" data-testid="rekey-recipient-name">
                    {r.displayName}
                  </span>{' '}
                  <span className="text-xs text-slate-400">
                    {r.kind === 'INVITEE' ? 'invited, not joined yet' : 'member'}
                  </span>
                </p>
                <p className="break-all font-mono text-xs text-slate-300">{r.fingerprint}</p>
                {r.knownHolder ? null : (
                  <label className="flex items-start gap-2 text-xs text-amber-300">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={confirmed.has(r.userId)}
                      onChange={(event) => {
                        const next = new Set(confirmed);
                        if (event.target.checked) next.add(r.userId);
                        else next.delete(r.userId);
                        setConfirmed(next);
                      }}
                    />
                    <span>
                      This is a new identity key for {r.displayName} that the room has not seen signed before (for
                      example after a vault reset). I compared this fingerprint with them over a channel I trust.
                    </span>
                  </label>
                )}
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap gap-2">
            <Button type="button" disabled={unconfirmed.length > 0} onClick={() => void confirm(review.operationId)}>
              Create and share the new key
            </Button>
            <SecondaryButton type="button" onClick={() => void cancel(review.operationId)}>
              Cancel
            </SecondaryButton>
          </div>
        </div>
      )}
      {phase.kind === 'working' ? (
        <p className="text-sm text-slate-400" data-testid="rekey-progress">
          {phase.step}
        </p>
      ) : null}
      {phase.kind === 'done' ? (
        <Alert kind="info">
          <span data-testid="rekey-done">
            Key version {phase.keyVersion} is now current and verified on this device. Compare the new Room Safety Code
            with the other members.
          </span>
        </Alert>
      ) : null}

      <Reshare
        roomId={roomId}
        role={role}
        members={members}
        policy={policy}
        needing={state.membersNeedingKeys}
        locked={locked}
        onChanged={onChanged}
        onStepUp={onStepUp}
      />
    </Card>
  );
}

/** AZ-14 (CM-T053): members whose current identity holds no current key, and the re-share flow. */
function Reshare({
  roomId,
  role,
  members,
  policy,
  needing,
  locked,
  onChanged,
  onStepUp,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly members: readonly RoomMember[];
  readonly policy: ProfilePolicy;
  readonly needing: RoomKeyStateResponse['membersNeedingKeys'];
  readonly locked: boolean;
  readonly onChanged: () => Promise<void>;
  readonly onStepUp: (reason: string, retry: () => Promise<void>) => void;
}) {
  const vault = useVault();
  const [selected, setSelected] = useState<
    { readonly userId: string; readonly identity: VerifiedIdentity } | undefined
  >();
  const [compared, setCompared] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [done, setDone] = useState<string | undefined>();
  // After a re-share the list empties on reload; the result stays visible until the next choice.
  if ((needing.length === 0 && done === undefined) || !mayAttempt('AZ-14', role)) return null;

  async function choose(userId: string): Promise<void> {
    setError(undefined);
    setDone(undefined);
    setCompared(false);
    try {
      setSelected({ userId, identity: await roomKeys.memberIdentity(roomId, userId) });
    } catch (e) {
      setError(describeRoomError(e));
    }
  }

  async function share(): Promise<void> {
    if (selected === undefined) return;
    const member = members.find((m) => m.userId === selected.userId);
    if (member === undefined || member.role === 'OWNER') return;
    setError(undefined);
    try {
      const versions = await roomKeys.reshare({
        roomId,
        member: selected.identity,
        role: member.role,
        confirmedFingerprint: compared ? selected.identity.fingerprint : null,
        currentVersionOnly: policy.invitations.keyHistory === 'current-only',
      });
      setDone(`${member.displayName} received ${String(versions.length)} key version(s).`);
      setSelected(undefined);
      await onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        onStepUp('Sharing room keys in a restricted room needs a recent identity confirmation.', share);
        return;
      }
      setError(describeRoomError(e));
    }
  }

  const fingerprintRequired = policy.invitations.fingerprintConfirmation === 'required';
  return (
    <div className="space-y-2 border-t border-slate-800 pt-3" data-testid="reshare">
      {needing.length === 0 ? null : (
        <p className="text-sm text-slate-300">These members hold no key for this room on their current identity:</p>
      )}
      <ul className="space-y-2" aria-label="Members who need room keys">
        {needing.map((n) => {
          const member = members.find((m) => m.userId === n.userId);
          const allowed = member !== undefined && mayAttempt('AZ-06', role, [member.role]);
          return (
            <li key={n.userId} className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span>
                {member?.displayName ?? 'A member'}{' '}
                <span className="text-xs text-slate-400">
                  {member === undefined ? '' : ROLE_LABEL[member.role]} ·{' '}
                  {n.reason === 'SUSPENDED' ? 'suspended, account enabled again' : 'new identity key (vault reset)'}
                </span>
              </span>
              {allowed && !locked && vault.kind === 'unlocked' ? (
                <SecondaryButton type="button" onClick={() => void choose(n.userId)}>
                  Share keys again
                </SecondaryButton>
              ) : null}
            </li>
          );
        })}
      </ul>
      {locked ? (
        <p className="text-xs text-slate-500">Rotate the room key first; keys are shared again afterwards.</p>
      ) : null}
      {selected === undefined ? null : (
        <div className="space-y-2 rounded-lg border border-slate-700 bg-slate-950/40 p-3">
          <p className="text-xs text-slate-400">Their current fingerprint, computed on this device:</p>
          <p className="font-mono text-xs text-slate-300" data-testid="reshare-fingerprint">
            {formatFingerprint(selected.identity.fingerprint).join(' ')}
          </p>
          <label className="flex items-start gap-2 text-xs">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={compared}
              onChange={(event) => {
                setCompared(event.target.checked);
              }}
            />
            <span>I compared this fingerprint with them over a channel I trust.</span>
          </label>
          <Button type="button" disabled={fingerprintRequired && !compared} onClick={() => void share()}>
            Share the room keys
          </Button>
        </div>
      )}
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
      {done === undefined ? null : <Alert kind="info">{done}</Alert>}
    </div>
  );
}
