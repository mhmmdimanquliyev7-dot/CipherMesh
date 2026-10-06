'use client';

import { isUuidV4, ROOM_NAME_MAX_LENGTH, type RoomRole } from '@ciphermesh/shared';
import {
  memberListResponseSchema,
  memberRemovedResponseSchema,
  memberRoleChangedResponseSchema,
  ownershipTransferredResponseSchema,
  roomDeletedResponseSchema,
  roomDetailResponseSchema,
  roomRenamedResponseSchema,
  sessionInfoResponseSchema,
  type RoomDetail,
  type RoomMember,
} from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import { StepUpForm } from '../../../components/step-up-form';
import { Alert, Button, Card, Field, SecondaryButton } from '../../../components/ui';
import { api, ApiError, formText } from '../../../lib/api';
import { describeRoomError, REKEY_NOTICE, ROOM_NAME_WARNING } from '../../../rooms/messages';
import { assignableRoles, mayAttempt, ROLE_LABEL } from '../../../rooms/permissions';

/**
 * One room (Phase 5, CM-T030, CM-T031). The static export has no per-room pages, so the room ID
 * travels in the query string and is validated before use (ADR-011). The page shows controls the
 * shared matrix allows for the user's role, as UX only; the API authorizes every request against
 * the stored membership and answers 404 to anyone who is not a member.
 */
export default function RoomPage() {
  return (
    <Suspense fallback={<p className="text-slate-400">Loading…</p>}>
      <RoomFromQuery />
    </Suspense>
  );
}

function RoomFromQuery() {
  const id = useSearchParams().get('id') ?? '';
  if (!isUuidV4(id)) return <NotFound />;
  return <Room roomId={id} />;
}

function NotFound() {
  return (
    <div className="space-y-4">
      <Alert kind="error">This room does not exist, or you are not a member of it.</Alert>
      <Link className="text-sky-400 underline" href="/rooms">
        Back to your rooms
      </Link>
    </div>
  );
}

type PendingStepUp = { readonly reason: string; readonly retry: () => Promise<void> } | undefined;

function Room({ roomId }: { readonly roomId: string }) {
  const router = useRouter();
  const [room, setRoom] = useState<RoomDetail | undefined>();
  const [members, setMembers] = useState<RoomMember[]>([]);
  const [selfId, setSelfId] = useState<string | undefined>();
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [missing, setMissing] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();
  const [stepUp, setStepUp] = useState<PendingStepUp>();

  const load = useCallback(async () => {
    try {
      const session = await api('GET', '/auth/session', sessionInfoResponseSchema);
      setSelfId(session.user.id);
      setMfaEnabled(session.user.mfaEnabled);
      setRoom(await api('GET', `/rooms/${roomId}`, roomDetailResponseSchema));
      setMembers((await api('GET', `/rooms/${roomId}/members`, memberListResponseSchema)).members);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'UNAUTHENTICATED') router.replace('/login');
      else if (e instanceof ApiError && e.code === 'NOT_FOUND') setMissing(true);
      else setMessage({ kind: 'error', text: describeRoomError(e) });
    }
  }, [roomId, router]);

  useEffect(() => {
    void load();
  }, [load]);

  /** Runs an action; asks for a step-up when the API requires one, then retries it. */
  async function act(action: () => Promise<void>, stepUpReason: string, done?: string, reload = true): Promise<void> {
    setMessage(undefined);
    try {
      await action();
      if (done !== undefined) setMessage({ kind: 'info', text: done });
      if (reload) await load();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        setStepUp({ reason: stepUpReason, retry: () => act(action, stepUpReason, done, reload) });
      } else {
        setMessage({ kind: 'error', text: describeRoomError(e) });
        await load();
      }
    }
  }

  if (missing) return <NotFound />;
  if (room === undefined || selfId === undefined) return <p className="text-slate-400">Loading…</p>;
  const role = room.membership.role;

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Link className="text-sm text-sky-400 underline" href="/rooms">
          Your rooms
        </Link>
        <h1 className="text-2xl font-semibold">{room.room.name}</h1>
        <p className="flex flex-wrap gap-2 text-xs">
          <span className="rounded bg-slate-800 px-2 py-0.5">{room.room.securityProfile}</span>
          <span className="rounded bg-slate-800 px-2 py-0.5">Your role: {ROLE_LABEL[role]}</span>
        </p>
      </div>
      {room.room.keyState === 'ACTIVE' ? null : <Alert kind="info">{REKEY_NOTICE}</Alert>}
      {message === undefined ? null : <Alert kind={message.kind}>{message.text}</Alert>}
      {stepUp === undefined ? null : (
        <StepUpForm
          mfaEnabled={mfaEnabled}
          reason={stepUp.reason}
          onDone={() => {
            const retry = stepUp.retry;
            setStepUp(undefined);
            void retry();
          }}
        />
      )}
      <Members
        roomId={roomId}
        role={role}
        selfId={selfId}
        members={members}
        onAction={(action, reason, done) => act(action, reason, done)}
      />
      {mayAttempt('AZ-02', role) ? (
        <Rename
          roomId={roomId}
          current={room.room.name}
          onRename={(name) =>
            act(async () => {
              await api('POST', `/rooms/${roomId}/rename`, roomRenamedResponseSchema, { name });
            }, '')
          }
        />
      ) : null}
      {mayAttempt('AZ-04', role) ? (
        <Delete
          onDelete={() =>
            act(
              async () => {
                await api('POST', `/rooms/${roomId}/delete`, roomDeletedResponseSchema, {});
                router.push('/rooms');
              },
              'Deleting a room needs a recent confirmation with your account password.',
              undefined,
              false,
            )
          }
        />
      ) : null}
    </div>
  );
}

function Members({
  roomId,
  role,
  selfId,
  members,
  onAction,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly selfId: string;
  readonly members: readonly RoomMember[];
  readonly onAction: (action: () => Promise<void>, stepUpReason: string, done?: string) => Promise<void>;
}) {
  return (
    <Card title="Members">
      <p className="text-xs text-slate-500">Inviting members arrives with encrypted room keys in a later phase.</p>
      <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Members">
        {members.map((member) => {
          const self = member.userId === selfId;
          const active = member.status === 'ACTIVE';
          const roles = self || !active ? [] : assignableRoles(role, member.role);
          const removable = !self && mayAttempt('AZ-09', role, [member.role]);
          const transferable = !self && active && mayAttempt('AZ-05', role, [member.role]);
          return (
            <li
              key={member.userId}
              className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              data-testid={`member-${member.userId}`}
            >
              <span className="space-x-2">
                <span className="font-medium">{member.displayName}</span>
                <span className="text-xs text-slate-400">
                  {ROLE_LABEL[member.role]}
                  {self ? ' (you)' : ''}
                  {active ? '' : ' · suspended'}
                </span>
              </span>
              <span className="flex flex-wrap items-center gap-2">
                {roles.map((to) => (
                  <SecondaryButton
                    key={to}
                    type="button"
                    onClick={() =>
                      void onAction(async () => {
                        await api(
                          'POST',
                          `/rooms/${roomId}/members/${member.userId}/role`,
                          memberRoleChangedResponseSchema,
                          {
                            role: to,
                          },
                        );
                      }, '')
                    }
                  >
                    Make {ROLE_LABEL[to].toLowerCase()}
                  </SecondaryButton>
                ))}
                {transferable ? (
                  <SecondaryButton
                    type="button"
                    onClick={() =>
                      void onAction(
                        async () => {
                          await api(
                            'POST',
                            `/rooms/${roomId}/members/${member.userId}/transfer-ownership`,
                            ownershipTransferredResponseSchema,
                            {},
                          );
                        },
                        'Transferring ownership needs a recent confirmation with your account password.',
                        `${member.displayName} is now the owner. You are an admin of this room.`,
                      )
                    }
                  >
                    Transfer ownership
                  </SecondaryButton>
                ) : null}
                {removable ? (
                  <SecondaryButton
                    type="button"
                    onClick={() =>
                      void onAction(
                        async () => {
                          await api(
                            'POST',
                            `/rooms/${roomId}/members/${member.userId}/remove`,
                            memberRemovedResponseSchema,
                            {},
                          );
                        },
                        '',
                        `${member.displayName} was removed. ${REKEY_NOTICE}`,
                      )
                    }
                  >
                    Remove
                  </SecondaryButton>
                ) : null}
              </span>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Rename({
  roomId,
  current,
  onRename,
}: {
  readonly roomId: string;
  readonly current: string;
  readonly onRename: (name: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = formText(new FormData(event.currentTarget), 'name');
    setBusy(true);
    try {
      await onRename(name);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card title="Rename the room">
      <form className="space-y-3" onSubmit={(e) => void onSubmit(e)} noValidate key={`${roomId}-${current}`}>
        <Field
          label="New room name"
          name="name"
          defaultValue={current}
          maxLength={ROOM_NAME_MAX_LENGTH}
          hint={ROOM_NAME_WARNING}
        />
        <Button type="submit" disabled={busy}>
          Rename
        </Button>
      </form>
    </Card>
  );
}

function Delete({ onDelete }: { readonly onDelete: () => Promise<void> }) {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Card title="Delete the room">
      <p className="text-sm text-slate-400">
        The room disappears for every member at once. Only the owner can delete it, after confirming the account
        password.
      </p>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => {
            setConfirmed(event.target.checked);
          }}
        />
        I understand that this room will be deleted for every member.
      </label>
      <Button type="button" disabled={!confirmed} onClick={() => void onDelete()}>
        Delete room
      </Button>
    </Card>
  );
}
