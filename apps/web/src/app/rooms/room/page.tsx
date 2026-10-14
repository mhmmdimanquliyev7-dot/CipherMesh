'use client';

import { isUuidV4, resolveRoomPolicy, ROOM_NAME_MAX_LENGTH, type RoomRole } from '@ciphermesh/shared';
import {
  memberListResponseSchema,
  memberRemovedResponseSchema,
  memberRoleChangedResponseSchema,
  ownershipTransferredResponseSchema,
  roomDeletedResponseSchema,
  roomDetailResponseSchema,
  roomLeftResponseSchema,
  roomRenamedResponseSchema,
  sessionInfoResponseSchema,
  type RoomDetail,
  type RoomMember,
} from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useCallback, useEffect, useState, type ReactNode, type SyntheticEvent } from 'react';
import { StepUpForm } from '../../../components/step-up-form';
import { Icon, type IconName } from '../../../components/icons';
import { Alert, Badge, Button, Card, Field, Loading, SecondaryButton } from '../../../components/ui';
import { KeyStateBadge, ProfileBadge, RoleBadge } from '../../../rooms/badges';
import { api, ApiError, formText } from '../../../lib/api';
import { FilePanel } from '../../../rooms/file-panel';
import { InviteCard, RoomInvitations } from '../../../rooms/invitations';
import { RoomKeyPanel } from '../../../rooms/key-panel';
import { NotePanel } from '../../../rooms/note-panel';
import { ProfilePanel } from '../../../rooms/profile-panel';
import { RekeyPanel } from '../../../rooms/rekey-panel';
import { SecretPanel } from '../../../rooms/secret-panel';
import { roomKeys } from '../../../rooms/keys';
import { describeRoomError, REKEY_NOTICE, ROOM_NAME_WARNING } from '../../../rooms/messages';
import { assignableRoles, mayAttempt, ROLE_LABEL } from '../../../rooms/permissions';

/**
 * One room (Phase 5, CM-T030, CM-T031; Phase 6, CM-T033 to CM-T036, CM-T085; Phase 7 files, CM-T038 to CM-T041). The static export has
 * no per-room pages, so the room ID travels in the query string and is validated before use
 * (ADR-011). The page shows controls the shared matrix allows for the user's role, as UX only; the
 * API authorizes every request against the stored membership and answers 404 to anyone who is not
 * a member. The room key is opened and verified on this device (RoomKeyPanel); invitations and
 * grants are made with the unlocked vault. Phase 11: the key rotation panel (RekeyPanel) rotates
 * the room key in this browser, and a member who is not the OWNER can leave the room (AZ-11).
 */
export default function RoomPage() {
  return (
    <Suspense fallback={<Loading />}>
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
      <Link className="text-sm font-medium text-accent-300 hover:text-accent-200" href="/rooms">
        Back to your rooms
      </Link>
    </div>
  );
}

/** In-page navigation: every section stays rendered, so nothing is hidden from search or tests. */
const SECTIONS: readonly { readonly id: string; readonly label: string; readonly icon: IconName }[] = [
  { id: 'room-key', label: 'Key & safety', icon: 'key' },
  { id: 'files', label: 'Files', icon: 'file' },
  { id: 'notes', label: 'Notes', icon: 'note' },
  { id: 'secrets', label: 'Secrets', icon: 'secret' },
  { id: 'members', label: 'Members', icon: 'members' },
  { id: 'key-rotation', label: 'Key rotation', icon: 'rotate' },
  { id: 'profile', label: 'Security profile', icon: 'trust' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function SectionNav() {
  return (
    <nav
      aria-label="Room sections"
      className="sticky top-[3.25rem] z-10 -mx-4 overflow-x-auto border-y border-slate-800/80 bg-slate-950/85 px-4 py-2 backdrop-blur sm:mx-0 sm:rounded-xl sm:border"
    >
      <ul className="flex min-w-max gap-1">
        {SECTIONS.map((section) => (
          <li key={section.id}>
            <a
              href={`#${section.id}`}
              className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800/70 hover:text-white"
            >
              <Icon name={section.icon} className="size-3.5 text-slate-400" />
              {section.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** A group of panels and the anchor target of the section navigation. */
function Section({ id, children }: { readonly id: string; readonly children: ReactNode }) {
  return (
    <div id={id} className="scroll-mt-32 space-y-6">
      {children}
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
  const [refreshKey, setRefreshKey] = useState(0);

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
      setRefreshKey((k) => k + 1);
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
  if (room === undefined || selfId === undefined) {
    return message === undefined ? (
      <Loading label="Loading the room…" />
    ) : (
      <div className="space-y-4">
        <Alert kind={message.kind}>{message.text}</Alert>
        <Link className="text-sm font-medium text-accent-300 hover:text-accent-200" href="/rooms">
          Back to your rooms
        </Link>
      </div>
    );
  }
  const role = room.membership.role;
  // The rules come from the room's stored profile and policy version, as on the server. A version
  // this client does not know is shown as such; nothing falls back to another version (CM-T046).
  const policy = resolveRoomPolicy(room.room.securityProfile, room.room.policyVersion);
  if (policy === undefined) {
    return (
      <Alert kind="error">This room uses a security policy version this version of CipherMesh does not know.</Alert>
    );
  }
  const onStepUp = (reason: string, retry: () => Promise<void>): void => {
    setStepUp({ reason, retry });
  };

  return (
    <div className="space-y-6">
      <header className="space-y-3">
        <nav aria-label="Breadcrumb" className="text-sm">
          <ol className="flex items-center gap-1.5 text-slate-400">
            <li>
              <Link className="hover:text-white" href="/rooms">
                Your rooms
              </Link>
            </li>
            <li aria-hidden="true">
              <Icon name="chevronRight" className="size-3.5" />
            </li>
            <li className="min-w-0 truncate text-slate-200" aria-current="page">
              {room.room.name}
            </li>
          </ol>
        </nav>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-4">
            <span className="hidden size-12 shrink-0 place-items-center rounded-xl border border-accent-500/30 bg-accent-500/10 text-accent-300 sm:grid">
              <Icon name="rooms" className="size-6" />
            </span>
            <div className="min-w-0 space-y-2">
              <h1 className="break-words text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                {room.room.name}
              </h1>
              <p className="flex flex-wrap gap-1.5">
                <ProfileBadge profile={room.room.securityProfile} />
                <RoleBadge role={role} prefix="Your role: " />
                <Badge tone="neutral">Policy version {policy.version}</Badge>
                <KeyStateBadge keyState={room.room.keyState} />
              </p>
            </div>
          </div>
          <p className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-surface px-3 py-1.5 text-xs text-slate-400">
            <Icon name="lock" className="size-3.5 text-accent-300" />
            Content is encrypted and decrypted on members&apos; devices
          </p>
        </div>
      </header>
      <SectionNav />
      {room.room.keyState === 'ACTIVE' ? null : <Alert kind="warning">{REKEY_NOTICE}</Alert>}
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
      <Section id="room-key">
        <RoomKeyPanel roomId={roomId} profile={room.room.securityProfile} members={members} refreshKey={refreshKey} />
      </Section>
      <Section id="files">
        <FilePanel
          roomId={roomId}
          role={role}
          policy={policy}
          keyState={room.room.keyState}
          selfId={selfId}
          members={members}
          onStepUp={onStepUp}
        />
      </Section>
      <Section id="notes">
        <NotePanel
          roomId={roomId}
          role={role}
          policy={policy}
          keyState={room.room.keyState}
          selfId={selfId}
          members={members}
        />
      </Section>
      <Section id="secrets">
        <SecretPanel
          roomId={roomId}
          role={role}
          policy={policy}
          keyState={room.room.keyState}
          selfId={selfId}
          members={members}
          onStepUp={onStepUp}
        />
      </Section>
      <Section id="members">
        <Members
          roomId={roomId}
          role={role}
          selfId={selfId}
          members={members}
          onAction={(action, reason, done) => act(action, reason, done)}
        />
        {room.room.keyState === 'ACTIVE' ? (
          <InviteCard
            roomId={roomId}
            role={role}
            policy={policy}
            onAction={(action, reason, done) => act(action, reason, done)}
          />
        ) : null}
        <RoomInvitations
          roomId={roomId}
          role={role}
          selfId={selfId}
          refreshKey={refreshKey}
          onAction={(action, reason, done) => act(action, reason, done)}
        />
      </Section>
      <Section id="key-rotation">
        <RekeyPanel
          roomId={roomId}
          role={role}
          selfId={selfId}
          members={members}
          policy={policy}
          refreshKey={refreshKey}
          onChanged={() => act(() => Promise.resolve(), '')}
          onStepUp={onStepUp}
        />
      </Section>
      <Section id="profile">
        <ProfilePanel
          roomId={roomId}
          role={role}
          policy={policy}
          onAction={(action, reason, done) => act(action, reason, done)}
        />
      </Section>
      <Section id="settings">
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
        {mayAttempt('AZ-11', role) ? (
          <Leave
            onLeave={() =>
              act(
                async () => {
                  await api('POST', `/rooms/${roomId}/leave`, roomLeftResponseSchema, {});
                  router.push('/rooms');
                },
                '',
                undefined,
                false,
              )
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
      </Section>
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
    <Card
      title="Members"
      icon="members"
      description="Making someone an admin or the owner is signed with your identity key, so your vault must be unlocked."
      actions={<Badge tone="neutral">{members.length === 1 ? '1 member' : `${String(members.length)} members`}</Badge>}
    >
      <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800" aria-label="Members">
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
              <span className="flex min-w-0 items-center gap-3">
                <span
                  className="grid size-9 shrink-0 place-items-center rounded-full bg-slate-800 text-sm font-semibold text-slate-200"
                  aria-hidden="true"
                >
                  {member.displayName.trim().slice(0, 1).toUpperCase()}
                </span>
                <span className="min-w-0 space-x-2">
                  <span className="break-words font-medium text-white">{member.displayName}</span>
                  <span className="text-xs text-slate-400">
                    {ROLE_LABEL[member.role]}
                    {self ? ' (you)' : ''}
                    {active ? '' : ' · suspended'}
                  </span>
                </span>
              </span>
              <span className="flex flex-wrap items-center gap-2">
                {roles.map((to) => (
                  <SecondaryButton
                    key={to}
                    type="button"
                    onClick={() =>
                      void onAction(async () => {
                        // Granting ADMIN carries the OWNER's signed grant (ADR-015 section 4).
                        const grant = to === 'ADMIN' ? await roomKeys.grant(roomId, member.userId, 'ADMIN') : undefined;
                        await api(
                          'POST',
                          `/rooms/${roomId}/members/${member.userId}/role`,
                          memberRoleChangedResponseSchema,
                          grant === undefined ? { role: to } : { role: to, grant },
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
                            { grant: await roomKeys.grant(roomId, member.userId, 'OWNER') },
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
                        'Removing a member of a restricted room needs a recent identity confirmation.',
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
    <Card title="Rename the room" icon="settings">
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

function Leave({ onLeave }: { readonly onLeave: () => Promise<void> }) {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Card title="Leave the room" icon="arrowRight" tone="warning">
      <p className="text-sm text-slate-400">
        You lose access at once and your room keys are deleted from the server. The room is locked for new content until
        an owner or admin rotates its key. Leaving does not erase anything you already downloaded.
      </p>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => {
            setConfirmed(event.target.checked);
          }}
        />
        I want to leave this room.
      </label>
      <Button type="button" disabled={!confirmed} onClick={() => void onLeave()}>
        Leave room
      </Button>
    </Card>
  );
}

function Delete({ onDelete }: { readonly onDelete: () => Promise<void> }) {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Card title="Delete the room" icon="xCircle" tone="danger">
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
      <Button type="button" tone="danger" disabled={!confirmed} onClick={() => void onDelete()}>
        Delete room
      </Button>
    </Card>
  );
}
