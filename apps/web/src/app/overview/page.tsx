'use client';

import {
  ownInvitationListResponseSchema,
  roomListResponseSchema,
  sessionInfoResponseSchema,
  type OwnInvitation,
  type RoomSummary,
  type SessionInfoResponse,
} from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { Icon } from '../../components/icons';
import { Alert, buttonClass, Card, EmptyState, Loading, PageHeader, Stat } from '../../components/ui';
import { api, ApiError, describeError } from '../../lib/api';
import { KeyStateBadge, ProfileBadge, RoleBadge } from '../../rooms/badges';
import { useVault } from '../../vault/use-vault';

/**
 * The workspace overview (Phase 14 + Prompt 16.5, CM-T061). Every figure comes from an existing,
 * authorized API response for the signed-in user (their session, their rooms, their invitations)
 * or from the vault controller in this tab. Nothing is estimated: a count that is only partly
 * known (more pages of rooms exist) is shown as "at least", and no platform-wide data appears.
 */

interface Overview {
  readonly session: SessionInfoResponse;
  readonly rooms: readonly RoomSummary[];
  readonly moreRooms: boolean;
  readonly invitations: readonly OwnInvitation[];
}

const VAULT_TEXT = {
  loading: 'Checking…',
  'signed-out': 'Signed out',
  failed: 'Unavailable',
  'not-configured': 'Not set up',
  locked: 'Locked',
  unlocked: 'Unlocked',
} as const;

export default function OverviewPage() {
  const router = useRouter();
  const vault = useVault();
  const [data, setData] = useState<Overview | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    void (async () => {
      try {
        const session = await api('GET', '/auth/session', sessionInfoResponseSchema);
        const [rooms, invitations] = await Promise.all([
          api('GET', '/rooms', roomListResponseSchema),
          api('GET', '/invitations', ownInvitationListResponseSchema),
        ]);
        setData({
          session,
          rooms: rooms.rooms,
          moreRooms: rooms.nextCursor !== null,
          invitations: invitations.invitations,
        });
      } catch (e) {
        if (e instanceof ApiError && e.code === 'UNAUTHENTICATED') router.replace('/login');
        else setError(describeError(e));
      }
    })();
  }, [router]);

  if (error !== undefined) return <Alert kind="error">{error}</Alert>;
  if (data === undefined) return <Loading />;

  const locked = data.rooms.filter((room) => room.keyState !== 'ACTIVE');
  const open = data.invitations.filter((invitation) => invitation.status === 'PENDING');
  const waiting = data.invitations.filter((invitation) => invitation.status === 'PENDING_APPROVAL');
  const roomCount = `${String(data.rooms.length)}${data.moreRooms ? '+' : ''}`;

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Overview"
        description={`Signed in as ${data.session.user.displayName}. Everything below is read from your own rooms, invitations and session.`}
        actions={
          <>
            <Link className={buttonClass.secondary} href="/trust">
              <Icon name="trust" className="size-4" />
              Trust Center
            </Link>
            <Link className={buttonClass.primary} href="/rooms#create-room">
              <Icon name="plus" className="size-4" />
              New room
            </Link>
          </>
        }
      />

      <section aria-label="Notices" className="space-y-3">
        {vault.kind === 'not-configured' ? (
          <Alert kind="warning">
            Your vault is not set up yet. It creates your cryptographic identity, which every room needs.{' '}
            <Link className="font-medium underline" href="/vault">
              Set up your vault
            </Link>
          </Alert>
        ) : null}
        {vault.kind === 'locked' ? (
          <Alert kind="info">
            Your vault is locked, so room keys and content cannot be opened in this tab.{' '}
            <Link className="font-medium underline" href="/vault">
              Unlock it
            </Link>
          </Alert>
        ) : null}
        {data.session.user.mfaEnabled ? null : (
          <Alert kind="warning">
            Two-step sign-in is off. Confidential and restricted rooms refuse sessions without it.{' '}
            <Link className="font-medium underline" href="/account#mfa">
              Turn it on
            </Link>
          </Alert>
        )}
        {locked.length === 0 ? null : (
          <Alert kind="warning">
            {locked.length === 1 ? 'One of your rooms is' : `${String(locked.length)} of your rooms are`} locked for new
            content until the room key is rotated.
          </Alert>
        )}
        {open.length === 0 ? null : (
          <Alert kind="info">
            You have {open.length === 1 ? 'an invitation' : `${String(open.length)} invitations`} to answer.{' '}
            <Link className="font-medium underline" href="/invitations">
              Review invitations
            </Link>
          </Alert>
        )}
      </section>

      <section aria-label="Summary" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat icon="rooms" label="Your rooms" value={roomCount} detail="Rooms you are a member of." />
        <Stat
          icon="rotate"
          label="Need key rotation"
          value={data.moreRooms ? `${String(locked.length)}+` : String(locked.length)}
          detail="Write-locked until an owner or admin rotates the key."
        />
        <Stat
          icon="invitations"
          label="Open invitations"
          value={String(open.length)}
          detail={
            waiting.length === 0 ? 'Ready to accept or decline.' : `${String(waiting.length)} waiting for approval.`
          }
        />
        <Stat
          icon="vault"
          label="Vault in this tab"
          value={VAULT_TEXT[vault.kind]}
          detail={data.session.user.mfaEnabled ? 'Two-step sign-in is on.' : 'Two-step sign-in is off.'}
        />
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <Card
          title="Recent rooms"
          icon="rooms"
          actions={
            <Link className={buttonClass.ghost} href="/rooms">
              View all rooms
              <Icon name="arrowRight" className="size-4" />
            </Link>
          }
        >
          {data.rooms.length === 0 ? (
            <EmptyState icon="rooms" title="No rooms yet">
              Create a room with your unlocked vault, or accept an invitation from another member.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800">
              {data.rooms.slice(0, 6).map((room) => (
                <li key={room.id}>
                  <Link
                    href={`/rooms/room?id=${room.id}`}
                    className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 transition-colors hover:bg-slate-800/40"
                  >
                    <span className="min-w-0 break-words font-medium text-white">{room.name}</span>
                    <span className="flex flex-wrap gap-1.5">
                      <ProfileBadge profile={room.securityProfile} />
                      <RoleBadge role={room.role} />
                      <KeyStateBadge keyState={room.keyState} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="This session" icon="clock" description="Set by the server; this page only displays it.">
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Signed in</dt>
              <dd className="text-right text-slate-100">
                {new Date(data.session.session.authenticatedAt).toLocaleString()}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Ends at the latest</dt>
              <dd className="text-right text-slate-100">
                {new Date(data.session.session.absoluteExpiresAt).toLocaleString()}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Second factor verified</dt>
              <dd className="text-right text-slate-100">
                {data.session.session.mfaVerifiedAt === null
                  ? 'Not in this session'
                  : new Date(data.session.session.mfaVerifiedAt).toLocaleString()}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-400">Last identity confirmation</dt>
              <dd className="text-right text-slate-100">
                {data.session.session.stepUpAt === null
                  ? 'None in this session'
                  : new Date(data.session.session.stepUpAt).toLocaleString()}
              </dd>
            </div>
          </dl>
          <p className="border-t border-slate-800 pt-3 text-xs text-slate-500">
            Sessions are opaque random tokens in an HttpOnly cookie that this page cannot read. The server keeps only a
            SHA-256 digest of the token.
          </p>
        </Card>
      </div>
    </div>
  );
}
