'use client';

import {
  invitationAcceptedResponseSchema,
  invitationClosedResponseSchema,
  ownInvitationListResponseSchema,
  type OwnInvitation,
} from '@ciphermesh/validation';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, EmptyState, Loading, PageHeader, SecondaryButton } from '../../components/ui';
import { ProfileBadge, RoleBadge } from '../../rooms/badges';
import { api, ApiError } from '../../lib/api';
import { describeRoomError } from '../../rooms/messages';

/**
 * The signed-in user's own invitations (Phase 6, SS-03, CM-T035). Accepting makes the user a member
 * on the server; the room key is then opened and verified on this device when the room page loads,
 * never trusted merely because the server accepted the invitation (ADR-015 section 4). Invitations
 * are in-app only: there is no link or token to share.
 */
export default function InvitationsPage() {
  const router = useRouter();
  const [invitations, setInvitations] = useState<OwnInvitation[] | undefined>();
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();

  const load = useCallback(async () => {
    try {
      setInvitations((await api('GET', '/invitations', ownInvitationListResponseSchema)).invitations);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'UNAUTHENTICATED') router.replace('/login');
      else setMessage({ kind: 'error', text: describeRoomError(e) });
    }
  }, [router]);

  useEffect(() => {
    void load();
  }, [load]);

  async function respond(invitation: OwnInvitation, accept: boolean) {
    setMessage(undefined);
    try {
      if (accept) {
        const accepted = await api(
          'POST',
          `/invitations/${invitation.id}/accept`,
          invitationAcceptedResponseSchema,
          {},
        );
        router.push(`/rooms/room?id=${accepted.roomId}`);
        return;
      }
      await api('POST', `/invitations/${invitation.id}/decline`, invitationClosedResponseSchema, {});
      setMessage({ kind: 'info', text: 'Invitation declined.' });
      await load();
    } catch (e) {
      setMessage({ kind: 'error', text: describeRoomError(e) });
      await load();
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Invitations"
        description="Invitations to rooms. After you accept, the room key is opened and checked on this device with your unlocked vault; a key that fails the check is not used."
      />
      {message === undefined ? null : <Alert kind={message.kind}>{message.text}</Alert>}
      <Card title="Your invitations" icon="invitations">
        {invitations === undefined ? (
          <Loading />
        ) : invitations.length === 0 ? (
          <EmptyState icon="invitations" title="You have no open invitations.">
            When someone invites you, the invitation appears here. There is no link or token to share.
          </EmptyState>
        ) : (
          <ul
            className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800"
            aria-label="Your invitations"
          >
            {invitations.map((invitation) => (
              <li key={invitation.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <span className="min-w-0 space-y-1.5 text-sm">
                  <span className="block break-words font-medium text-white">{invitation.room.name}</span>
                  <span className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    <ProfileBadge profile={invitation.room.securityProfile} />
                    <RoleBadge role={invitation.role} />
                    <span>
                      from {invitation.invitedBy.displayName}
                      {invitation.status === 'PENDING_APPROVAL' ? ' · waiting for the room owner to approve' : ''}
                    </span>
                  </span>
                </span>
                <span className="flex gap-2">
                  <Button
                    type="button"
                    disabled={invitation.status !== 'PENDING'}
                    onClick={() => void respond(invitation, true)}
                  >
                    Accept
                  </Button>
                  <SecondaryButton type="button" onClick={() => void respond(invitation, false)}>
                    Decline
                  </SecondaryButton>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
