'use client';

import type { ProfilePolicy, RoomRole } from '@ciphermesh/shared';
import {
  invitationApprovedResponseSchema,
  invitationClosedResponseSchema,
  roomInvitationListResponseSchema,
  type RoomInvitation,
} from '@ciphermesh/validation';
import { useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import { Alert, Button, Card, Field, SecondaryButton } from '../components/ui';
import { api, formText } from '../lib/api';
import { vaultController, type DirectoryResult } from '../vault/controller';
import { roomKeys } from './keys';
import { FINGERPRINT_GUIDANCE } from './messages';
import { mayAttempt, ROLE_LABEL } from './permissions';

/**
 * Inviting members (Phase 6, CM-T034, DF-06; security-ui.md section 2.2). The invitee is looked
 * up by exact email; the directory answer is verified here and the fingerprint computed here. The
 * email address is not verified by CipherMesh (T-35). Fingerprint confirmation follows PC-05:
 * required in RESTRICTED, prompted in CONFIDENTIAL, optional in STANDARD. The room key is wrapped
 * to the invitee's identity and the grant signed in this browser (roomKeys.invite).
 */
type Act = (action: () => Promise<void>, stepUpReason: string, done?: string) => Promise<void>;

export function InviteCard({
  roomId,
  role,
  policy,
  onAction,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  /** The room's policy, resolved from its stored profile and version (CM-T046). */
  readonly policy: ProfilePolicy;
  readonly onAction: Act;
}) {
  const [found, setFound] = useState<DirectoryResult | undefined>();
  const [lookupError, setLookupError] = useState<string | undefined>();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const rules = policy.invitations;
  const roles = (['ADMIN', 'MEMBER', 'VIEWER'] as const).filter((r) => mayAttempt('AZ-06', role, [r]));

  async function onLookup(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setLookupError(undefined);
    setFound(undefined);
    setConfirmed(false);
    try {
      setFound(await vaultController.lookup(formText(new FormData(event.currentTarget), 'email')));
    } catch {
      setLookupError('No user with a vault was found for this exact email address.');
    }
  }

  async function onInvite(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (found === undefined) return;
    const chosen = formText(new FormData(event.currentTarget), 'role');
    const inviteRole = roles.find((r) => r === chosen);
    if (inviteRole === undefined) return;
    setBusy(true);
    try {
      await onAction(
        async () => {
          await roomKeys.invite({
            roomId,
            invitee: found.identity,
            role: inviteRole,
            confirmedFingerprint: confirmed ? found.fingerprint : null,
            currentVersionOnly: rules.keyHistory === 'current-only',
          });
          setFound(undefined);
          setConfirmed(false);
        },
        'Inviting to a RESTRICTED room needs a recent confirmation with your account password and code.',
        `${found.displayName} was invited.`,
      );
    } finally {
      setBusy(false);
    }
  }

  if (roles.length === 0) return null;
  return (
    <Card title="Invite a member">
      <form className="space-y-3" onSubmit={(e) => void onLookup(e)} noValidate>
        <Field label="Email address of the person to invite" name="email" type="email" required />
        <SecondaryButton type="submit">Look up</SecondaryButton>
      </form>
      {lookupError === undefined ? null : <Alert kind="error">{lookupError}</Alert>}
      {found === undefined ? null : (
        <form className="space-y-3" onSubmit={(e) => void onInvite(e)} noValidate data-testid="invite-candidate">
          <p className="text-sm">
            <span className="font-medium">{found.displayName}</span>{' '}
            <span className="text-xs text-amber-300">email address not verified</span>
          </p>
          <p className="text-xs text-slate-400">Account created {found.accountCreatedAt.slice(0, 10)}</p>
          <p className="text-xs text-slate-400">Fingerprint computed on this device:</p>
          <p className="font-mono text-xs text-slate-200" data-testid="invitee-fingerprint">
            {found.fingerprintGroups.join(' ')}
          </p>
          {rules.fingerprintConfirmation === 'optional' ? null : (
            <p className="text-xs text-slate-400">
              {rules.fingerprintConfirmation === 'required'
                ? 'This RESTRICTED room requires you to compare the fingerprint before inviting.'
                : 'This CONFIDENTIAL room asks you to compare the fingerprint before inviting.'}
            </p>
          )}
          <p className="text-xs text-slate-500">{FINGERPRINT_GUIDANCE}</p>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => {
                setConfirmed(event.target.checked);
              }}
            />
            I compared this fingerprint with {found.displayName} over a channel I trust, and it matches.
          </label>
          <label className="block space-y-1">
            <span className="text-sm text-slate-300">Role</span>
            <select
              name="role"
              defaultValue={roles.includes('MEMBER') ? 'MEMBER' : roles[0]}
              className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
            >
              {roles.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          {rules.keyHistory === 'current-only' ? (
            <p className="text-xs text-slate-500">
              New members of a RESTRICTED room receive the current room key only.
            </p>
          ) : null}
          <Button type="submit" disabled={busy || (rules.fingerprintConfirmation === 'required' && !confirmed)}>
            Invite
          </Button>
        </form>
      )}
    </Card>
  );
}

/** The room's open invitations, for the OWNER and ADMINs (AZ-31, OL-11). */
export function RoomInvitations({
  roomId,
  role,
  selfId,
  onAction,
  refreshKey,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly selfId: string;
  readonly onAction: Act;
  readonly refreshKey: number;
}) {
  const [invitations, setInvitations] = useState<RoomInvitation[]>([]);
  const load = useCallback(async () => {
    setInvitations((await api('GET', `/rooms/${roomId}/invitations`, roomInvitationListResponseSchema)).invitations);
  }, [roomId]);
  useEffect(() => {
    void load().catch(() => undefined);
  }, [load, refreshKey]);

  if (!mayAttempt('AZ-31', role)) return null;
  return (
    <Card title="Open invitations">
      {invitations.length === 0 ? <p className="text-sm text-slate-400">No open invitations.</p> : null}
      <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Open invitations">
        {invitations.map((invitation) => {
          const canApprove =
            invitation.status === 'PENDING_APPROVAL' &&
            mayAttempt('AZ-07', role) &&
            invitation.invitedBy.userId !== selfId;
          const canRevoke = role === 'OWNER' || invitation.invitedBy.userId === selfId;
          return (
            <li key={invitation.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <span className="space-x-2 text-sm">
                <span className="font-medium">{invitation.invitee.displayName}</span>
                <span className="text-xs text-slate-400">
                  {ROLE_LABEL[invitation.role]} ·{' '}
                  {invitation.status === 'PENDING_APPROVAL' ? 'waiting for the owner' : 'waiting for the invitee'} ·
                  invited by {invitation.invitedBy.displayName} · expires{' '}
                  {invitation.expiresAt.slice(0, 16).replace('T', ' ')}
                  {invitation.fingerprintConfirmed ? ' · fingerprint confirmed' : ''}
                </span>
              </span>
              <span className="flex gap-2">
                {canApprove ? (
                  <SecondaryButton
                    type="button"
                    onClick={() =>
                      void onAction(async () => {
                        await api(
                          'POST',
                          `/rooms/${roomId}/invitations/${invitation.id}/approve`,
                          invitationApprovedResponseSchema,
                          {},
                        );
                        await load();
                      }, 'Approving in a RESTRICTED room needs a recent confirmation with your account password and code.')
                    }
                  >
                    Approve
                  </SecondaryButton>
                ) : null}
                {canRevoke ? (
                  <SecondaryButton
                    type="button"
                    onClick={() =>
                      void onAction(async () => {
                        await api(
                          'POST',
                          `/rooms/${roomId}/invitations/${invitation.id}/revoke`,
                          invitationClosedResponseSchema,
                          {},
                        );
                        await load();
                      }, '')
                    }
                  >
                    Revoke
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
