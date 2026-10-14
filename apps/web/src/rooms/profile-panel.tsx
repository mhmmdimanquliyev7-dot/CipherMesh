'use client';

import {
  currentPolicy,
  profileChangeDirection,
  PROFILE_CHANGE_RULES,
  SECURITY_PROFILES,
  type ProfilePolicy,
  type RoomRole,
  type SecurityProfile,
} from '@ciphermesh/shared';
import { profileChangedResponseSchema } from '@ciphermesh/validation';
import { useState, type SyntheticEvent } from 'react';
import { Alert, Button, Card, controlClass } from '../components/ui';
import { api } from '../lib/api';
import { mayAttempt } from './permissions';

/**
 * The Security profile section of a room (Phase 10, CM-T046 to CM-T048). It explains the rules the
 * API enforces for the room's stored profile and policy version, read from the same versioned
 * catalogue the API uses (packages/shared, policy.ts), and lets the OWNER change the profile.
 *
 * Everything here is UX. The API decides every request against the stored profile; hiding a
 * control or a confirmation box changes nothing about that (INV-08). Only rules the API enforces
 * today are listed as active, including the room-key cryptoperiod (PC-14, enforced by the worker
 * since Phase 11). External links (PC-11) are not built, so they are not mentioned.
 */

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;

const LABEL: Readonly<Record<SecurityProfile, string>> = {
  STANDARD: 'Standard',
  CONFIDENTIAL: 'Confidential',
  RESTRICTED: 'Restricted',
};

function duration(ms: number): string {
  if (ms % DAY === 0) return `${ms / DAY} day${ms === DAY ? '' : 's'}`;
  if (ms % HOUR === 0) return `${ms / HOUR} hour${ms === HOUR ? '' : 's'}`;
  return `${Math.round(ms / 60_000)} minutes`;
}

/** The enforced rules of a policy, in plain language, one line per control. */
export function describePolicy(policy: ProfilePolicy): readonly { readonly id: string; readonly text: string }[] {
  const minutes = policy.sensitiveStepUp.windowMs / 60_000;
  const invitations = policy.invitations;
  const fingerprint =
    invitations.fingerprintConfirmation === 'required'
      ? 'must be confirmed before inviting'
      : invitations.fingerprintConfirmation === 'prompted'
        ? 'should be compared (you are prompted)'
        : 'can optionally be compared';
  const expiry = policy.contentExpiry;
  return [
    {
      id: 'PC-01',
      text: policy.access.mfaVerifiedSession
        ? 'Members need a session verified with an authentication code (two-step sign-in).'
        : 'A password sign-in is enough; two-step sign-in is not required.',
    },
    {
      id: 'PC-02',
      text: `Members must have signed in within the last ${duration(policy.access.maxAuthenticationAgeMs)}.`,
    },
    {
      id: 'PC-03',
      text: policy.sensitiveStepUp.required
        ? `Revealing secrets, downloading files, inviting, approving, removing members, changing the profile and deleting the room need an identity confirmation within the last ${minutes} minutes.`
        : 'Only deleting the room and transferring ownership need an identity confirmation.',
    },
    {
      id: 'PC-04',
      text: invitations.adminInvitationNeedsApproval
        ? 'Invitations created by an admin wait for the owner’s approval.'
        : 'Invitations created by an admin need no approval.',
    },
    { id: 'PC-05', text: `The invitee’s key fingerprint ${fingerprint}.` },
    { id: 'PC-06', text: `Invitations are valid for ${duration(invitations.validityMs)}.` },
    {
      id: 'PC-07',
      text:
        invitations.keyHistory === 'current-only'
          ? 'New members receive only the current room key version.'
          : 'New members receive every retained room key version.',
    },
    {
      id: 'PC-08',
      text:
        expiry.maxMs === null
          ? 'Files and notes may have an expiry; none is required.'
          : `Files and notes must expire within ${duration(expiry.maxMs)}.`,
    },
    {
      id: 'PC-09',
      text: `Secrets expire within ${duration(policy.secrets.maxLifetimeMs)} (default ${duration(policy.secrets.defaultLifetimeMs)}).`,
    },
    {
      id: 'PC-10',
      text: policy.secrets.burnMandatory
        ? 'Every secret is destroyed after its first reveal.'
        : 'Secrets are destroyed after the first reveal unless the sender turns this off.',
    },
    {
      id: 'PC-12',
      text: policy.viewerMayObtainFileKeys
        ? 'Viewers can download and open files.'
        : 'Viewers see that files exist but cannot download or open them.',
    },
    {
      id: 'PC-13',
      text: `Audit level ${policy.auditLevel.toLowerCase()}${
        policy.auditLevel === 'BASELINE'
          ? ''
          : policy.auditLevel === 'EXTENDED'
            ? ': file downloads and note reads are recorded too'
            : ': file downloads, note reads, key and member-list views are recorded too'
      }.`,
    },
    { id: 'PC-15, PC-16', text: 'Losing a member locks new content and invitations until the room key is rotated.' },
  ];
}

const UPGRADE_EFFECTS =
  'Takes effect at once. Existing expiry dates are shortened to the new maximum, open invitations and secrets that break the new rules are revoked, and members who do not meet the new sign-in rules lose access until they do. Nothing is re-encrypted.';
const DOWNGRADE_EFFECTS = `Weakens the room's controls for new content and requests. Existing expiry dates are not extended. You must confirm your identity within the last ${
  PROFILE_CHANGE_RULES.downgradeStepUpMs / 60_000
} minutes, and the change is recorded as a high-severity event.`;

type Act = (action: () => Promise<void>, stepUpReason: string, done?: string) => Promise<void>;

export function ProfilePanel({
  roomId,
  role,
  policy,
  onAction,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly policy: ProfilePolicy;
  readonly onAction: Act;
}) {
  const others = SECURITY_PROFILES.filter((p) => p !== policy.profile);
  const [target, setTarget] = useState<SecurityProfile>(others[0] ?? policy.profile);
  const [understood, setUnderstood] = useState(false);
  const direction = profileChangeDirection(policy, currentPolicy(target));
  const canChange = mayAttempt('AZ-03', role);

  function onSubmit(event: SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!understood) return;
    void onAction(
      async () => {
        await api('POST', `/rooms/${roomId}/profile`, profileChangedResponseSchema, {
          securityProfile: target,
          // A precondition only: the API refuses the change if the stored profile differs.
          expectedProfile: policy.profile,
        });
        setUnderstood(false);
      },
      direction === 'DOWNGRADE'
        ? 'Lowering the security profile needs an identity confirmation from the last 5 minutes.'
        : 'Changing the security profile of this room needs a recent identity confirmation.',
      `The room is now ${LABEL[target]}.`,
    );
  }

  return (
    <Card
      title="Security profile"
      icon="trust"
      description="The room’s information classification. It governs access, handling and lifetime; the encryption is the same in every profile."
    >
      <p className="text-sm" data-testid="profile-current">
        <span className="font-medium">{LABEL[policy.profile]}</span>
        <span className="text-xs text-slate-400"> · policy version {policy.version}</span>
      </p>
      <p className="text-xs text-slate-500">
        The server enforces these rules for every member, whatever this page shows.
      </p>
      <ul className="grid gap-2 text-sm text-slate-300 md:grid-cols-2" aria-label="Enforced rules">
        {describePolicy(policy).map((rule) => (
          <li key={rule.id} className="flex gap-2.5 rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
            <span className="mt-0.5 shrink-0 font-mono text-[11px] text-accent-300">{rule.id}</span>
            <span>{rule.text}</span>
          </li>
        ))}
      </ul>
      {policy.cryptoperiodMs === null ? null : (
        <p className="text-xs text-slate-500">
          Room key cryptoperiod: the worker locks the room for a rekey when the current key version is older than{' '}
          {duration(policy.cryptoperiodMs)}; members are reminded 14 days before.
        </p>
      )}
      {canChange ? (
        <form className="space-y-3 border-t border-slate-800 pt-3" onSubmit={onSubmit} aria-label="Change profile">
          <label className="block space-y-1 text-sm">
            <span>Change the profile to</span>
            <select
              name="securityProfile"
              className={`${controlClass} sm:w-auto`}
              value={target}
              onChange={(event) => {
                setTarget(event.target.value as SecurityProfile);
                setUnderstood(false);
              }}
            >
              {others.map((p) => (
                <option key={p} value={p}>
                  {LABEL[p]}
                </option>
              ))}
            </select>
          </label>
          <Alert kind={direction === 'DOWNGRADE' ? 'error' : 'info'}>
            {direction === 'DOWNGRADE' ? DOWNGRADE_EFFECTS : UPGRADE_EFFECTS}
          </Alert>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              name="understood"
              checked={understood}
              onChange={(event) => {
                setUnderstood(event.target.checked);
              }}
            />
            <span>
              I understand what changes when this room becomes {LABEL[target]}
              {direction === 'DOWNGRADE' ? ' (a weaker profile)' : ''}.
            </span>
          </label>
          <Button type="submit" disabled={!understood}>
            Change profile
          </Button>
        </form>
      ) : null}
    </Card>
  );
}
