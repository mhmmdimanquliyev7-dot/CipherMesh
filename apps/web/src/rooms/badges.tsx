import type { RoomRole, SecurityProfile } from '@ciphermesh/shared';
import { Badge } from '../components/ui';
import { REKEY_NOTICE } from './messages';
import { ROLE_LABEL } from './permissions';

/** Labels for a room's classification, the caller's role and the key state, used on every page. */

const PROFILE_TONE = { STANDARD: 'neutral', CONFIDENTIAL: 'warning', RESTRICTED: 'danger' } as const;

export function ProfileBadge({ profile }: { readonly profile: SecurityProfile }) {
  return (
    <Badge tone={PROFILE_TONE[profile]} icon="trust" title="Security profile (information classification)">
      {profile}
    </Badge>
  );
}

export function RoleBadge({ role, prefix = '' }: { readonly role: RoomRole; readonly prefix?: string }) {
  return (
    <Badge tone="neutral" icon="account">
      {prefix}
      {ROLE_LABEL[role]}
    </Badge>
  );
}

/** Only states other than ACTIVE are worth a badge: they restrict what the room accepts. */
export function KeyStateBadge({ keyState }: { readonly keyState: string }) {
  if (keyState === 'ACTIVE') return null;
  return (
    <Badge tone="warning" icon="rotate" title={REKEY_NOTICE}>
      Key rotation required
    </Badge>
  );
}
