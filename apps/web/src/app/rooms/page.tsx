'use client';

import { ROOM_NAME_MAX_LENGTH, SECURITY_PROFILES } from '@ciphermesh/shared';
import { roomListResponseSchema, type RoomSummary } from '@ciphermesh/validation';
import Link from 'next/link';
import { Icon } from '../../components/icons';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import {
  Alert,
  Button,
  Card,
  controlClass,
  EmptyState,
  Field,
  labelClass,
  Loading,
  PageHeader,
  SecondaryButton,
} from '../../components/ui';
import { KeyStateBadge, ProfileBadge, RoleBadge } from '../../rooms/badges';
import { api, ApiError, formText } from '../../lib/api';
import { roomKeys } from '../../rooms/keys';
import { describeRoomError, ROOM_NAME_WARNING } from '../../rooms/messages';
import { PROFILE_DESCRIPTION } from '../../rooms/permissions';
import { useVault } from '../../vault/use-vault';

/**
 * Rooms (Phase 5, CM-T030; Phase 6, CM-T033): the rooms the signed-in user belongs to, and room
 * creation. The list and every permission come from the API, which filters by the user's
 * memberships. Creating a room creates its first room key in this browser, so it needs the
 * unlocked vault; only the commitment, signatures and the owner's envelope are sent (DF-05).
 */
export default function RoomsPage() {
  const router = useRouter();
  const [rooms, setRooms] = useState<RoomSummary[] | undefined>();
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | undefined>();

  const load = useCallback(
    async (cursor?: string) => {
      try {
        const page = await api(
          'GET',
          cursor === undefined ? '/rooms' : `/rooms?cursor=${encodeURIComponent(cursor)}`,
          roomListResponseSchema,
        );
        setRooms((current) => (cursor === undefined ? page.rooms : [...(current ?? []), ...page.rooms]));
        setNextCursor(page.nextCursor);
      } catch (e) {
        if (e instanceof ApiError && e.code === 'UNAUTHENTICATED') router.replace('/login');
        else setError(describeRoomError(e));
      }
    },
    [router],
  );

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Rooms"
        description="A room groups people with roles and has its own room key, created in a browser and shared with each member as an envelope only their identity can open. Files, notes and secrets in a room are encrypted on members' devices. Its security profile classifies how sensitive the room is."
      />
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
      <div className="grid items-start gap-6 xl:grid-cols-[1.5fr_1fr]">
        <Card title="Your rooms" icon="rooms">
          {rooms === undefined ? (
            <Loading />
          ) : rooms.length === 0 ? (
            <EmptyState icon="rooms" title="You are not a member of any room yet.">
              Create one with your unlocked vault, or accept an invitation.
            </EmptyState>
          ) : (
            <ul
              className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800"
              aria-label="Your rooms"
            >
              {rooms.map((room) => (
                <li
                  key={room.id}
                  className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 hover:bg-slate-800/30"
                >
                  <span className="flex min-w-0 items-center gap-3">
                    <span
                      className="grid size-9 shrink-0 place-items-center rounded-lg bg-slate-800/80 text-accent-300"
                      aria-hidden="true"
                    >
                      <Icon name="rooms" className="size-4" />
                    </span>
                    <Link
                      className="min-w-0 break-words font-medium text-white hover:text-accent-200"
                      href={`/rooms/room?id=${room.id}`}
                    >
                      {room.name}
                    </Link>
                  </span>
                  <span className="flex flex-wrap gap-1.5">
                    <ProfileBadge profile={room.securityProfile} />
                    <RoleBadge role={room.role} />
                    <KeyStateBadge keyState={room.keyState} />
                  </span>
                </li>
              ))}
            </ul>
          )}
          {nextCursor === null ? null : (
            <SecondaryButton
              type="button"
              onClick={() => {
                void load(nextCursor);
              }}
            >
              Show more rooms
            </SecondaryButton>
          )}
        </Card>
        <CreateRoom
          onCreated={(roomId) => {
            router.push(`/rooms/room?id=${roomId}`);
          }}
        />
      </div>
    </div>
  );
}

function CreateRoom({ onCreated }: { readonly onCreated: (roomId: string) => void }) {
  const vault = useVault();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [vaultMissing, setVaultMissing] = useState(false);

  async function onSubmit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(undefined);
    setVaultMissing(false);
    try {
      // The browser chooses the room ID and creates key version 1 for it (DF-05, CM-T033).
      onCreated(await roomKeys.createRoom(formText(form, 'name'), formText(form, 'securityProfile')));
    } catch (e) {
      setVaultMissing(e instanceof ApiError && e.code === 'VAULT_SETUP_REQUIRED');
      setError(describeRoomError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Create a room"
      id="create-room"
      icon="plus"
      description="Its first room key is created and signed in this browser."
    >
      <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Room name" name="name" maxLength={ROOM_NAME_MAX_LENGTH} required hint={ROOM_NAME_WARNING} />
        <label className="block space-y-1.5">
          <span className={labelClass}>Security profile</span>
          <select name="securityProfile" defaultValue="STANDARD" className={controlClass}>
            {SECURITY_PROFILES.map((profile) => (
              <option key={profile} value={profile}>
                {profile}
              </option>
            ))}
          </select>
        </label>
        <ul className="space-y-2 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs leading-relaxed text-slate-400">
          {SECURITY_PROFILES.map((profile) => (
            <li key={profile}>
              <span className="font-semibold text-slate-200">{profile}:</span> {PROFILE_DESCRIPTION[profile]}
            </li>
          ))}
        </ul>
        {error === undefined ? null : (
          <Alert kind="error">
            {error}{' '}
            {vaultMissing ? (
              <Link className="underline" href="/vault">
                Go to your vault
              </Link>
            ) : null}
          </Alert>
        )}
        {vault.kind === 'unlocked' ? null : (
          <Alert kind="info">
            Unlock your vault to create a room: its room key is created in this browser.{' '}
            <Link className="underline" href="/vault">
              Go to your vault
            </Link>
          </Alert>
        )}
        <Button type="submit" disabled={busy || vault.kind !== 'unlocked'}>
          Create room
        </Button>
      </form>
    </Card>
  );
}
