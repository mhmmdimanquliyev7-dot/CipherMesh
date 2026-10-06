'use client';

import { ROOM_NAME_MAX_LENGTH, SECURITY_PROFILES } from '@ciphermesh/shared';
import { roomListResponseSchema, roomSummarySchema, type RoomSummary } from '@ciphermesh/validation';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type SyntheticEvent } from 'react';
import { Alert, Button, Card, Field, SecondaryButton } from '../../components/ui';
import { api, ApiError, formText } from '../../lib/api';
import { describeRoomError, REKEY_NOTICE, ROOM_NAME_WARNING } from '../../rooms/messages';
import { PROFILE_DESCRIPTION, ROLE_LABEL } from '../../rooms/permissions';

/**
 * Rooms (Phase 5, CM-T030): the rooms the signed-in user belongs to, and room creation. The list
 * and every permission come from the API, which filters by the user's memberships; this page only
 * shows what it answers. Rooms hold no content yet: client-side encrypted files, notes and secrets
 * arrive in later phases, and members join through invitations from Phase 6 on.
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
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Rooms</h1>
      <p className="max-w-3xl text-sm text-slate-400">
        A room groups people with roles. Its security profile records how sensitive the room is: creating a CONFIDENTIAL
        or RESTRICTED room already needs a session verified with an authentication code, and the profile&apos;s other
        rules are enforced from a later phase on. Client-side encrypted files, notes and secrets are not available yet,
        and members join through invitations, which also arrive in a later phase.
      </p>
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
      <CreateRoom
        onCreated={(roomId) => {
          router.push(`/rooms/room?id=${roomId}`);
        }}
      />
      <Card title="Your rooms">
        {rooms === undefined ? (
          <p className="text-slate-400">Loading…</p>
        ) : rooms.length === 0 ? (
          <p className="text-sm text-slate-400">You are not a member of any room yet.</p>
        ) : (
          <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Your rooms">
            {rooms.map((room) => (
              <li key={room.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <Link className="font-medium text-sky-300 underline" href={`/rooms/room?id=${room.id}`}>
                  {room.name}
                </Link>
                <span className="flex flex-wrap gap-2 text-xs">
                  <span className="rounded bg-slate-800 px-2 py-0.5">{room.securityProfile}</span>
                  <span className="rounded bg-slate-800 px-2 py-0.5">{ROLE_LABEL[room.role]}</span>
                  {room.keyState === 'ACTIVE' ? null : (
                    <span
                      className="rounded border border-amber-500/40 px-2 py-0.5 text-amber-300"
                      title={REKEY_NOTICE}
                    >
                      Key rotation required
                    </span>
                  )}
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
    </div>
  );
}

function CreateRoom({ onCreated }: { readonly onCreated: (roomId: string) => void }) {
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
      // The browser chooses the room ID: from Phase 6 on it enters the room's key contexts (DF-05).
      const created = await api('POST', '/rooms', roomSummarySchema, {
        roomId: crypto.randomUUID(),
        name: formText(form, 'name'),
        securityProfile: formText(form, 'securityProfile'),
      });
      onCreated(created.id);
    } catch (e) {
      setVaultMissing(e instanceof ApiError && e.code === 'VAULT_SETUP_REQUIRED');
      setError(describeRoomError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Create a room">
      <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label="Room name" name="name" maxLength={ROOM_NAME_MAX_LENGTH} required hint={ROOM_NAME_WARNING} />
        <label className="block space-y-1">
          <span className="text-sm text-slate-300">Security profile</span>
          <select
            name="securityProfile"
            defaultValue="STANDARD"
            className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 focus:border-sky-500 focus:outline-none"
          >
            {SECURITY_PROFILES.map((profile) => (
              <option key={profile} value={profile}>
                {profile}
              </option>
            ))}
          </select>
        </label>
        <ul className="space-y-1 text-xs text-slate-500">
          {SECURITY_PROFILES.map((profile) => (
            <li key={profile}>
              <span className="font-medium text-slate-400">{profile}:</span> {PROFILE_DESCRIPTION[profile]}
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
        <Button type="submit" disabled={busy}>
          Create room
        </Button>
      </form>
    </Card>
  );
}
