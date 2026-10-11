'use client';

import { NOTE_RULES, roomRuleFor, type RoomRole, type SecurityProfile } from '@ciphermesh/shared';
import type { RoomMember } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useState, useSyncExternalStore, type SyntheticEvent } from 'react';
import { Alert, Button, Card, SecondaryButton } from '../components/ui';
import { ApiError } from '../lib/api';
import { useVault } from '../vault/use-vault';
import { roomKeys } from './keys';
import {
  describeNoteError,
  NOTE_CONFLICT,
  NOTE_INTEGRITY_ERROR,
  NOTE_ROLLBACK,
  NOTE_UNSUPPORTED,
  NOTES_EXPLANATION,
} from './messages';
import {
  createNote,
  deleteNote,
  fetchNote,
  listNotes,
  NOTE_MAX_KIB,
  NOTE_TITLE_MAX,
  noteFits,
  saveNote,
  type NoteEntry,
} from './notes';
import { mayAttempt } from './permissions';

/**
 * The Notes section of a room (Phase 8, CM-T042). Titles and bodies exist only in this browser
 * after authenticated decryption with a room key verified here; the list from the server carries
 * ciphertext. Note text is untrusted and rendered as plain text only (React escaping, no HTML or
 * Markdown, T-12). Controls follow the shared matrix as UX only: the API authorizes every request
 * (INV-05). Decrypted text is dropped as soon as the room keys go away (vault lock, sign-out).
 */

const DAY = 24 * 60 * 60_000;
const notOpen = (): boolean => false;
const formatDate = (iso: string | null): string => (iso === null ? 'Never' : new Date(iso).toLocaleString());

/** Expiry choices the profile allows (PC-08), with its default first. */
function expiryChoices(profile: SecurityProfile): { readonly label: string; readonly days: number | null }[] {
  const rules = NOTE_RULES[profile];
  const days = [1, 7, 30, 90].filter((d) => rules.maxExpiryMs === null || d * DAY <= rules.maxExpiryMs);
  const choices: { label: string; days: number | null }[] = days.map((d) => ({
    label: d === 1 ? '1 day' : `${String(d)} days`,
    days: d,
  }));
  if (!rules.expiryRequired) choices.unshift({ label: 'No expiry', days: null });
  const preferred = rules.defaultExpiryMs === null ? null : rules.defaultExpiryMs / DAY;
  return [...choices].sort((a, b) => (a.days === preferred ? -1 : b.days === preferred ? 1 : 0));
}

const inputClass =
  'w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 focus:border-sky-500 focus:outline-none';

/** The text fields of a new note or an edit. Plain text only. */
function NoteFields({
  title,
  body,
  onTitle,
  onBody,
  disabled,
}: {
  readonly title: string;
  readonly body: string;
  readonly onTitle: (value: string) => void;
  readonly onBody: (value: string) => void;
  readonly disabled: boolean;
}) {
  return (
    <>
      <label className="block space-y-1">
        <span className="text-sm text-slate-300">Title (encrypted, at most {NOTE_TITLE_MAX} characters)</span>
        <input
          name="title"
          value={title}
          maxLength={NOTE_TITLE_MAX}
          disabled={disabled}
          onChange={(e) => {
            onTitle(e.target.value);
          }}
          data-testid="note-title-input"
          className={inputClass}
          autoComplete="off"
          spellCheck
        />
      </label>
      <label className="block space-y-1">
        <span className="text-sm text-slate-300">Note (encrypted plain text, at most {NOTE_MAX_KIB} KiB)</span>
        <textarea
          name="body"
          value={body}
          rows={8}
          disabled={disabled}
          onChange={(e) => {
            onBody(e.target.value);
          }}
          data-testid="note-body-input"
          className={`${inputClass} font-mono text-sm`}
          spellCheck
        />
      </label>
      {noteFits(title, body) ? null : (
        <p className="text-sm text-red-300" role="alert">
          This note is longer than {NOTE_MAX_KIB} KiB and cannot be saved.
        </p>
      )}
    </>
  );
}

/** One-line titles: the same rule the crypto package enforces (no control characters). */
// eslint-disable-next-line no-control-regex -- the class is the point: it detects control characters
const TITLE_CONTROL = /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/;
const titleProblem = (title: string): string | undefined =>
  title.trim() === ''
    ? 'Give the note a title.'
    : TITLE_CONTROL.test(title)
      ? 'The title cannot contain control or text-direction characters.'
      : undefined;

type Editing = { readonly noteId: string; readonly baseRevision: number; title: string; body: string };

export function NotePanel({
  roomId,
  role,
  profile,
  keyState,
  selfId,
  members,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  readonly profile: SecurityProfile;
  readonly keyState: string;
  readonly selfId: string;
  readonly members: readonly RoomMember[];
}) {
  const vault = useVault();
  const held = useSyncExternalStore(roomKeys.subscribe, () => roomKeys.isOpen(roomId), notOpen);
  const [entries, setEntries] = useState<NoteEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();
  const [busy, setBusy] = useState<string | undefined>();
  const [composing, setComposing] = useState(false);
  const [draft, setDraft] = useState({ title: '', body: '' });
  const [selected, setSelected] = useState<string | undefined>();
  const [editing, setEditing] = useState<Editing | undefined>();
  const [conflict, setConflict] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | undefined>();

  const load = useCallback(async () => {
    try {
      const page = await listNotes(roomId);
      setEntries(page.entries);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeNoteError(error) });
    } finally {
      setLoaded(true);
    }
  }, [roomId]);

  // Reload whenever the verified keys arrive or go away: note text exists only while keys are held.
  useEffect(() => {
    void load();
  }, [load, held]);
  // A vault lock drops every decrypted title and body at once, before any reload answers.
  useEffect(() => {
    if (held) return;
    setEntries((current) =>
      current.map(({ view, rolledBack }) => (rolledBack === true ? { view, rolledBack } : { view })),
    );
    setEditing(undefined);
    setComposing(false);
    setDraft({ title: '', body: '' });
  }, [held]);

  const unlocked = vault.kind === 'unlocked' && held;
  const writable = keyState === 'ACTIVE';
  const canCreate = mayAttempt('AZ-19', role);
  const mayChange = (action: 'AZ-21' | 'AZ-22', authorId: string): boolean => {
    const rule = roomRuleFor(action, role);
    return rule.kind === 'allow' || (rule.kind === 'own' && authorId === selfId);
  };
  const nameOf = (id: string): string => members.find((m) => m.userId === id)?.displayName ?? 'Former member';
  const current = entries.find((e) => e.view.id === selected);
  const dirty =
    (composing && (draft.title !== '' || draft.body !== '')) ||
    (editing !== undefined &&
      (current?.opened === undefined ||
        editing.title !== current.opened.title ||
        editing.body !== current.opened.body));

  // Leaving the page with unsaved text asks first; the text itself is never stored anywhere.
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => {
      window.removeEventListener('beforeunload', warn);
    };
  }, [dirty]);

  async function run(key: string, action: () => Promise<void>): Promise<void> {
    setMessage(undefined);
    setBusy(key);
    try {
      await action();
    } catch (error) {
      if (error instanceof ApiError && error.code === 'REVISION_CONFLICT') setConflict(true);
      setMessage({ kind: 'error', text: describeNoteError(error) });
    } finally {
      setBusy(undefined);
    }
  }

  const replace = (entry: NoteEntry): void => {
    setEntries((list) => [entry, ...list.filter((e) => e.view.id !== entry.view.id)]);
  };

  async function onCreate(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const problem = titleProblem(draft.title);
    if (problem !== undefined) {
      setMessage({ kind: 'error', text: problem });
      return;
    }
    const expiry = event.currentTarget.elements.namedItem('expiry');
    const days = expiry instanceof HTMLSelectElement && expiry.value !== '' ? Number(expiry.value) : null;
    const expiresAt = days === null ? null : new Date(Date.now() + days * DAY).toISOString();
    await run('create', async () => {
      const entry = await createNote(roomId, draft.title.trim(), draft.body, expiresAt);
      replace(entry);
      setDraft({ title: '', body: '' });
      setComposing(false);
      setSelected(entry.view.id);
      setMessage({ kind: 'info', text: 'The note was encrypted in your browser and saved.' });
    });
  }

  async function onSave(): Promise<void> {
    if (editing === undefined) return;
    const problem = titleProblem(editing.title);
    if (problem !== undefined) {
      setMessage({ kind: 'error', text: problem });
      return;
    }
    await run('save', async () => {
      const entry = await saveNote(roomId, editing.noteId, editing.baseRevision, editing.title.trim(), editing.body);
      replace(entry);
      setEditing(undefined);
      setConflict(false);
      setMessage({ kind: 'info', text: `Saved as revision ${String(entry.view.revision)}.` });
    });
  }

  /** After a conflict: load the latest revision; the editor keeps the user's text until they discard it. */
  const reloadLatest = (noteId: string) =>
    run('reload', async () => {
      const entry = await fetchNote(roomId, noteId);
      replace(entry);
      setConflict(false);
      setEditing((e) => (e === undefined ? e : { ...e, baseRevision: entry.view.revision }));
      setMessage({
        kind: 'info',
        text: `Revision ${String(entry.view.revision)} is loaded above. Your text is still in the editor; saving now replaces that revision.`,
      });
    });

  const remove = (noteId: string) =>
    run(`delete-${noteId}`, async () => {
      await deleteNote(roomId, noteId);
      setEntries((list) => list.filter((e) => e.view.id !== noteId));
      setConfirmDelete(undefined);
      setSelected(undefined);
      setEditing(undefined);
      setMessage({ kind: 'info', text: 'The note was deleted for every member.' });
    });

  async function loadMore(): Promise<void> {
    if (nextCursor === null) return;
    try {
      const page = await listNotes(roomId, nextCursor);
      setEntries((list) => [...list, ...page.entries]);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeNoteError(error) });
    }
  }

  const labelOf = (entry: NoteEntry): string =>
    entry.opened !== undefined
      ? entry.opened.title
      : entry.problem === 'damaged'
        ? 'Damaged note (integrity check failed)'
        : entry.problem === 'unsupported'
          ? 'Note in an unsupported format'
          : 'Encrypted note';

  return (
    <Card title="Notes">
      <div data-testid="notes-card" className="space-y-4">
        <p className="text-xs text-slate-500">{NOTES_EXPLANATION}</p>
        {message === undefined ? null : (
          <div data-testid="note-message">
            <Alert kind={message.kind}>{message.text}</Alert>
          </div>
        )}

        {vault.kind !== 'unlocked' ? (
          <p className="text-sm text-slate-400" data-testid="notes-locked">
            Notes are encrypted on this device.{' '}
            <Link className="text-sky-400 underline" href="/vault">
              Unlock your vault
            </Link>{' '}
            to read and write them.
          </p>
        ) : !held ? (
          <p className="text-sm text-slate-400" data-testid="notes-no-key">
            The room key is not open on this device yet, so notes cannot be decrypted. Open it in the room key section
            above.
          </p>
        ) : !canCreate ? null : !writable ? (
          <p className="text-sm text-slate-400">New notes cannot be added or edited until the room key is rotated.</p>
        ) : composing ? (
          <form className="space-y-3" onSubmit={(e) => void onCreate(e)} noValidate aria-label="New note">
            <NoteFields
              title={draft.title}
              body={draft.body}
              onTitle={(title) => {
                setDraft((d) => ({ ...d, title }));
              }}
              onBody={(body) => {
                setDraft((d) => ({ ...d, body }));
              }}
              disabled={busy !== undefined}
            />
            <label className="block space-y-1">
              <span className="text-sm text-slate-300">Expires</span>
              <select
                name="expiry"
                data-testid="note-expiry"
                className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
              >
                {expiryChoices(profile).map((choice) => (
                  <option key={choice.label} value={choice.days === null ? '' : String(choice.days)}>
                    {choice.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex flex-wrap gap-2">
              <Button
                type="submit"
                disabled={busy !== undefined || !noteFits(draft.title, draft.body)}
                data-testid="note-create"
              >
                {busy === 'create' ? 'Encrypting and saving…' : 'Encrypt and save'}
              </Button>
              <SecondaryButton
                type="button"
                onClick={() => {
                  setComposing(false);
                  setDraft({ title: '', body: '' });
                }}
              >
                Cancel
              </SecondaryButton>
            </div>
          </form>
        ) : (
          <SecondaryButton
            type="button"
            onClick={() => {
              setComposing(true);
            }}
            data-testid="note-new"
          >
            New note
          </SecondaryButton>
        )}

        {!loaded ? (
          <p className="text-sm text-slate-400" role="status">
            Loading notes…
          </p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-slate-400" data-testid="notes-empty">
            No notes yet.
          </p>
        ) : (
          <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Notes">
            {entries.map((entry) => {
              const { view } = entry;
              const open = selected === view.id;
              return (
                <li key={view.id} className="space-y-3 px-4 py-3" data-testid="note-row">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <button
                      type="button"
                      className="min-w-0 text-left"
                      aria-expanded={open}
                      onClick={() => {
                        if (open && dirty) return;
                        setSelected(open ? undefined : view.id);
                        setEditing(undefined);
                        setConflict(false);
                        setConfirmDelete(undefined);
                      }}
                      data-testid="note-open"
                    >
                      <span className="block break-all font-medium" data-testid="note-title">
                        {labelOf(entry)}
                      </span>
                      <span className="block text-xs text-slate-400">
                        {nameOf(view.authorId)} · revision {String(view.revision)} · updated{' '}
                        {formatDate(view.updatedAt)}
                        {view.updatedById === view.authorId ? '' : ` by ${nameOf(view.updatedById)}`}
                        {view.expiresAt === null ? '' : ` · expires ${formatDate(view.expiresAt)}`}
                      </span>
                    </button>
                    {mayChange('AZ-22', view.authorId) ? (
                      confirmDelete === view.id ? (
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="text-sm text-red-200">Delete for every member?</span>
                          <SecondaryButton
                            type="button"
                            disabled={busy !== undefined}
                            onClick={() => void remove(view.id)}
                            data-testid="note-delete-confirm"
                          >
                            Delete
                          </SecondaryButton>
                          <SecondaryButton
                            type="button"
                            onClick={() => {
                              setConfirmDelete(undefined);
                            }}
                          >
                            Keep
                          </SecondaryButton>
                        </span>
                      ) : (
                        <SecondaryButton
                          type="button"
                          disabled={busy !== undefined}
                          onClick={() => {
                            setConfirmDelete(view.id);
                          }}
                          data-testid="note-delete"
                        >
                          Delete
                        </SecondaryButton>
                      )
                    ) : null}
                  </div>
                  {entry.rolledBack === true ? <Alert kind="error">{NOTE_ROLLBACK}</Alert> : null}
                  {open ? (
                    <div className="space-y-3" data-testid="note-view">
                      {entry.problem === 'damaged' ? <Alert kind="error">{NOTE_INTEGRITY_ERROR}</Alert> : null}
                      {entry.problem === 'unsupported' ? <Alert kind="error">{NOTE_UNSUPPORTED}</Alert> : null}
                      {entry.opened === undefined ? (
                        entry.problem === undefined ? (
                          <p className="text-sm text-slate-400">
                            {unlocked
                              ? 'This note uses a room key version this device does not hold.'
                              : 'Unlock your vault to decrypt this note.'}
                          </p>
                        ) : null
                      ) : (
                        <>
                          <h3 className="break-words text-base font-semibold" data-testid="note-view-title">
                            {entry.opened.title}
                          </h3>
                          {/* Untrusted text: React renders it as text, never as HTML or Markdown (T-12). */}
                          <div
                            className="whitespace-pre-wrap break-words rounded border border-slate-800 bg-slate-950 p-3 text-sm"
                            data-testid="note-view-body"
                          >
                            {entry.opened.body === '' ? (
                              <span className="text-slate-500">(empty)</span>
                            ) : (
                              entry.opened.body
                            )}
                          </div>
                          {editing === undefined && writable && unlocked && mayChange('AZ-21', view.authorId) ? (
                            <SecondaryButton
                              type="button"
                              onClick={() => {
                                const { title, body } = entry.opened ?? { title: '', body: '' };
                                setEditing({ noteId: view.id, baseRevision: view.revision, title, body });
                              }}
                              data-testid="note-edit"
                            >
                              Edit
                            </SecondaryButton>
                          ) : null}
                        </>
                      )}
                      {editing !== undefined && editing.noteId === view.id ? (
                        <form
                          className="space-y-3"
                          aria-label="Edit note"
                          onSubmit={(e) => {
                            e.preventDefault();
                            void onSave();
                          }}
                          noValidate
                        >
                          <NoteFields
                            title={editing.title}
                            body={editing.body}
                            onTitle={(title) => {
                              setEditing((e) => (e === undefined ? e : { ...e, title }));
                            }}
                            onBody={(body) => {
                              setEditing((e) => (e === undefined ? e : { ...e, body }));
                            }}
                            disabled={busy !== undefined}
                          />
                          {dirty ? (
                            <p className="text-xs text-amber-200" data-testid="note-unsaved">
                              Unsaved changes
                            </p>
                          ) : null}
                          {conflict ? (
                            <div className="space-y-2" data-testid="note-conflict">
                              <Alert kind="error">{NOTE_CONFLICT}</Alert>
                              <SecondaryButton type="button" onClick={() => void reloadLatest(view.id)}>
                                Load the latest version
                              </SecondaryButton>
                            </div>
                          ) : null}
                          <div className="flex flex-wrap gap-2">
                            <Button
                              type="submit"
                              disabled={busy !== undefined || conflict || !noteFits(editing.title, editing.body)}
                              data-testid="note-save"
                            >
                              {busy === 'save' ? 'Encrypting and saving…' : 'Encrypt and save'}
                            </Button>
                            <SecondaryButton
                              type="button"
                              onClick={() => {
                                setEditing(undefined);
                                setConflict(false);
                              }}
                            >
                              Discard changes
                            </SecondaryButton>
                          </div>
                        </form>
                      ) : null}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
        {nextCursor === null ? null : (
          <SecondaryButton type="button" onClick={() => void loadMore()}>
            Show more notes
          </SecondaryButton>
        )}
      </div>
    </Card>
  );
}
