'use client';

import type { OpenedFile } from '@ciphermesh/crypto';
import { FILE_TAG_BYTES, roomRuleFor, type ProfilePolicy, type RoomRole } from '@ciphermesh/shared';
import type { RoomMember } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type SyntheticEvent } from 'react';
import { Icon } from '../components/icons';
import { Alert, Button, Card, controlClass, EmptyState, labelClass, SecondaryButton } from '../components/ui';
import { ApiError } from '../lib/api';
import { useVault } from '../vault/use-vault';
import {
  decryptFile,
  deleteFile,
  isPreviewable,
  isRiskyName,
  listFiles,
  previewUrl,
  safeDownloadName,
  saveToDevice,
  uploadFile,
  type FileEntry,
  type UploadStage,
} from './files';
import { roomKeys } from './keys';
import { describeRoomError, FILES_EXPLANATION } from './messages';
import { mayAttempt } from './permissions';
import { FileReceipt } from './receipts';

/**
 * The Files section of a room (Phase 7, CM-T038 to CM-T041). Names, types and contents exist only
 * in this browser after authenticated decryption with a room key verified here; the list from the
 * server carries ciphertext references and sizes. Decrypted names are untrusted text and are
 * rendered as text only. Downloads are saved as opaque bytes with a sanitized name; only raster
 * images are previewed, through a temporary blob URL in an <img> element. Controls follow the
 * shared matrix as UX only: the API authorizes every request (INV-05).
 */

const DAY = 24 * 60 * 60_000;
const notOpen = (): boolean => false;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

const formatDate = (iso: string | null): string => (iso === null ? 'Never' : new Date(iso).toLocaleString());

/** Expiry choices the profile allows (PC-08), with its default first. */
function expiryChoices(policy: ProfilePolicy): { readonly label: string; readonly days: number | null }[] {
  const rules = policy.contentExpiry;
  const days = [1, 7, 30, 90].filter((d) => rules.maxMs === null || d * DAY <= rules.maxMs);
  const choices: { label: string; days: number | null }[] = days.map((d) => ({
    label: d === 1 ? '1 day' : `${String(d)} days`,
    days: d,
  }));
  if (!rules.required) choices.unshift({ label: 'No expiry', days: null });
  const preferred = rules.defaultMs === null ? null : rules.defaultMs / DAY;
  return [...choices].sort((a, b) => (a.days === preferred ? -1 : b.days === preferred ? 1 : 0));
}

const STAGE_TEXT: Readonly<Record<UploadStage, string>> = {
  reading: 'Reading the file…',
  encrypting: 'Encrypting in your browser…',
  uploading: 'Uploading the encrypted file…',
  finishing: 'Finishing…',
};

type Preview = { readonly url: string; readonly name: string } | undefined;

export function FilePanel({
  roomId,
  role,
  policy,
  keyState,
  selfId,
  members,
  onStepUp,
}: {
  readonly roomId: string;
  readonly role: RoomRole;
  /** The room's policy, resolved from its stored profile and version (CM-T046). */
  readonly policy: ProfilePolicy;
  readonly keyState: string;
  readonly selfId: string;
  readonly members: readonly RoomMember[];
  /** Asks the page for a step-up (PC-03 in RESTRICTED rooms), then runs `retry`. */
  readonly onStepUp: (reason: string, retry: () => Promise<void>) => void;
}) {
  const vault = useVault();
  const held = useSyncExternalStore(roomKeys.subscribe, () => roomKeys.isOpen(roomId), notOpen);
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | undefined>();
  const [stage, setStage] = useState<{ stage: UploadStage; progress?: number } | undefined>();
  const [busyFile, setBusyFile] = useState<string | undefined>();
  const [confirmRisky, setConfirmRisky] = useState<string | undefined>();
  const [preview, setPreview] = useState<Preview>();
  const previewRef = useRef<Preview>(undefined);

  const load = useCallback(async () => {
    try {
      const page = await listFiles(roomId);
      setEntries(page.entries);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeRoomError(error) });
    }
  }, [roomId]);

  // Reload whenever the verified keys arrive or go away: names exist only while keys are held.
  useEffect(() => {
    void load();
  }, [load, held]);

  const closePreview = useCallback(() => {
    if (previewRef.current !== undefined) URL.revokeObjectURL(previewRef.current.url);
    previewRef.current = undefined;
    setPreview(undefined);
  }, []);
  // A preview never outlives the page, a vault lock or the dropped keys.
  useEffect(() => closePreview, [closePreview]);
  useEffect(() => {
    if (!held) closePreview();
  }, [held, closePreview]);

  const canUpload = mayAttempt('AZ-16', role);
  const mayDelete = (uploaderId: string): boolean => {
    const rule = roomRuleFor('AZ-18', role);
    return rule.kind === 'allow' || (rule.kind === 'own' && uploaderId === selfId);
  };
  const viewerRestricted = role === 'VIEWER' && !policy.viewerMayObtainFileKeys;
  const unlocked = vault.kind === 'unlocked' && held;
  const nameOfUploader = (id: string): string => members.find((m) => m.userId === id)?.displayName ?? 'Former member';

  async function onUpload(event: SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const input = form.elements.namedItem('file');
    const expiry = form.elements.namedItem('expiry');
    const file = input instanceof HTMLInputElement ? input.files?.[0] : undefined;
    if (file === undefined) {
      setMessage({ kind: 'error', text: 'Choose a file first.' });
      return;
    }
    const days = expiry instanceof HTMLSelectElement && expiry.value !== '' ? Number(expiry.value) : null;
    const expiresAt = days === null ? null : new Date(Date.now() + days * DAY).toISOString();
    setMessage(undefined);
    try {
      await uploadFile(roomId, file, expiresAt, (s, progress) => {
        setStage(progress === undefined ? { stage: s } : { stage: s, progress });
      });
      form.reset();
      setMessage({ kind: 'info', text: 'The file was encrypted in your browser and uploaded.' });
      await load();
    } catch (error) {
      setMessage({ kind: 'error', text: describeRoomError(error) });
    } finally {
      setStage(undefined);
    }
  }

  async function withFile(fileId: string, action: () => Promise<void>): Promise<void> {
    setMessage(undefined);
    setBusyFile(fileId);
    try {
      await action();
    } catch (error) {
      if (error instanceof ApiError && error.code === 'STEP_UP_REQUIRED') {
        onStepUp('Downloading files in a restricted room requires confirming your identity.', () =>
          withFile(fileId, action),
        );
      } else {
        setMessage({ kind: 'error', text: describeRoomError(error) });
      }
    } finally {
      setBusyFile(undefined);
    }
  }

  const download = (entry: FileEntry, opened: OpenedFile) =>
    withFile(entry.view.id, async () => {
      if (isRiskyName(opened.name) && confirmRisky !== entry.view.id) {
        setConfirmRisky(entry.view.id);
        return;
      }
      setConfirmRisky(undefined);
      const { opened: verified, bytes } = await decryptFile(roomId, entry.view.id);
      saveToDevice(verified.name, bytes);
      setMessage({ kind: 'info', text: `${safeDownloadName(verified.name)} was decrypted and saved to your device.` });
    });

  const showPreview = (entry: FileEntry) =>
    withFile(entry.view.id, async () => {
      const { opened, bytes } = await decryptFile(roomId, entry.view.id);
      closePreview();
      const next = { url: previewUrl(opened, bytes), name: opened.name };
      bytes.fill(0);
      previewRef.current = next;
      setPreview(next);
    });

  const remove = (entry: FileEntry) =>
    withFile(entry.view.id, async () => {
      await deleteFile(roomId, entry.view.id);
      if (previewRef.current !== undefined) closePreview();
      setMessage({ kind: 'info', text: 'The file was deleted for every member.' });
      await load();
    });

  async function loadMore(): Promise<void> {
    if (nextCursor === null) return;
    try {
      const page = await listFiles(roomId, nextCursor);
      setEntries((current) => [...current, ...page.entries]);
      setNextCursor(page.nextCursor);
    } catch (error) {
      setMessage({ kind: 'error', text: describeRoomError(error) });
    }
  }

  return (
    <Card title="Files" icon="file" description={FILES_EXPLANATION}>
      {message === undefined ? null : <Alert kind={message.kind}>{message.text}</Alert>}

      {!canUpload ? null : keyState !== 'ACTIVE' ? (
        <p className="text-sm text-slate-400">New files cannot be added until the room key is rotated.</p>
      ) : !unlocked ? (
        <p className="text-sm text-slate-400">
          Files are encrypted on this device before upload.{' '}
          <Link className="text-accent-400 underline" href="/vault">
            Unlock your vault
          </Link>{' '}
          to upload, and to see file names.
        </p>
      ) : (
        <form
          className="flex flex-wrap items-end gap-3 rounded-lg border border-dashed border-slate-700 bg-slate-950/40 p-4"
          onSubmit={(e) => void onUpload(e)}
          noValidate
        >
          <label className="block min-w-0 flex-1 space-y-1.5">
            <span className={labelClass}>File (at most 50 MiB)</span>
            <input
              name="file"
              type="file"
              data-testid="file-input"
              className="block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border file:border-slate-600 file:bg-slate-900 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-slate-100 hover:file:border-slate-400"
            />
          </label>
          <label className="block space-y-1.5">
            <span className={labelClass}>Expires</span>
            <select name="expiry" data-testid="file-expiry" className={`${controlClass} sm:w-auto`}>
              {expiryChoices(policy).map((choice) => (
                <option key={choice.label} value={choice.days === null ? '' : String(choice.days)}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>
          <Button type="submit" disabled={stage !== undefined} data-testid="file-upload">
            <Icon name="upload" className="size-4" />
            Encrypt and upload
          </Button>
        </form>
      )}
      {stage === undefined ? null : (
        <p
          role="status"
          className="flex items-center gap-2 rounded-lg border border-accent-500/30 bg-accent-500/10 px-3 py-2 text-sm text-accent-100"
          data-testid="file-upload-status"
        >
          <span
            className="size-2 animate-pulse rounded-full bg-accent-300 motion-reduce:animate-none"
            aria-hidden="true"
          />
          {STAGE_TEXT[stage.stage]}
          {stage.progress === undefined ? '' : ` ${String(Math.round(stage.progress * 100))}%`}
        </p>
      )}

      {viewerRestricted ? (
        <p className="text-sm text-slate-400">
          In restricted rooms, viewers see that files exist but cannot open or download them.
        </p>
      ) : null}

      {entries.length === 0 ? (
        <EmptyState icon="file" title="No files yet." testId="files-empty">
          Files are encrypted on the uploader&apos;s device and stored as ciphertext.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800" aria-label="Files">
          {entries.map((entry) => {
            const { view, opened } = entry;
            const label =
              opened !== undefined
                ? opened.name
                : entry.damaged === true
                  ? 'Damaged file (integrity check failed)'
                  : 'Encrypted file';
            const size = opened?.size ?? view.ciphertextSize - FILE_TAG_BYTES;
            const busy = busyFile === view.id;
            return (
              <li key={view.id} className="space-y-2 px-4 py-3" data-testid="file-row">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <span className="flex min-w-0 items-start gap-3">
                    <span
                      className={`mt-0.5 grid size-9 shrink-0 place-items-center rounded-lg ${
                        entry.damaged === true ? 'bg-rose-500/15 text-rose-300' : 'bg-slate-800/80 text-accent-300'
                      }`}
                      aria-hidden="true"
                    >
                      <Icon
                        name={entry.damaged === true ? 'alert' : opened === undefined ? 'lock' : 'file'}
                        className="size-4"
                      />
                    </span>
                    <span className="min-w-0 space-y-1">
                      <span className="block break-all font-medium text-white" data-testid="file-name">
                        {label}
                      </span>
                      <span className="block text-xs text-slate-400">
                        {formatBytes(size)} · {nameOfUploader(view.uploaderId)} · {formatDate(view.uploadedAt)}
                        {view.expiresAt === null ? '' : ` · expires ${formatDate(view.expiresAt)}`}
                        {view.keyVersion > 1 ? ` · key version ${String(view.keyVersion)}` : ''}
                      </span>
                    </span>
                  </span>
                  <span className="flex flex-wrap items-center gap-2">
                    {opened !== undefined && view.keyMaterial !== null ? (
                      <>
                        <SecondaryButton type="button" disabled={busy} onClick={() => void download(entry, opened)}>
                          {confirmRisky === view.id ? 'Download anyway' : 'Download'}
                        </SecondaryButton>
                        {isPreviewable(opened) ? (
                          <SecondaryButton type="button" disabled={busy} onClick={() => void showPreview(entry)}>
                            Preview
                          </SecondaryButton>
                        ) : null}
                      </>
                    ) : null}
                    {mayDelete(view.uploaderId) ? (
                      <SecondaryButton type="button" disabled={busy} onClick={() => void remove(entry)}>
                        Delete
                      </SecondaryButton>
                    ) : null}
                  </span>
                </div>
                <FileReceipt entry={entry} />
                {confirmRisky === view.id ? (
                  <Alert kind="error">
                    Files of this type can run code or show active content when you open them. Download only if you
                    trust the person who uploaded it.
                  </Alert>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {nextCursor === null ? null : (
        <SecondaryButton type="button" onClick={() => void loadMore()}>
          Show more files
        </SecondaryButton>
      )}
      {preview === undefined ? null : (
        <figure className="space-y-2" data-testid="file-preview">
          {/* A blob: URL of decrypted bytes of an allowlisted raster type; never HTML or SVG. */}
          <img
            src={preview.url}
            alt={`Preview of ${preview.name}`}
            className="max-h-96 rounded-lg border border-slate-800"
          />
          <figcaption className="flex items-center gap-3 text-xs text-slate-400">
            <span className="break-all">{preview.name}</span>
            <SecondaryButton type="button" onClick={closePreview}>
              Close preview
            </SecondaryButton>
          </figcaption>
        </figure>
      )}
    </Card>
  );
}
