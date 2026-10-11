'use client';

import type { OpenedFile } from '@ciphermesh/crypto';
import { FILE_RULES, FILE_TAG_BYTES, roomRuleFor, type RoomRole, type SecurityProfile } from '@ciphermesh/shared';
import type { RoomMember } from '@ciphermesh/validation';
import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type SyntheticEvent } from 'react';
import { Alert, Button, Card, SecondaryButton } from '../components/ui';
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
function expiryChoices(profile: SecurityProfile): { readonly label: string; readonly days: number | null }[] {
  const rules = FILE_RULES[profile];
  const days = [1, 7, 30, 90].filter((d) => rules.maxExpiryMs === null || d * DAY <= rules.maxExpiryMs);
  const choices: { label: string; days: number | null }[] = days.map((d) => ({
    label: d === 1 ? '1 day' : `${String(d)} days`,
    days: d,
  }));
  if (!rules.expiryRequired) choices.unshift({ label: 'No expiry', days: null });
  const preferred = rules.defaultExpiryMs === null ? null : rules.defaultExpiryMs / DAY;
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
  const viewerRestricted = role === 'VIEWER' && !FILE_RULES[profile].viewerMayDownload;
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
      setMessage({ kind: 'error', text: describeRoomError(error) });
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
    <Card title="Files">
      <p className="text-xs text-slate-500">{FILES_EXPLANATION}</p>
      {message === undefined ? null : <Alert kind={message.kind}>{message.text}</Alert>}

      {!canUpload ? null : keyState !== 'ACTIVE' ? (
        <p className="text-sm text-slate-400">New files cannot be added until the room key is rotated.</p>
      ) : !unlocked ? (
        <p className="text-sm text-slate-400">
          Files are encrypted on this device before upload.{' '}
          <Link className="text-sky-400 underline" href="/vault">
            Unlock your vault
          </Link>{' '}
          to upload, and to see file names.
        </p>
      ) : (
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => void onUpload(e)} noValidate>
          <label className="block space-y-1">
            <span className="text-sm text-slate-300">File (at most 50 MiB)</span>
            <input
              name="file"
              type="file"
              data-testid="file-input"
              className="block text-sm text-slate-300 file:mr-3 file:rounded file:border file:border-slate-600 file:bg-slate-900 file:px-3 file:py-1 file:text-slate-200"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-sm text-slate-300">Expires</span>
            <select
              name="expiry"
              data-testid="file-expiry"
              className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            >
              {expiryChoices(profile).map((choice) => (
                <option key={choice.label} value={choice.days === null ? '' : String(choice.days)}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>
          <Button type="submit" disabled={stage !== undefined} data-testid="file-upload">
            Encrypt and upload
          </Button>
        </form>
      )}
      {stage === undefined ? null : (
        <p role="status" className="text-sm text-sky-200" data-testid="file-upload-status">
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
        <p className="text-sm text-slate-400" data-testid="files-empty">
          No files yet.
        </p>
      ) : (
        <ul className="divide-y divide-slate-800 rounded border border-slate-800" aria-label="Files">
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
                  <span className="min-w-0 space-y-1">
                    <span className="block break-all font-medium" data-testid="file-name">
                      {label}
                    </span>
                    <span className="block text-xs text-slate-400">
                      {formatBytes(size)} · {nameOfUploader(view.uploaderId)} · {formatDate(view.uploadedAt)}
                      {view.expiresAt === null ? '' : ` · expires ${formatDate(view.expiresAt)}`}
                      {view.keyVersion > 1 ? ` · key version ${String(view.keyVersion)}` : ''}
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
            className="max-h-96 rounded border border-slate-800"
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
