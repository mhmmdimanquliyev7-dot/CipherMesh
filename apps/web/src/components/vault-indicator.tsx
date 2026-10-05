'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { vaultController } from '../vault/controller';
import { useVault } from '../vault/use-vault';

/**
 * Vault status in the global header (security-ui.md section 2.1): locked or unlocked, the time
 * left before the inactivity lock, and "Lock now". It reflects the controller's real state.
 */
export function VaultIndicator() {
  const view = useVault();
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    if (view.kind !== 'unlocked') return;
    const tick = (): void => {
      setRemaining(vaultController.millisecondsUntilAutoLock());
    };
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [view.kind]);

  if (view.kind !== 'locked' && view.kind !== 'unlocked') return null;
  const minutes = Math.floor(remaining / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1000);
  return (
    <div className="flex items-center gap-3 text-xs" data-testid="vault-indicator">
      <Link href="/vault" className="rounded border border-slate-700 px-2 py-0.5 text-slate-200 hover:border-slate-500">
        {view.kind === 'unlocked'
          ? `Vault unlocked · locks in ${String(minutes)}:${String(seconds).padStart(2, '0')}`
          : 'Vault locked'}
      </Link>
      {view.kind === 'unlocked' ? (
        <button
          type="button"
          className="rounded border border-slate-600 px-2 py-0.5 text-slate-200 hover:border-slate-400"
          onClick={() => {
            vaultController.lock('manual');
          }}
        >
          Lock now
        </button>
      ) : null}
    </div>
  );
}
