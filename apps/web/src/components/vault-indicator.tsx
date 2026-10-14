'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { vaultController } from '../vault/controller';
import { useVault } from '../vault/use-vault';
import { Icon } from './icons';

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
  const unlocked = view.kind === 'unlocked';
  return (
    <div className="flex items-center gap-2 text-xs" data-testid="vault-indicator">
      <Link
        href="/vault"
        className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-medium transition-colors ${
          unlocked
            ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100 hover:border-emerald-400/60'
            : 'border-slate-700 bg-slate-900/70 text-slate-200 hover:border-slate-500'
        }`}
      >
        <Icon name={unlocked ? 'unlock' : 'lock'} className="size-3.5" />
        <span className="tabular">
          {unlocked
            ? `Vault unlocked · locks in ${String(minutes)}:${String(seconds).padStart(2, '0')}`
            : 'Vault locked'}
        </span>
      </Link>
      {unlocked ? (
        <button
          type="button"
          className="whitespace-nowrap rounded-lg border border-slate-700 bg-slate-900/70 px-2.5 py-1 font-medium text-slate-200 hover:border-slate-500"
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
