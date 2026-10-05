'use client';

import { usePathname } from 'next/navigation';
import { useEffect, useSyncExternalStore } from 'react';
import { vaultController, type VaultView } from './controller';

/**
 * The vault state of this tab for React components. Components see only the view (status,
 * public identity, account); the private keys stay inside the controller.
 */
export function useVault(): VaultView {
  return useSyncExternalStore(
    vaultController.subscribe,
    vaultController.getSnapshot,
    vaultController.getServerSnapshot,
  );
}

/**
 * Starts auto-lock once per page and reloads the account and vault state on every route change,
 * so signing in, signing out or a reset elsewhere is reflected without a full page load. A refresh
 * never unlocks anything; it can only lock (identity changed, session gone). Mounted by the root
 * layout.
 */
export function VaultLifecycle(): null {
  const pathname = usePathname();
  useEffect(() => {
    vaultController.start();
  }, []);
  useEffect(() => {
    void vaultController.refresh();
  }, [pathname]);
  return null;
}
