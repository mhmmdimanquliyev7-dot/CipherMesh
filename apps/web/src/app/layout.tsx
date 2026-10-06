import { PRODUCT_NAME, PRODUCT_TAGLINE } from '@ciphermesh/shared';
import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { VaultIndicator } from '../components/vault-indicator';
import { VaultLifecycle } from '../vault/use-vault';
import './globals.css';

export const metadata: Metadata = {
  title: { default: PRODUCT_NAME, template: `%s · ${PRODUCT_NAME}` },
  description: PRODUCT_TAGLINE,
  // The shell must not be indexed while it is a development build.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        <header className="border-b border-slate-800">
          <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-4">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              {PRODUCT_NAME}
            </Link>
            <nav className="flex items-center gap-4 text-sm">
              <VaultIndicator />
              <Link href="/rooms" className="text-slate-300 hover:text-white">
                Rooms
              </Link>
              <Link href="/vault" className="text-slate-300 hover:text-white">
                Vault
              </Link>
              <Link href="/account" className="text-slate-300 hover:text-white">
                Account
              </Link>
              <span className="rounded border border-amber-500/40 px-2 py-0.5 text-xs text-amber-300">
                Development build
              </span>
            </nav>
          </div>
        </header>
        <VaultLifecycle />
        <main className="mx-auto max-w-5xl px-4 py-10">{children}</main>
        <footer className="mx-auto max-w-5xl px-4 pb-10 text-xs text-slate-500">
          University security project. Development build: do not store real data.
        </footer>
      </body>
    </html>
  );
}
