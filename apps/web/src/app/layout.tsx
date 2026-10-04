import { PRODUCT_NAME, PRODUCT_TAGLINE } from '@ciphermesh/shared';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
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
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-4">
            <span className="text-lg font-semibold tracking-tight">{PRODUCT_NAME}</span>
            <span className="rounded border border-amber-500/40 px-2 py-0.5 text-xs text-amber-300">
              Foundation build
            </span>
          </div>
        </header>
        <main className="mx-auto max-w-5xl px-4 py-10">{children}</main>
        <footer className="mx-auto max-w-5xl px-4 pb-10 text-xs text-slate-500">
          University security project. Development build: do not store real data.
        </footer>
      </body>
    </html>
  );
}
