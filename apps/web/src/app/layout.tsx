import { PRODUCT_NAME, PRODUCT_TAGLINE } from '@ciphermesh/shared';
import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { AppShell } from '../components/app-shell';
import { VaultLifecycle } from '../vault/use-vault';
import './globals.css';

export const metadata: Metadata = {
  title: { default: PRODUCT_NAME, template: `%s · ${PRODUCT_NAME}` },
  description: PRODUCT_TAGLINE,
  // The shell must not be indexed while it is a development build.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: '#0a0f1c',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen text-slate-100 antialiased">
        <VaultLifecycle />
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
