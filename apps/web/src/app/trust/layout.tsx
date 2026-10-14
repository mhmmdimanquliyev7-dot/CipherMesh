import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { TrustNav } from '../../trust/ui';

export const metadata: Metadata = { title: 'Security & Trust Center' };

/**
 * The Security & Trust Center (Phase 14 + Prompt 16.5, CM-T061). Its pages are static and public:
 * they show the project's public documents and evidence, compiled at build time, and never user
 * data. The platform security dashboard is the only part that calls the API, and the API
 * restricts it to platform administrators (PA-01).
 */
export default function TrustLayout({ children }: { readonly children: ReactNode }) {
  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-accent-300">Security &amp; Trust Center</p>
        <TrustNav />
      </div>
      {children}
    </div>
  );
}
