'use client';

import { PRODUCT_NAME } from '@ciphermesh/shared';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { publicEnv } from '../config/public-env';
import { vaultController } from '../vault/controller';
import { useVault } from '../vault/use-vault';
import { BrandMark, Icon, type IconName } from './icons';
import { buttonClass } from './ui';
import { VaultIndicator } from './vault-indicator';

/**
 * The application frame (Phase 14 + Prompt 16.5, CM-T061): one navigation landmark that is a
 * sidebar on wide screens and a toggled panel on narrow ones. There is exactly one copy of each
 * link in the document, so assistive technology and the browser tests see one "Rooms", one
 * "Vault" and so on. Navigation is UX only: every page and API request is authorized by the API.
 */

interface NavItem {
  readonly href: string;
  readonly label: string;
  readonly icon: IconName;
}

const NAVIGATION: readonly { readonly group: string; readonly items: readonly NavItem[] }[] = [
  {
    group: 'Workspace',
    items: [
      { href: '/overview', label: 'Overview', icon: 'overview' },
      { href: '/rooms', label: 'Rooms', icon: 'rooms' },
      { href: '/invitations', label: 'Invitations', icon: 'invitations' },
    ],
  },
  {
    group: 'Security',
    items: [
      { href: '/vault', label: 'Vault', icon: 'vault' },
      { href: '/trust', label: 'Trust Center', icon: 'trust' },
    ],
  },
  { group: 'Settings', items: [{ href: '/account', label: 'Account', icon: 'account' }] },
];

/** Pages that are reached before signing in use the lighter public frame. */
const PUBLIC_PAGES = new Set(['/', '/login', '/register']);

const ENVIRONMENT_LABEL = {
  development: 'Development build',
  'local-docker': 'Local Docker demonstration',
  'cloud-demonstration': 'Cloud demonstration',
} as const;

const isActive = (pathname: string, href: string): boolean => pathname === href || pathname.startsWith(`${href}/`);

export function AppShell({ children }: { readonly children: ReactNode }) {
  const pathname = usePathname();
  if (PUBLIC_PAGES.has(pathname)) return <PublicFrame>{children}</PublicFrame>;
  return <WorkspaceFrame pathname={pathname}>{children}</WorkspaceFrame>;
}

function SkipLink() {
  return (
    <a
      href="#content"
      className="sr-only rounded-md bg-accent-400 px-3 py-2 text-sm font-medium text-accent-950 focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50"
    >
      Skip to content
    </a>
  );
}

function EnvironmentBadge() {
  return (
    <span
      className="hidden items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-200 sm:inline-flex"
      title="Build-time label. Synthetic data only: do not store real data."
      data-testid="environment-badge"
    >
      <span className="size-1.5 rounded-full bg-amber-300" aria-hidden="true" />
      {ENVIRONMENT_LABEL[publicEnv.deploymentEnvironment]}
    </span>
  );
}

/**
 * Sign out from any page. The vault is locked before the session ends (session-and-csrf.md
 * section 5); the controller does both. Shown only while the vault controller knows a session.
 */
function SignOut() {
  const router = useRouter();
  const view = useVault();
  const [busy, setBusy] = useState(false);
  if (view.kind === 'loading' || view.kind === 'signed-out') return null;
  return (
    <button
      type="button"
      disabled={busy}
      className="whitespace-nowrap rounded-lg border border-slate-700 bg-slate-900/70 px-2.5 py-1 text-xs font-medium text-slate-200 hover:border-slate-500 disabled:opacity-50"
      onClick={() => {
        setBusy(true);
        // The vault is locked even when the request fails; sign-in is the next page either way.
        void vaultController
          .logout()
          .catch(() => undefined)
          .then(() => {
            setBusy(false);
            router.replace('/login');
          });
      }}
    >
      Sign out
    </button>
  );
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2.5 rounded-md text-white" aria-label={`${PRODUCT_NAME} home`}>
      <BrandMark className="size-8" />
      <span className="text-[15px] font-semibold tracking-tight">{PRODUCT_NAME}</span>
    </Link>
  );
}

function Footer() {
  return (
    <footer className="mx-auto w-full max-w-7xl px-4 pb-8 pt-10 text-xs text-slate-500 sm:px-6 lg:px-10">
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80 pt-5">
        <p>University security project. Development build: do not store real data. Synthetic accounts only.</p>
        <p className="flex gap-4">
          <Link className="hover:text-slate-300" href="/trust">
            Security &amp; Trust
          </Link>
          <Link className="hover:text-slate-300" href="/trust/walkthrough">
            Guided walkthrough
          </Link>
        </p>
      </div>
    </footer>
  );
}

function PublicFrame({ children }: { readonly children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <SkipLink />
      <header className="sticky top-0 z-30 border-b border-slate-800/70 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-10">
          <Brand />
          <nav aria-label="Public" className="flex items-center gap-1 text-sm sm:gap-2">
            <Link className={`${buttonClass.ghost} hidden sm:inline-flex`} href="/trust">
              Trust Center
            </Link>
            <Link className={buttonClass.ghost} href="/login">
              Sign in
            </Link>
            <Link className={`${buttonClass.primary} hidden sm:inline-flex`} href="/register">
              Get started
            </Link>
          </nav>
        </div>
      </header>
      <main id="content" className="mx-auto w-full max-w-7xl flex-1 px-4 py-10 sm:px-6 lg:px-10">
        {children}
      </main>
      <Footer />
    </div>
  );
}

function WorkspaceFrame({ pathname, children }: { readonly pathname: string; readonly children: ReactNode }) {
  const [open, setOpen] = useState(false);

  // Close the narrow-screen menu on navigation and on Escape.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[16rem_1fr]">
      <SkipLink />
      <aside className="lg:sticky lg:top-0 lg:h-screen lg:border-r lg:border-slate-800/80 lg:bg-slate-950/70">
        <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 px-4 py-3 lg:border-b-0 lg:px-5 lg:py-5">
          <Brand />
          <button
            type="button"
            className={`${buttonClass.ghost} px-2.5 lg:hidden`}
            aria-expanded={open}
            aria-controls="primary-navigation"
            onClick={() => {
              setOpen(!open);
            }}
          >
            <Icon name={open ? 'x' : 'menu'} />
            <span className="sr-only">{open ? 'Close menu' : 'Open menu'}</span>
          </button>
        </div>
        <nav
          id="primary-navigation"
          aria-label="Primary"
          className={`${open ? 'flex' : 'hidden'} flex-col gap-6 border-b border-slate-800/80 px-3 pb-5 pt-3 lg:flex lg:border-b-0 lg:pt-1`}
        >
          {NAVIGATION.map((section) => (
            <div key={section.group} className="space-y-1">
              <p className="px-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                {section.group}
              </p>
              <ul className="space-y-0.5">
                {section.items.map((item) => {
                  const active = isActive(pathname, item.href);
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        aria-current={active ? 'page' : undefined}
                        className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                          active
                            ? 'bg-accent-400/10 text-white ring-1 ring-inset ring-accent-400/30'
                            : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                        }`}
                      >
                        <Icon
                          name={item.icon}
                          className={`size-[18px] ${active ? 'text-accent-300' : 'text-slate-400'}`}
                        />
                        {item.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          <div className="mx-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs leading-relaxed text-slate-400">
            <p className="flex items-center gap-1.5 font-medium text-slate-200">
              <Icon name="lock" className="size-3.5 text-accent-300" />
              Client-side encrypted
            </p>
            <p className="mt-1">Room content is encrypted in this browser before upload.</p>
          </div>
        </nav>
      </aside>
      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-20 border-b border-slate-800/70 bg-slate-950/75 backdrop-blur">
          <div className="mx-auto flex w-full max-w-7xl items-center justify-end gap-3 px-4 py-2.5 sm:px-6 lg:px-10">
            <EnvironmentBadge />
            <VaultIndicator />
            <SignOut />
          </div>
        </header>
        <main id="content" className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6 lg:px-10 lg:py-10">
          {children}
        </main>
        <Footer />
      </div>
    </div>
  );
}
