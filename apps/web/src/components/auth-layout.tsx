import type { ReactNode } from 'react';
import { Icon, type IconName } from './icons';

/** The frame of the sign-in and registration pages: the form, and what protects the account. */

const POINTS: readonly { readonly icon: IconName; readonly title: string; readonly text: string }[] = [
  {
    icon: 'account',
    title: 'Account password',
    text: 'Proves who you are to the server, which stores only an Argon2id hash of it.',
  },
  {
    icon: 'vault',
    title: 'Vault Passphrase',
    text: 'A second, separate secret that unlocks your keys in this browser. It is never sent to the server.',
  },
  {
    icon: 'fingerprint',
    title: 'Two-step sign-in',
    text: 'An authenticator app adds a second factor. Confidential and restricted rooms require it.',
  },
];

export function AuthLayout({
  title,
  description,
  children,
  footer,
}: {
  readonly title: string;
  readonly description: string;
  readonly children: ReactNode;
  readonly footer: ReactNode;
}) {
  return (
    <div className="mx-auto grid max-w-5xl items-start gap-10 lg:grid-cols-[1fr_1.05fr] lg:gap-16 lg:pt-6">
      <div className="order-2 space-y-6 lg:order-1 lg:pt-10">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-accent-300">
          How your account is protected
        </p>
        <ul className="space-y-5">
          {POINTS.map((point) => (
            <li key={point.title} className="flex gap-4">
              <span className="grid size-10 shrink-0 place-items-center rounded-lg border border-slate-800 bg-surface text-accent-300">
                <Icon name={point.icon} />
              </span>
              <div className="space-y-1">
                <p className="font-medium text-white">{point.title}</p>
                <p className="text-sm leading-relaxed text-slate-400">{point.text}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>
      <div className="order-1 space-y-6 rounded-2xl border border-line bg-surface/90 p-6 shadow-2xl shadow-black/30 sm:p-8 lg:order-2">
        <div className="space-y-1.5">
          <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
          <p className="text-sm text-slate-400">{description}</p>
        </div>
        {children}
        <div className="border-t border-slate-800 pt-4 text-sm text-slate-400">{footer}</div>
      </div>
    </div>
  );
}
