'use client';

import { useSyncExternalStore, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { buttonClass } from './styles';

const noSubscription = () => () => undefined;

/**
 * False in the prerendered HTML and during hydration, true once React runs in the browser.
 * Buttons stay disabled until then: before hydration no handler exists, and a native submission
 * of a prerendered form would be a GET that puts the typed values, such as the account password,
 * into the URL (security finding SF-04-01). The CSP's form-action 'none' refuses such a
 * submission as well; this keeps the user from reaching it.
 */
function useHydrated(): boolean {
  return useSyncExternalStore(
    noSubscription,
    () => true,
    () => false,
  );
}

export function Button({
  children,
  disabled,
  tone = 'primary',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  readonly children: ReactNode;
  readonly tone?: 'primary' | 'danger';
}) {
  const hydrated = useHydrated();
  return (
    <button {...props} disabled={disabled === true || !hydrated} className={buttonClass[tone]}>
      {children}
    </button>
  );
}

export function SecondaryButton({
  children,
  disabled,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { readonly children: ReactNode }) {
  const hydrated = useHydrated();
  return (
    <button {...props} disabled={disabled === true || !hydrated} className={buttonClass.secondary}>
      {children}
    </button>
  );
}
