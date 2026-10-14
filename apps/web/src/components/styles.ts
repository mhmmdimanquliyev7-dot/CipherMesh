/**
 * Class names shared by server and client components (design system, Phase 14 + Prompt 16.5).
 * Plain constants in a module without 'use client', so server components receive the strings.
 */

/** Shared look of text inputs, selects and text areas. */
export const controlClass =
  'w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 shadow-inner shadow-black/20 transition-colors hover:border-slate-600 focus:border-accent-400 focus:outline-none focus:ring-2 focus:ring-accent-400/25 disabled:opacity-60';

export const labelClass = 'text-sm font-medium text-slate-200';

const BUTTON_BASE =
  'inline-flex min-h-9 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50';

/** Class names for links that look like buttons (navigation, never form submission). */
export const buttonClass = {
  primary: `${BUTTON_BASE} bg-accent-400 text-accent-950 shadow-sm shadow-accent-500/20 hover:bg-accent-300`,
  secondary: `${BUTTON_BASE} border border-slate-700 bg-slate-900/60 text-slate-100 hover:border-slate-500 hover:bg-slate-800/80`,
  danger: `${BUTTON_BASE} bg-rose-500 text-white hover:bg-rose-400`,
  ghost: `${BUTTON_BASE} text-slate-300 hover:bg-slate-800/70 hover:text-white`,
} as const;
