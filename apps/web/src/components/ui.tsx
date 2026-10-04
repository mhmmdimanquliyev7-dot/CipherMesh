import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

/** Small presentational building blocks. Text only: no HTML rendering of server data. */

export function Field({
  label,
  hint,
  ...input
}: InputHTMLAttributes<HTMLInputElement> & { readonly label: string; readonly hint?: string }) {
  return (
    <label className="block space-y-1">
      <span className="text-sm text-slate-300">{label}</span>
      <input
        {...input}
        className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 focus:border-sky-500 focus:outline-none"
      />
      {hint === undefined ? null : <span className="block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function Button({
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { readonly children: ReactNode }) {
  return (
    <button
      {...props}
      className="rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
    >
      {children}
    </button>
  );
}

export function SecondaryButton({
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { readonly children: ReactNode }) {
  return (
    <button
      {...props}
      className="rounded border border-slate-600 px-4 py-2 text-sm text-slate-200 hover:border-slate-400 disabled:opacity-50"
    >
      {children}
    </button>
  );
}

export function Alert({ kind, children }: { readonly kind: 'error' | 'info'; readonly children: ReactNode }) {
  const style = kind === 'error' ? 'border-red-500/50 text-red-200' : 'border-sky-500/40 text-sky-200';
  return (
    <p role={kind === 'error' ? 'alert' : 'status'} className={`rounded border px-3 py-2 text-sm ${style}`}>
      {children}
    </p>
  );
}

export function Card({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <section className="space-y-4 rounded-lg border border-slate-800 p-5">
      <h2 className="text-lg font-semibold">{title}</h2>
      {children}
    </section>
  );
}
