import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react';
import { Icon, type IconName } from './icons';
import { controlClass, labelClass } from './styles';

export { Button, SecondaryButton } from './buttons';
export { buttonClass, controlClass, labelClass } from './styles';

/**
 * CipherMesh presentational building blocks (design system, Phase 14 + Prompt 16.5). Text only:
 * no HTML rendering of server data, no inline styles (strict CSP). Labels and roles are part of
 * the contract with the browser tests and with assistive technology: change them deliberately.
 */

export function Field({
  label,
  hint,
  ...input
}: InputHTMLAttributes<HTMLInputElement> & { readonly label: string; readonly hint?: string }) {
  return (
    <label className="block space-y-1.5">
      <span className={labelClass}>{label}</span>
      <input {...input} className={controlClass} />
      {hint === undefined ? null : <span className="block text-xs leading-relaxed text-slate-400">{hint}</span>}
    </label>
  );
}

export function SelectField({
  label,
  hint,
  children,
  ...select
}: SelectHTMLAttributes<HTMLSelectElement> & {
  readonly label: string;
  readonly hint?: string;
  readonly children: ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className={labelClass}>{label}</span>
      <select {...select} className={controlClass}>
        {children}
      </select>
      {hint === undefined ? null : <span className="block text-xs leading-relaxed text-slate-400">{hint}</span>}
    </label>
  );
}

type AlertKind = 'error' | 'info' | 'warning' | 'success';

const ALERT_STYLE: Readonly<Record<AlertKind, { readonly box: string; readonly icon: IconName }>> = {
  error: { box: 'border-rose-500/40 bg-rose-500/10 text-rose-100', icon: 'xCircle' },
  warning: { box: 'border-amber-500/40 bg-amber-500/10 text-amber-100', icon: 'alert' },
  info: { box: 'border-sky-500/30 bg-sky-500/10 text-sky-100', icon: 'info' },
  success: { box: 'border-emerald-500/35 bg-emerald-500/10 text-emerald-100', icon: 'checkCircle' },
};

/** A message. Errors are announced at once (role alert); the others politely (role status). */
export function Alert({ kind, children }: { readonly kind: AlertKind; readonly children: ReactNode }) {
  const style = ALERT_STYLE[kind];
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-2.5 text-sm leading-relaxed ${style.box}`}
    >
      <Icon name={style.icon} className="mt-0.5 size-4" />
      <div className="min-w-0">{children}</div>
    </div>
  );
}

export function Card({
  title,
  children,
  description,
  icon,
  actions,
  id,
  tone = 'default',
}: {
  readonly title: string;
  readonly children: ReactNode;
  readonly description?: ReactNode;
  readonly icon?: IconName;
  readonly actions?: ReactNode;
  readonly id?: string;
  readonly tone?: 'default' | 'warning' | 'danger';
}) {
  const border = tone === 'warning' ? 'border-amber-500/30' : tone === 'danger' ? 'border-rose-500/30' : 'border-line';
  return (
    <section
      id={id}
      className={`scroll-mt-24 space-y-4 rounded-xl border ${border} bg-surface/90 p-5 shadow-lg shadow-black/10 sm:p-6`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          {icon === undefined ? null : (
            <span className="mt-0.5 grid size-8 place-items-center rounded-lg border border-slate-700/80 bg-slate-900 text-accent-300">
              <Icon name={icon} className="size-4" />
            </span>
          )}
          <div className="min-w-0 space-y-1">
            <h2 className="text-base font-semibold tracking-tight text-white">{title}</h2>
            {description === undefined ? null : (
              <div className="text-sm leading-relaxed text-slate-400">{description}</div>
            )}
          </div>
        </div>
        {actions === undefined ? null : <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info' | 'violet';

const BADGE_TONE: Readonly<Record<BadgeTone, string>> = {
  neutral: 'border-slate-700 bg-slate-800/70 text-slate-200',
  accent: 'border-accent-500/40 bg-accent-500/10 text-accent-200',
  success: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
  warning: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  danger: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  info: 'border-sky-500/40 bg-sky-500/10 text-sky-200',
  violet: 'border-indigo-400/40 bg-indigo-400/10 text-indigo-200',
};

/** A short label. Its meaning is always in the text; the colour only repeats it. */
export function Badge({
  tone = 'neutral',
  icon,
  children,
  title,
}: {
  readonly tone?: BadgeTone;
  readonly icon?: IconName;
  readonly children: ReactNode;
  readonly title?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 text-left text-xs font-medium leading-tight ${BADGE_TONE[tone]}`}
    >
      {icon === undefined ? null : <Icon name={icon} className="size-3.5" />}
      {children}
    </span>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  children,
}: {
  readonly eyebrow?: string;
  readonly title: ReactNode;
  readonly description?: ReactNode;
  readonly actions?: ReactNode;
  readonly children?: ReactNode;
}) {
  return (
    <header className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0 space-y-2">
          {eyebrow === undefined ? null : (
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-accent-300">{eyebrow}</p>
          )}
          <h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">{title}</h1>
          {description === undefined ? null : (
            <div className="max-w-3xl text-sm leading-relaxed text-slate-400 sm:text-base">{description}</div>
          )}
        </div>
        {actions === undefined ? null : <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  testId,
}: {
  readonly icon: IconName;
  readonly title: string;
  readonly children?: ReactNode;
  readonly testId?: string;
}) {
  return (
    <div
      className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-slate-700 px-6 py-8 text-center"
      data-testid={testId}
    >
      <span className="grid size-10 place-items-center rounded-full bg-slate-800/80 text-slate-400">
        <Icon name={icon} />
      </span>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {children === undefined ? null : <div className="max-w-md text-sm text-slate-400">{children}</div>}
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { readonly label?: string }) {
  return (
    <p className="flex items-center gap-2 text-sm text-slate-400" role="status">
      <span className="size-2 animate-pulse rounded-full bg-accent-400 motion-reduce:animate-none" aria-hidden="true" />
      {label}
    </p>
  );
}

/** A metric with a real source. `value` undefined means "not available", never zero. */
export function Stat({
  label,
  value,
  detail,
  icon,
}: {
  readonly label: string;
  readonly value: ReactNode;
  readonly detail?: ReactNode;
  readonly icon?: IconName;
}) {
  return (
    <div className="space-y-1.5 rounded-xl border border-line bg-surface/90 p-4">
      <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
        {icon === undefined ? null : <Icon name={icon} className="size-4 text-accent-300" />}
        {label}
      </p>
      <p className="tabular text-2xl font-semibold tracking-tight text-white">{value}</p>
      {detail === undefined ? null : <p className="text-xs leading-relaxed text-slate-400">{detail}</p>}
    </div>
  );
}

/** Label and value pairs. */
export function DetailList({
  items,
  testId,
}: {
  readonly items: readonly { readonly term: string; readonly value: ReactNode }[];
  readonly testId?: string;
}) {
  return (
    <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]" data-testid={testId}>
      {items.map((item) => (
        <div key={item.term} className="contents">
          <dt className="text-slate-400">{item.term}</dt>
          <dd className="min-w-0 break-words text-slate-100">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A native disclosure (keyboard and screen-reader support from the browser). */
export function Disclosure({
  summary,
  children,
  testId,
}: {
  readonly summary: ReactNode;
  readonly children: ReactNode;
  readonly testId?: string;
}) {
  return (
    <details className="group rounded-lg border border-slate-800 bg-slate-950/40" data-testid={testId}>
      <summary className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white">
        <Icon name="chevronRight" className="disclosure-chevron size-3.5" />
        {summary}
      </summary>
      <div className="border-t border-slate-800 px-3 py-3">{children}</div>
    </details>
  );
}
