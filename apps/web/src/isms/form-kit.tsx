'use client';

import { useId, useState, type ReactNode, type SyntheticEvent } from 'react';
import { Alert, Button, controlClass, labelClass, SecondaryButton } from '../components/ui';

/**
 * Forms of the ISMS Control Center, described by field specifications, so every workflow form has
 * the same labels, validation messages and accessibility. Values are text: lists are one item per
 * line, and the page turns them into the exact request body the API validates.
 */

export interface FieldSpec {
  readonly name: string;
  readonly label: string;
  readonly kind: 'text' | 'textarea' | 'select' | 'date' | 'lines' | 'checkbox';
  readonly options?: readonly { readonly value: string; readonly label: string }[];
  readonly hint?: string;
  readonly initial?: string | boolean;
  readonly optional?: boolean;
}

export type FormValues = Readonly<Record<string, string | boolean>>;

/** One item per non-empty line. */
export const linesOf = (value: string | boolean | undefined): string[] =>
  typeof value === 'string'
    ? value
        .split(/\r?\n|,/)
        .map((line) => line.trim())
        .filter((line) => line !== '')
    : [];

export const textOf = (value: string | boolean | undefined): string => (typeof value === 'string' ? value.trim() : '');

export function SpecForm({
  fields,
  submitLabel,
  onSubmit,
  onCancel,
  testId,
  intro,
}: {
  readonly fields: readonly FieldSpec[];
  readonly submitLabel: string;
  readonly onSubmit: (values: FormValues) => Promise<void>;
  readonly onCancel?: () => void;
  readonly testId?: string;
  readonly intro?: ReactNode;
}) {
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  async function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const values: Record<string, string | boolean> = {};
    const missing: string[] = [];
    for (const field of fields) {
      if (field.kind === 'checkbox') {
        values[field.name] = form.get(field.name) === 'on';
        continue;
      }
      const raw = form.get(field.name);
      const value = typeof raw === 'string' ? raw.trim() : '';
      values[field.name] = value;
      if (value === '' && field.optional !== true) missing.push(field.label);
    }
    if (missing.length > 0) {
      setError(`Required: ${missing.join(', ')}.`);
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await onSubmit(values);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unexpected error.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="space-y-3 rounded-lg border border-slate-800 bg-slate-950/40 p-4"
      onSubmit={(e) => void submit(e)}
      noValidate
      data-testid={testId}
    >
      {intro === undefined ? null : <div className="text-sm leading-relaxed text-slate-300">{intro}</div>}
      <div className="grid gap-3 md:grid-cols-2">
        {fields.map((field) => (
          <FieldInput key={field.name} field={field} />
        ))}
      </div>
      {error === undefined ? null : <Alert kind="error">{error}</Alert>}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy}>
          {submitLabel}
        </Button>
        {onCancel === undefined ? null : (
          <SecondaryButton type="button" onClick={onCancel}>
            Cancel
          </SecondaryButton>
        )}
      </div>
    </form>
  );
}

function FieldInput({ field }: { readonly field: FieldSpec }) {
  const id = useId();
  const wide = field.kind === 'textarea' || field.kind === 'lines' ? 'md:col-span-2' : '';
  const hint =
    field.hint ?? (field.kind === 'lines' ? 'One item per line.' : field.optional === true ? 'Optional.' : undefined);
  // The label names the control exactly; the hint is its description (aria-describedby), so the
  // accessible name stays the label alone.
  const described = hint === undefined ? {} : { 'aria-describedby': `${id}-hint` };
  const hintText =
    hint === undefined ? null : (
      <span id={`${id}-hint`} className="block text-xs leading-relaxed text-slate-400">
        {hint}
      </span>
    );
  if (field.kind === 'checkbox') {
    return (
      <div className="flex items-start gap-2 text-sm text-slate-200 md:col-span-2">
        <input
          id={id}
          type="checkbox"
          name={field.name}
          defaultChecked={field.initial === true}
          className="mt-1 size-4 rounded border-slate-600 bg-slate-900"
          {...(field.hint === undefined ? {} : described)}
        />
        <span>
          <label htmlFor={id}>{field.label}</label>
          {field.hint === undefined ? null : hintText}
        </span>
      </div>
    );
  }
  const initial = typeof field.initial === 'string' ? field.initial : '';
  return (
    <div className={`space-y-1.5 ${wide}`}>
      <label htmlFor={id} className={`block ${labelClass}`}>
        {field.label}
      </label>
      {field.kind === 'select' ? (
        <select id={id} name={field.name} defaultValue={initial} className={controlClass} {...described}>
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      ) : field.kind === 'textarea' || field.kind === 'lines' ? (
        <textarea id={id} name={field.name} defaultValue={initial} rows={3} className={controlClass} {...described} />
      ) : (
        <input
          id={id}
          name={field.name}
          type={field.kind === 'date' ? 'date' : 'text'}
          defaultValue={initial}
          className={controlClass}
          {...described}
        />
      )}
      {hintText}
    </div>
  );
}

export const LEVEL_OPTIONS = [
  { value: 'Low', label: 'Low' },
  { value: 'Medium', label: 'Medium' },
  { value: 'High', label: 'High' },
] as const;
