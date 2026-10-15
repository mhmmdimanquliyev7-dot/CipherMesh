'use client';

import { createContext, useContext } from 'react';
import type { IsmsState, Write } from './client';

/** The code of the written record and of any findings created with it. */
export interface WriteOutcome {
  readonly code: string;
  readonly created: readonly string[];
}

/** What every section of the ISMS Control Center may use: the loaded state, writes and navigation. */
export interface IsmsContextValue {
  readonly state: IsmsState;
  /** Sends a creation or transition; asks for a step-up when the server requires it; reloads after. */
  readonly run: (write: Write) => Promise<WriteOutcome>;
  /** Opens a section, optionally on one item (a risk, control, policy or record code). */
  readonly go: (section: SectionId, item?: string) => void;
  readonly item: string | undefined;
}

export const SECTIONS = [
  { id: 'overview', label: 'Overview' },
  { id: 'context', label: 'Scope & context' },
  { id: 'assets', label: 'Assets' },
  { id: 'risks', label: 'Risk register' },
  { id: 'treatment', label: 'Treatment plan' },
  { id: 'soa', label: 'Statement of Applicability' },
  { id: 'policies', label: 'Policies & roles' },
  { id: 'assurance', label: 'Control assurance' },
  { id: 'audits', label: 'Audits & findings' },
  { id: 'actions', label: 'Corrective actions' },
  { id: 'review', label: 'Management review' },
  { id: 'improvement', label: 'Improvement & activity' },
] as const;

export type SectionId = (typeof SECTIONS)[number]['id'];

export const IsmsContext = createContext<IsmsContextValue | undefined>(undefined);

export function useIsms(): IsmsContextValue {
  const value = useContext(IsmsContext);
  if (value === undefined) throw new Error('useIsms outside the ISMS Control Center');
  return value;
}
