import cloudFile from './generated/cloud.json';
import evidenceFile from './generated/evidence.json';
import ismsFile from './generated/isms.json';
import limitationsFile from './generated/limitations.json';
import parametersFile from './generated/parameters.json';
import risksFile from './generated/risks.json';

/**
 * Typed access to the Trust Center data generated from the normative documents
 * (apps/web/scripts/generate-trust-data.mjs). Every value shown in the Trust Center is either read
 * from here, or curated in cryptography.ts and infrastructure.ts with a source reference that a
 * unit test resolves. Nothing is fetched at runtime and nothing here is secret: the documents are
 * public in the repository.
 */

export type EvidenceStatus = 'captured' | 'partial' | 'pending' | 'deferred' | 'planned';
export type SubjectTag = 'CRY' | 'CLD' | 'ISMS' | 'APP';

export interface EvidenceItem {
  readonly id: string;
  readonly phase: number;
  readonly evidence: string;
  readonly how: string;
  readonly demonstrates: string;
  readonly tags: readonly string[];
  readonly status: EvidenceStatus;
  readonly files: readonly { readonly label: string; readonly path: string }[];
  readonly locations: readonly string[];
  readonly captions: readonly string[];
  readonly date: string;
}

export interface Risk {
  readonly id: string;
  readonly threat: string;
  readonly title: string;
  readonly likelihood: string;
  readonly impact: string;
  readonly inherent: string;
  readonly treatment: string;
  readonly residual: string;
  readonly limitations: readonly string[];
  readonly fields: readonly { readonly label: string; readonly text: string; readonly items: readonly string[] }[];
}

export interface Control {
  readonly control: string;
  readonly title: string;
  readonly theme: string;
  readonly status: string;
  readonly implementation: string;
  readonly evidenceText: string;
  readonly evidence: readonly string[];
}

export interface Limitation {
  readonly id: string;
  readonly limitation: string;
  readonly why: string;
  readonly response: string;
  readonly demonstration: string;
}

export interface Parameter {
  readonly id: string;
  readonly name: string;
  readonly value: string;
  readonly notes: string;
}

export const REPOSITORY_URL: string = evidenceFile.repository;

export const evidence = evidenceFile.evidence as readonly EvidenceItem[];
export const risks = risksFile.risks as readonly Risk[];
export const limitations = limitationsFile.limitations as readonly Limitation[];
export const parameters = parametersFile.parameters as readonly Parameter[];
export const isms = {
  scope: ismsFile.scope,
  statusLegend: ismsFile.statusLegend,
  clauses: ismsFile.clauses as readonly { clause: string; requirement: string; implementation: string }[],
  controls: ismsFile.controls as readonly Control[],
};
export const cloud = {
  services: cloudFile.services as readonly string[],
  layers: cloudFile.layers as readonly { layer: string; owners: readonly string[] }[],
  exposure: cloudFile.exposure as readonly { endpoint: string; exposedTo: string; port: string; notes: string }[],
};

const evidenceById = new Map(evidence.map((item) => [item.id, item]));
const limitationById = new Map(limitations.map((item) => [item.id, item]));
const parameterById = new Map(parameters.map((item) => [item.id, item]));

export const evidenceItem = (id: string): EvidenceItem | undefined => evidenceById.get(id);
export const limitation = (id: string): Limitation | undefined => limitationById.get(id);
export const parameter = (id: string): Parameter | undefined => parameterById.get(id);

/** A repository document on GitHub (main branch). Paths are repository-relative. */
export const documentUrl = (path: string): string => `${REPOSITORY_URL}/blob/main/${path}`;

export const EVIDENCE_STATUS_LABEL: Readonly<Record<EvidenceStatus, string>> = {
  captured: 'Captured',
  partial: 'Partly captured',
  pending: 'Missing',
  deferred: 'Deferred',
  planned: 'Later workstream',
};

export const EVIDENCE_STATUS_TONE = {
  captured: 'success',
  partial: 'warning',
  pending: 'danger',
  deferred: 'neutral',
  planned: 'info',
} as const satisfies Record<EvidenceStatus, string>;

export const SUBJECT_LABEL: Readonly<Record<SubjectTag, string>> = {
  CRY: 'Cryptography',
  CLD: 'Cloud security',
  ISMS: 'ISMS',
  APP: 'Application security',
};

/** Counts of evidence statuses for a set of items. */
export function evidenceSummary(items: readonly EvidenceItem[]): Readonly<Record<EvidenceStatus, number>> {
  const counts: Record<EvidenceStatus, number> = { captured: 0, partial: 0, pending: 0, deferred: 0, planned: 0 };
  for (const item of items) counts[item.status] += 1;
  return counts;
}

export const evidenceFor = (tag: SubjectTag): readonly EvidenceItem[] =>
  evidence.filter((item) => item.tags.includes(tag));
