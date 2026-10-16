// Trust Center data (Phase 14 + Prompt 16.5, CM-T061). The Trust Center shows the project's own
// normative documents, never a second copy typed by hand: this module parses the Markdown sources
// (threat model, limitations, ISMS control mapping, evidence plan and index, parameter register)
// into plain JSON. `generate-trust-data.mjs` writes the result into the web client and, with
// --check, fails the build when the committed JSON no longer matches the documents, so a page can
// never show a risk, control or evidence status that the documents do not state.
//
// Pure functions only, so they can be unit tested. Text is reduced to plain text (no Markdown, no
// HTML): the client renders every value as text.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';

/** Repository on GitHub; evidence and document links point to the reviewed `main` branch. */
export const REPOSITORY_URL = 'https://github.com/mhmmdimanquliyev7-dot/CipherMesh';

/** Phases the project owner deferred on 2026-10-13 (Phase 14 + Prompt 16.5 approval). */
export const DEFERRED_PHASES = Object.freeze([12, 13, 15, 16]);

/** Phases that belong to the later workstreams (cloud deployment, hardening, assessment, report). */
export const LATER_PHASES = Object.freeze([17, 18, 19, 20, 21, 22]);

/**
 * Markdown inline syntax to plain text: links keep their text, emphasis and code marks go.
 * @param {string} text
 * @returns {string}
 */
export function plain(text) {
  return text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1$2')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * The cells of a Markdown table row. Escaped pipes are not used in the sources.
 * @param {string} line
 * @returns {string[]}
 */
export function cells(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith('|')) return [];
  return trimmed
    .slice(1, trimmed.endsWith('|') ? -1 : undefined)
    .split('|')
    .map((cell) => cell.trim());
}

/**
 * The lines of one `## ` section whose heading starts with `prefix`, up to the next `## `.
 * @param {string} markdown
 * @param {string} prefix
 * @returns {string[]}
 */
export function section(markdown, prefix) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => line.startsWith(`## ${prefix}`));
  if (start === -1) throw new Error(`Section "## ${prefix}" not found`);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return end === -1 ? rest : rest.slice(0, end);
}

/**
 * Data rows of every table in `lines` whose first cell matches `idPattern`.
 * @param {string[]} lines
 * @param {RegExp} idPattern
 * @returns {string[][]}
 */
export function tableRows(lines, idPattern) {
  return lines.map(cells).filter((row) => row.length > 0 && idPattern.test(row[0] ?? ''));
}

/**
 * Every evidence ID named in a text, with ranges such as "EV-03-03 to EV-03-09" expanded.
 * @param {string} text
 * @returns {string[]}
 */
export function evidenceIds(text) {
  const ids = new Set();
  const rangePattern = /EV-(\d{2})-(\d{2})\s+to\s+EV-(\d{2})-(\d{2})/g;
  for (const match of text.matchAll(rangePattern)) {
    const [, phaseA, fromRaw, phaseB, toRaw] = match;
    if (phaseA !== phaseB) continue;
    for (let n = Number(fromRaw); n <= Number(toRaw); n += 1) ids.add(`EV-${phaseA}-${String(n).padStart(2, '0')}`);
  }
  for (const match of text.matchAll(/EV-\d{2}-\d{2}/g)) ids.add(match[0]);
  return [...ids].sort();
}

/**
 * Risk register: the summary table of section 5 joined with the threat descriptions of section 4.
 * @param {string} markdown docs/threat-model/threat-model.md
 */
export function parseRisks(markdown) {
  /** @typedef {{ id: string, title: string, fields: { label: string, text: string, items: string[] }[] }} RiskDetail */
  /** @type {Map<string, RiskDetail>} */
  const details = new Map();
  /** @type {RiskDetail | undefined} */
  let current;
  for (const line of section(markdown, '4.')) {
    const heading = /^### (T-\d+) (.+)$/.exec(line);
    if (heading) {
      const detail = { id: heading[1] ?? '', title: plain(heading[2] ?? ''), fields: [] };
      details.set(detail.id, detail);
      current = detail;
      continue;
    }
    if (current === undefined) continue;
    const field = /^- \*\*([^*]+?):\*\*\s*(.*)$/.exec(line);
    if (field) {
      current.fields.push({ label: plain(field[1] ?? ''), text: plain(field[2] ?? ''), items: [] });
      continue;
    }
    const item = /^ {2,}- (.+)$/.exec(line);
    const last = current.fields.at(-1);
    if (item && last) last.items.push(plain(item[1] ?? ''));
  }
  const rows = tableRows(section(markdown, '5.'), /^T-\d+$/);
  return rows.map((row) => {
    const [
      id = '',
      threat = '',
      likelihood = '',
      impact = '',
      inherent = '',
      treatment = '',
      residual = '',
      related = '',
      controls = '',
    ] = row;
    const detail = details.get(id);
    if (detail === undefined) throw new Error(`Risk ${id} has no section in the threat model`);
    return {
      id,
      threat: plain(threat),
      title: detail.title,
      likelihood: plain(likelihood),
      impact: plain(impact),
      inherent: plain(inherent),
      treatment: plain(treatment),
      residual: plain(residual),
      limitations: [...plain(related).matchAll(/L-\d+/g)].map((m) => m[0]),
      // Baseline risk-to-control mapping (risk treatment plan, clause 6.1.3): SoA row identifiers.
      controls: plain(controls)
        .split(/,\s*/)
        .filter((control) => control !== ''),
      assets: [...(detail.fields.find((f) => f.label === 'Assets')?.text ?? '').matchAll(/A-\d+/g)].map((m) => m[0]),
      fields: detail.fields,
    };
  });
}

/**
 * Limitations register.
 * @param {string} markdown docs/security/limitations.md
 */
export function parseLimitations(markdown) {
  const rows = tableRows(markdown.split(/\r?\n/), /^L-\d+$/);
  return rows.map(([id = '', limitation = '', why = '', response = '', demonstration = '']) => ({
    id,
    limitation: plain(limitation),
    why: plain(why),
    response: plain(response),
    demonstration: plain(demonstration),
  }));
}

/**
 * ISMS: scope, management-system clauses and Annex A controls.
 * @param {string} markdown docs/security/isms-control-mapping.md
 */
export function parseIsms(markdown) {
  const scope = plain(
    section(markdown, '1.')
      .filter((line) => line.trim() !== '')
      .join(' '),
  );
  const clauses = tableRows(section(markdown, '2.'), /^\d+(\.\d+)*(, \d+(\.\d+)*)*$/).map(
    ([clause = '', requirement = '', implementation = '']) => ({
      clause,
      requirement: plain(requirement),
      implementation: plain(implementation),
    }),
  );
  const annex = section(markdown, '3.');
  const legend = annex.find((line) => line.startsWith('Status values:'));
  const controls = tableRows(annex, /^\d+\.\d+( to \d+\.\d+)?$/).map((row) => {
    const [control = '', title = '', status = '', implementation = '', ...evidence] = row;
    const evidenceText = evidence.join(', ');
    return {
      control,
      title: plain(title),
      theme: themeOf(control),
      status: plain(status),
      implementation: plain(implementation),
      evidenceText: plain(evidenceText),
      evidence: evidenceIds(evidenceText),
    };
  });
  return { scope, statusLegend: plain(legend ?? ''), clauses, controls };
}

/**
 * ISO/IEC 27001:2022 Annex A theme of a control number.
 * @param {string} control
 */
export function themeOf(control) {
  const theme = control.split('.')[0];
  return theme === '5' ? 'Organizational' : theme === '6' ? 'People' : theme === '7' ? 'Physical' : 'Technological';
}

/**
 * Evidence plan items (ID, what, how, demonstrates, subject tags).
 * @param {string} markdown docs/report/evidence-plan.md
 */
export function parseEvidencePlan(markdown) {
  return tableRows(section(markdown, '3.'), /^EV-\d{2}-\d{2}$/).map(
    ([id = '', evidence = '', how = '', demonstrates = '', tags = '']) => ({
      id,
      phase: Number(id.slice(3, 5)),
      evidence: plain(evidence),
      how: plain(how),
      demonstrates: plain(demonstrates),
      // "All" in the plan means every subject tag.
      tags:
        plain(tags) === 'All'
          ? ['CRY', 'CLD', 'ISMS', 'APP']
          : plain(tags)
              .split(/,\s*/)
              .filter((tag) => tag !== ''),
    }),
  );
}

/**
 * Evidence index rows: which items are captured, with links to the committed files.
 * @param {string} markdown docs/report/evidence/index.md
 */
export function parseEvidenceIndex(markdown) {
  return tableRows(markdown.split(/\r?\n/), /^EV-\d{2}-\d{2}/).map(
    ([idCell = '', file = '', date = '', jira = '', caption = '']) => {
      const links = [...file.matchAll(/\[([^\]]+)\]\(([^)]+)\)/g)].map((m) => ({
        label: m[1] ?? '',
        path: posix.normalize(posix.join('docs/report/evidence', m[2] ?? '')),
      }));
      const pending = /^pending\b/i.test(plain(file));
      return {
        ids: evidenceIds(idCell),
        qualifier: plain(
          idCell.replace(/EV-\d{2}-\d{2}(\s+to\s+EV-\d{2}-\d{2})?/g, '').replace(/^[\s,]+|[\s,]+$/g, ''),
        ),
        location: links.length > 0 || pending ? '' : plain(file),
        links,
        pending,
        date: plain(date),
        jira: plain(jira),
        caption: plain(caption),
      };
    },
  );
}

/**
 * Evidence IDs a committed evidence file belongs to, from its name: "EV-06-01_rows.txt",
 * "EV-01-06a_build.txt" and "EV-11-06-07_recovery.txt" (two items).
 * @param {string} path
 * @returns {string[]}
 */
export function evidenceIdsOfFile(path) {
  const name = posix.basename(path);
  const match = /^EV-(\d{2})-(\d{2})(?:-(\d{2}))?[a-z]?[_.-]/.exec(name);
  if (match === null) return [];
  const [, phase, first, second] = match;
  return [`EV-${phase}-${first}`, ...(second === undefined ? [] : [`EV-${phase}-${second}`])];
}

/**
 * The status of one planned evidence item, from the committed files, the index and the phase plan.
 * captured: a committed file (or a recorded location) exists for it and no part is pending.
 * partial: some parts are captured, others pending. pending: due in a completed phase but not captured.
 * deferred: its phase was deferred by the project owner. planned: its phase is a later workstream.
 * @param {{ id: string, phase: number }} item
 * @param {ReturnType<typeof parseEvidenceIndex>} index
 * @param {readonly string[]} [files] committed evidence files, repository-relative
 */
export function evidenceStatus(item, index, files = []) {
  const rows = index.filter((row) => row.ids.includes(item.id));
  const captured =
    rows.some((row) => !row.pending && (row.links.length > 0 || row.location !== '')) ||
    files.some((file) => evidenceIdsOfFile(file).includes(item.id));
  const open = rows.filter((row) => row.pending);
  if (captured) return open.length > 0 ? 'partial' : 'captured';
  if (DEFERRED_PHASES.includes(item.phase)) return 'deferred';
  if (LATER_PHASES.includes(item.phase)) return 'planned';
  return 'pending';
}

/**
 * Parameter register rows (CP-xx): name and value as the register states them.
 * @param {string} markdown docs/crypto/crypto-decisions.md
 */
export function parseParameters(markdown) {
  return tableRows(section(markdown, '1.'), /^CP-\d+$/).map(([id = '', name = '', value = '', notes = '']) => ({
    id,
    name: plain(name),
    value: plain(value),
    notes: plain(notes),
  }));
}

/**
 * Cloud documents: the shared-responsibility matrix and the designed network exposure.
 * @param {string} responsibility docs/cloud/shared-responsibility.md
 * @param {string} deployment docs/cloud/deployment-architecture.md
 */
export function parseCloud(responsibility, deployment) {
  const matrix = section(responsibility, '2.');
  const header = cells(matrix.find((line) => line.startsWith('| Layer')) ?? '');
  const services = header.slice(1).map(plain);
  const layers = matrix
    .map(cells)
    .filter((row) => row.length === header.length && row[0] !== 'Layer' && !/^-+$/.test(row[0] ?? ''))
    .map(([layer = '', ...owners]) => ({ layer: plain(layer), owners: owners.map(plain) }));
  const exposure = section(deployment, '2.')
    .map(cells)
    .filter((row) => row.length === 4 && row[0] !== 'Endpoint' && !/^-+$/.test(row[0] ?? ''))
    .map(([endpoint = '', exposedTo = '', port = '', notes = '']) => ({
      endpoint: plain(endpoint),
      exposedTo: plain(exposedTo),
      port: plain(port),
      notes: plain(notes),
    }));
  return { services, layers, exposure };
}

/**
 * Builds every Trust Center data file from the document texts.
 * @param {{ threatModel: string, limitations: string, isms: string, evidencePlan: string, evidenceIndex: string, cryptoDecisions: string, responsibility: string, deployment: string }} docs
 * @param {readonly string[]} evidenceFiles committed files under docs/report/evidence, repository-relative
 */
export function buildTrustData(docs, evidenceFiles) {
  const risks = parseRisks(docs.threatModel);
  const limitations = parseLimitations(docs.limitations);
  const isms = parseIsms(docs.isms);
  const evidence = buildEvidence(docs, evidenceFiles);
  const parameters = parseParameters(docs.cryptoDecisions);
  return {
    'risks.json': { source: 'docs/threat-model/threat-model.md', risks },
    'limitations.json': { source: 'docs/security/limitations.md', limitations },
    'isms.json': { source: 'docs/security/isms-control-mapping.md', ...isms },
    'evidence.json': {
      source: ['docs/report/evidence-plan.md', 'docs/report/evidence/index.md'],
      repository: REPOSITORY_URL,
      deferredPhases: DEFERRED_PHASES,
      laterPhases: LATER_PHASES,
      evidence,
    },
    'parameters.json': { source: 'docs/crypto/crypto-decisions.md', parameters },
    'cloud.json': {
      source: ['docs/cloud/shared-responsibility.md', 'docs/cloud/deployment-architecture.md'],
      ...parseCloud(docs.responsibility, docs.deployment),
    },
  };
}

/**
 * The evidence register: plan items with their status, files, captions and latest capture date.
 * @param {{ evidencePlan: string, evidenceIndex: string }} docs
 * @param {readonly string[]} evidenceFiles
 */
export function buildEvidence(docs, evidenceFiles) {
  const plan = parseEvidencePlan(docs.evidencePlan);
  const index = parseEvidenceIndex(docs.evidenceIndex);
  return plan.map((item) => {
    const rows = index.filter((row) => row.ids.includes(item.id));
    const linked = rows.flatMap((row) => row.links.map((link) => ({ label: link.label, path: link.path })));
    const named = evidenceFiles
      .filter((file) => evidenceIdsOfFile(file).includes(item.id) && !linked.some((link) => link.path === file))
      .map((file) => ({ label: posix.basename(file), path: file }));
    return {
      ...item,
      status: evidenceStatus(item, index, evidenceFiles),
      files: [...linked, ...named],
      locations: rows.map((row) => row.location).filter((location) => location !== ''),
      captions: rows.map((row) => (row.qualifier === '' ? row.caption : `${row.qualifier}: ${row.caption}`)),
      // The latest capture date: a refreshed item is current from its newest capture.
      date:
        rows
          .map((row) => row.date)
          .filter((date) => /^\d{4}-\d{2}-\d{2}$/.test(date))
          .sort()
          .at(-1) ?? '',
    };
  });
}

// ------------------------------------------------------------- operational ISMS (ADR-016)

/**
 * SHA-256 (hex) of a text with LF line endings, so a checkout's line endings never change it.
 * @param {string} text
 */
export function fingerprint(text) {
  return createHash('sha256').update(text.replace(/\r\n/g, '\n'), 'utf8').digest('hex');
}

/** @param {string} text */
const listOf = (text) =>
  plain(text)
    .split(/,\s*/)
    .filter((item) => item !== '');

/**
 * Asset inventory (control 5.9): threat model section 2.
 * @param {string} markdown docs/threat-model/threat-model.md
 */
export function parseAssets(markdown) {
  return tableRows(section(markdown, '2.'), /^A-\d+$/).map(
    ([
      id = '',
      asset = '',
      property = '',
      category = '',
      owner = '',
      confidentiality = '',
      integrity = '',
      availability = '',
      location = '',
    ]) => ({
      id,
      asset: plain(asset),
      property: plain(property),
      category: plain(category),
      owner: plain(owner),
      confidentiality: plain(confidentiality),
      integrity: plain(integrity),
      availability: plain(availability),
      location: plain(location),
    }),
  );
}

/**
 * Security goals G1 to G7 (the information security objectives).
 * @param {string} markdown docs/architecture/system-overview.md
 */
export function parseObjectives(markdown) {
  return tableRows(markdown.split(/\r?\n/), /^G\d+$/).map(([id = '', goal = '', how = '']) => ({
    id,
    goal: plain(goal),
    how: plain(how),
  }));
}

/**
 * Registers of the ISMS manual: context, roles, policies, freshness classes and metrics.
 * @param {string} markdown docs/security/isms-operations.md
 */
export function parseIsmsOperations(markdown) {
  const context = section(markdown, '2.');
  const issues = tableRows(context, /^ISS-\d+$/).map(([id = '', type = '', issue = '', effect = '']) => ({
    id,
    type: plain(type),
    issue: plain(issue),
    effect: plain(effect),
  }));
  const parties = tableRows(context, /^IP-\d+$/).map(([id = '', party = '', requirements = '', response = '']) => ({
    id,
    party: plain(party),
    requirements: plain(requirements),
    response: plain(response),
  }));
  const boundaries = tableRows(context, /^B-\d+$/).map(([id = '', boundary = '', element = '', reason = '']) => ({
    id,
    boundary: plain(boundary),
    element: plain(element),
    reason: plain(reason),
  }));
  const roles = tableRows(section(markdown, '3.'), /^ROLE-\d+$/).map(
    ([id = '', role = '', heldBy = '', responsibilities = '', permission = '']) => ({
      id,
      role: plain(role),
      heldBy: plain(heldBy),
      responsibilities: plain(responsibilities),
      permission: plain(permission),
    }),
  );
  const policies = tableRows(section(markdown, '4.'), /^POL-\d+$/).map(
    ([id = '', title = '', document = '', owner = '', cycle = '', controls = '', risks = '']) => {
      const reviewDays = Number(plain(cycle));
      if (!Number.isInteger(reviewDays) || reviewDays <= 0) throw new Error(`${id}: the review cycle must be days`);
      return {
        id,
        title: plain(title),
        path: plain(document),
        owner: plain(owner),
        reviewDays,
        controls: listOf(controls),
        risks: listOf(risks),
      };
    },
  );
  const freshness = section(markdown, '7.');
  const classes = tableRows(freshness, /^(VULNERABILITY|TECHNICAL|DESIGN)$/).map(
    ([id = '', days = '', appliesTo = '']) => {
      const validityDays = Number(plain(days));
      if (!Number.isInteger(validityDays) || validityDays <= 0) throw new Error(`${id}: the validity must be days`);
      return { id, validityDays, appliesTo: plain(appliesTo) };
    },
  );
  /** @type {Record<string, string>} */
  const evidenceClasses = Object.fromEntries(
    tableRows(freshness, /^EV-\d{2}-\d{2}$/).map(([id = '', cls = '']) => [id, plain(cls)]),
  );
  const metrics = tableRows(section(markdown, '12.'), /^M-\d+$/).map(
    ([
      id = '',
      objective = '',
      calculation = '',
      source = '',
      frequency = '',
      owner = '',
      target = '',
      limitation = '',
    ]) => ({
      id,
      objective: plain(objective),
      calculation: plain(calculation),
      source: plain(source),
      frequency: plain(frequency),
      owner: plain(owner),
      target: plain(target),
      limitation: plain(limitation),
    }),
  );
  return { issues, parties, boundaries, roles, policies, classes, evidenceClasses, metrics };
}

const RISK_DETAIL_LABELS = [
  'STRIDE',
  'Threat',
  'Attack scenario',
  'Security controls',
  'Residual risk',
  'Testing strategy',
];

/**
 * The catalogue of the operational ISMS (ADR-016): every risk, asset, Statement of Applicability
 * row, evidence item, policy, role, freshness class and metric that the API and the Control Center
 * may reference, generated from the normative documents and cross-checked here. The scope and the
 * policy documents are fingerprinted, so a review record names the exact revision it reviewed.
 * @param {{ threatModel: string, isms: string, ismsOperations: string, systemOverview: string, evidencePlan: string, evidenceIndex: string, policyDocuments: Record<string, string> }} docs
 * @param {readonly string[]} evidenceFiles
 */
export function buildIsmsCatalogue(docs, evidenceFiles) {
  const ops = parseIsmsOperations(docs.ismsOperations);
  const isms = parseIsms(docs.isms);
  const risks = parseRisks(docs.threatModel);
  const assets = parseAssets(docs.threatModel);
  const evidence = buildEvidence(docs, evidenceFiles);
  /** @param {string} message */
  const fail = (message) => {
    throw new Error(`ISMS catalogue: ${message}`);
  };
  const classIds = new Set(ops.classes.map((c) => c.id));
  if (!classIds.has('TECHNICAL')) fail('the default freshness class TECHNICAL is missing');
  for (const [id, cls] of Object.entries(ops.evidenceClasses)) {
    if (!classIds.has(cls)) fail(`${id} names the unknown freshness class ${cls}`);
    if (!evidence.some((item) => item.id === id)) fail(`${id} is not in the evidence plan`);
  }
  const rowIds = new Set(isms.controls.map((c) => c.control));
  const assetIds = new Set(assets.map((a) => a.id));
  const riskIds = new Set(risks.map((r) => r.id));
  for (const risk of risks) {
    if (risk.controls.length === 0) fail(`${risk.id} has no Annex A controls`);
    for (const control of risk.controls) {
      if (!rowIds.has(control)) fail(`${risk.id} names the unknown control ${control}`);
    }
    for (const asset of risk.assets) if (!assetIds.has(asset)) fail(`${risk.id} names the unknown asset ${asset}`);
  }
  for (const policy of ops.policies) {
    for (const control of policy.controls) {
      if (!rowIds.has(control)) fail(`${policy.id} names the unknown control ${control}`);
    }
    for (const risk of policy.risks) if (!riskIds.has(risk)) fail(`${policy.id} names the unknown risk ${risk}`);
    if (docs.policyDocuments[policy.path] === undefined) fail(`${policy.id}: ${policy.path} was not read`);
  }
  const revision = /Scope revision (\d+)/.exec(isms.scope)?.[1];
  return {
    sources: [
      'docs/security/isms-operations.md',
      'docs/security/isms-control-mapping.md',
      'docs/threat-model/threat-model.md',
      'docs/architecture/system-overview.md',
      'docs/report/evidence-plan.md',
      'docs/report/evidence/index.md',
    ],
    scope: { revision: Number(revision ?? '1'), text: isms.scope, fingerprint: fingerprint(isms.scope) },
    issues: ops.issues,
    parties: ops.parties,
    boundaries: ops.boundaries,
    roles: ops.roles,
    objectives: parseObjectives(docs.systemOverview),
    policies: ops.policies.map((policy) => ({
      ...policy,
      fingerprint: fingerprint(docs.policyDocuments[policy.path] ?? ''),
    })),
    freshness: { defaultClass: 'TECHNICAL', classes: ops.classes, evidence: ops.evidenceClasses },
    metrics: ops.metrics,
    assets,
    risks: risks.map((risk) => ({
      id: risk.id,
      title: risk.title,
      threat: risk.threat,
      likelihood: risk.likelihood,
      impact: risk.impact,
      inherent: risk.inherent,
      treatment: risk.treatment,
      residual: risk.residual,
      limitations: risk.limitations,
      controls: risk.controls,
      assets: risk.assets,
      details: risk.fields
        .filter((field) => RISK_DETAIL_LABELS.includes(field.label))
        .map((field) => ({ label: field.label, text: field.text })),
    })),
    clauses: isms.clauses,
    controls: isms.controls.map((control) => ({
      id: control.control,
      title: control.title,
      theme: control.theme,
      status: control.status,
      implementation: control.implementation,
      evidence: control.evidence,
    })),
    evidence: evidence.map((item) => ({
      id: item.id,
      phase: item.phase,
      title: item.evidence,
      how: item.how,
      status: item.status,
      captured: item.date === '' ? null : item.date,
      files: item.files.map((file) => file.path),
    })),
  };
}

/**
 * The catalogue as a TypeScript module of the shared package (read by the API and the web client).
 * @param {unknown} catalogue
 */
export function renderIsmsCatalogue(catalogue) {
  return [
    '// Generated by `pnpm trust:generate` from the normative documents (ADR-016). Do not edit by hand:',
    '// `pnpm trust:check` and the web build fail when this file differs from the documents.',
    "import type { IsmsCatalogue } from './isms';",
    '',
    `export const ISMS_CATALOGUE: IsmsCatalogue = ${JSON.stringify(catalogue, null, 2)};`,
    '',
  ].join('\n');
}

/**
 * Stable JSON text with a trailing newline, as committed.
 * @param {unknown} value
 */
export function serialize(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}
