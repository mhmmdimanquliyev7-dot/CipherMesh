// `pnpm db:check-schema [path]`: checks prisma/schema.prisma against the data-model rules
// (CM-T013, EV-02-01). Exits 1 on any problem. Negative controls: tests/database/check-schema.test.ts.
//
// Rules (docs/architecture/data-model.md sections 2 and 6):
//  1. Every stored field carries `/// class: X` with a classification from section 2.
//  2. Client-side ciphertext (CT), wrapped keys (WK), server-encrypted secrets (SENC) and public
//     keys (PUBK) are bytea. Digests (DIG) are bytea, except the Argon2id PHC string.
//  3. No field name matches the "must never exist" list: plaintext passwords or passphrases,
//     raw private, room or data keys, filenames, MIME types, plaintext hashes, note titles or
//     bodies, raw tokens or recovery codes, plaintext TOTP secrets, key escrow, Room Safety
//     Codes, presigned URLs, and IP addresses in audit events.
//  4. Any field that mentions a key must have an allowlisted shape (wrapped..., encrypted...,
//     ...Id, ...Iv, ...Version, public key fields, objectKey), so a new `roomKey`, `masterKey`
//     or `sessionKey` column fails until it is reviewed.
//  5. Forbidden models: a mutable SecurityPolicy table (4.16), key escrow or master keys.
// The check is name-based and cannot see what a column will hold at runtime; the database
// CHECK constraints, the response projections and the plaintext canary tests cover that.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const CLASSES = Object.freeze(['ID', 'META', 'PII', 'CT', 'WK', 'SENC', 'DIG', 'INT', 'PUBK']);
const BYTES_CLASSES = new Set(['CT', 'WK', 'SENC', 'PUBK']);
const SCALARS = new Set(['String', 'Boolean', 'Int', 'BigInt', 'Float', 'Decimal', 'DateTime', 'Json', 'Bytes']);

/**
 * [test, reason]. `n` is the name in lower case without separators; `t` is the list of words
 * split from camelCase or snake_case, so short abbreviations match whole words only.
 * @type {[(n: string, t: string[]) => boolean, string][]}
 */
const FORBIDDEN_FIELDS = [
  [
    (n) => /password/.test(n) && !['passwordhash', 'passwordchangedat'].includes(n),
    'plaintext or reversibly encrypted password (INV-11)',
  ],
  [(n) => /passphrase/.test(n), 'Vault Passphrase value, hash or verifier (INV-01)'],
  [
    (n) =>
      /privatekey/.test(n) &&
      // Ciphertext and IVs of the two wrapped identity keys (ADR-015); never a plaintext key.
      !['encryptedprivatekey', 'privatekeyiv', 'encryptedsigningprivatekey', 'signingprivatekeyiv'].includes(n),
    'plaintext private key (INV-01)',
  ],
  [
    (n, t) => t.some((w) => ['vrk', 'pkwk', 'rwk', 'rkm'].includes(w)) || /vaultroot|wrappingkey|keymaterial/.test(n),
    'vault-derived key or room key material (INV-01, INV-04)',
  ],
  [(n) => /roomkey(?!version)/.test(n), 'room key column (INV-04)'],
  [
    (n, t) =>
      (t.some((w) => ['dek', 'fek', 'nek', 'sek'].includes(w)) || /datakey|contentkey/.test(n)) &&
      !['wrappeddek', 'wrappedsek', 'dekiv'].includes(n),
    'plaintext data key (INV-01, INV-03)',
  ],
  [
    (n) => /filename|originalname|mimetype|contenttype|plaintext|cleartext/.test(n),
    'plaintext file metadata or content (INV-16)',
  ],
  [(n) => /title|body|notetext/.test(n), 'plaintext note title or body (INV-01)'],
  [(n) => /token/.test(n) && n !== 'tokendigest', 'raw session or invitation token (INV-12)'],
  [(n) => /recoverycode|code$/.test(n) && n !== 'codedigest', 'raw recovery code (INV-12)'],
  [(n) => /totp/.test(n) && !['mfatotpsecretenc', 'mfatotpkeyid'].includes(n), 'plaintext TOTP secret'],
  [(n) => /secret/.test(n) && !['mfatotpsecretenc'].includes(n), 'plaintext secret (INV-01)'],
  [(n) => /escrow|masterkey|recoverykey|backupkey/.test(n), 'key escrow or master key (ADR-002)'],
  [(n, t) => /safetycode|safetyword/.test(n) || t.includes('rsc'), 'Room Safety Code (INV-18)'],
  [(n) => /presign|signedurl|url$/.test(n), 'presigned URL (bearer capability)'],
  [(n) => /invitelink|invitationlink|linksecret/.test(n), 'invitation bearer secret'],
];

const KEY_FIELD_ALLOWED = [
  /^rekey/,
  /^wrapped/,
  /^encrypted/,
  /id$/,
  /iv$/,
  /version$/,
  /^keystate$/,
  /^publickey(spki|fingerprint)$/,
  /^signingpublickeyspki$/,
  /^objectkey$/,
];

/** @type {[(n: string) => boolean, string][]} */
const FORBIDDEN_MODELS = [
  [(n) => n === 'securitypolicy', 'security policy is a code-defined catalogue, not a mutable table (data-model 4.16)'],
  [(n) => /escrow|masterkey/.test(n), 'key escrow or master key (ADR-002)'],
  [(n) => /safetycode/.test(n), 'Room Safety Code (INV-18)'],
];

/** @param {string} name */
const normalise = (name) => name.toLowerCase().replace(/[^a-z0-9]/g, '');
/** @param {string} name */
const words = (name) =>
  name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);

/**
 * @typedef {{ model: string, field: string, column: string, type: string, optional: boolean, classification: string | undefined, line: number }} Field
 * @typedef {{ line: number, message: string }} Problem
 */

/**
 * Minimal parser for the subset of the Prisma schema language used in this repository.
 * @param {string} text
 * @returns {{ models: { name: string, table: string, line: number }[], fields: Field[] }}
 */
export function parseSchema(text) {
  const lines = text.split(/\r?\n/);
  const modelNames = new Set([...text.matchAll(/^\s*model\s+(\w+)\s*\{/gm)].map((m) => /** @type {string} */ (m[1])));
  /** @type {{ name: string, table: string, line: number }[]} */
  const models = [];
  /** @type {Field[]} */
  const fields = [];
  /** @type {{ name: string, table: string, line: number } | undefined} */
  let current;
  /** @type {string[]} */
  let docs = [];
  lines.forEach((raw, index) => {
    const line = raw.trim();
    const open = /^model\s+(\w+)\s*\{/.exec(line);
    if (open) {
      current = { name: /** @type {string} */ (open[1]), table: /** @type {string} */ (open[1]), line: index + 1 };
      models.push(current);
      docs = [];
      return;
    }
    if (current === undefined) return;
    if (line === '}') {
      current = undefined;
      return;
    }
    if (line.startsWith('///')) {
      docs.push(line.slice(3).trim());
      return;
    }
    const tableMap = /^@@map\("([^"]+)"\)/.exec(line);
    if (tableMap) current.table = /** @type {string} */ (tableMap[1]);
    if (line === '' || line.startsWith('//') || line.startsWith('@@')) {
      if (!line.startsWith('//')) docs = [];
      return;
    }
    const field = /^(\w+)\s+(\w+)(\[\])?(\?)?(.*)$/.exec(line);
    if (field) {
      const [, name = '', type = '', , optional, rest = ''] = field;
      if (!modelNames.has(type)) {
        const column = /@map\("([^"]+)"\)/.exec(rest)?.[1] ?? name;
        const classDoc = docs.find((d) => d.startsWith('class:'));
        const classification = classDoc === undefined ? undefined : /^class:\s*([A-Z]+)/.exec(classDoc)?.[1];
        fields.push({
          model: current.name,
          field: name,
          column,
          type,
          optional: optional === '?',
          classification,
          line: index + 1,
        });
      }
    }
    docs = [];
  });
  return { models, fields };
}

/**
 * @param {string} text the schema source
 * @returns {Problem[]}
 */
export function checkSchema(text) {
  const { models, fields } = parseSchema(text);
  /** @type {Problem[]} */
  const problems = [];
  const enumNames = new Set([...text.matchAll(/^\s*enum\s+(\w+)\s*\{/gm)].map((m) => m[1]));
  if (models.length === 0)
    problems.push({ line: 1, message: 'no models found: refusing to pass an empty or unreadable schema' });

  for (const model of models) {
    for (const [test, reason] of FORBIDDEN_MODELS) {
      if (test(normalise(model.name)) || test(normalise(model.table))) {
        problems.push({ line: model.line, message: `model ${model.name}: forbidden (${reason})` });
      }
    }
  }

  for (const f of fields) {
    const where = `${f.model}.${f.field}`;
    if (!SCALARS.has(f.type) && !enumNames.has(f.type)) {
      problems.push({ line: f.line, message: `${where}: unknown type ${f.type}` });
    }
    if (f.classification === undefined) {
      problems.push({ line: f.line, message: `${where}: missing "/// class: X" classification` });
    } else if (!CLASSES.includes(f.classification)) {
      problems.push({ line: f.line, message: `${where}: unknown classification ${f.classification}` });
    } else {
      const isPhc = f.classification === 'DIG' && f.field === 'passwordHash' && f.type === 'String';
      const needsBytes = BYTES_CLASSES.has(f.classification) || (f.classification === 'DIG' && !isPhc);
      if (needsBytes && f.type !== 'Bytes') {
        problems.push({
          line: f.line,
          message: `${where}: class ${f.classification} must be stored as Bytes, not ${f.type}`,
        });
      }
      if (f.type === 'Bytes' && !['CT', 'WK', 'SENC', 'DIG', 'INT', 'PUBK', 'META'].includes(f.classification)) {
        problems.push({
          line: f.line,
          message: `${where}: binary data needs a CT, WK, SENC, DIG, INT, PUBK or META class`,
        });
      }
    }
    for (const original of new Set([f.field, f.column])) {
      const name = normalise(original);
      for (const [test, reason] of FORBIDDEN_FIELDS) {
        if (test(name, words(original)))
          problems.push({ line: f.line, message: `${where}: forbidden field (${reason})` });
      }
      if (/key/.test(name) && !KEY_FIELD_ALLOWED.some((pattern) => pattern.test(name))) {
        problems.push({
          line: f.line,
          message: `${where}: key-related field without an allowlisted shape (review needed)`,
        });
      }
    }
    if (f.model === 'AuditEvent' && /(^ip|ipaddress|useragent|password|secret|token)/.test(normalise(f.field))) {
      problems.push({ line: f.line, message: `${where}: IP addresses and secrets never belong in audit events` });
    }
  }
  // The field name and its column name are both checked; report each finding once.
  return problems.filter((p, i) => problems.findIndex((q) => q.line === p.line && q.message === p.message) === i);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const path = process.argv[2] ?? 'prisma/schema.prisma';
  const problems = checkSchema(readFileSync(path, 'utf8'));
  const { models, fields } = parseSchema(readFileSync(path, 'utf8'));
  if (problems.length > 0) {
    for (const p of problems) console.error(`FAIL ${path}:${p.line} ${p.message}`);
    console.error(`${problems.length} problem(s) in ${path}`);
    process.exitCode = 1;
  } else {
    const counts = CLASSES.map((c) => `${c} ${fields.filter((f) => f.classification === c).length}`).join(', ');
    console.log(`PASS ${path}: ${models.length} models, ${fields.length} classified fields (${counts})`);
    console.log('PASS no field from the data-model "must never exist" list; ciphertext and key fields are bytea');
  }
}
