import { PRODUCT_TAGLINE } from '@ciphermesh/shared';

interface Capability {
  readonly name: string;
  readonly phase: string;
}

// Planned capabilities and the roadmap phase that delivers each. Nothing here is
// available yet, and the page says so rather than implying protection that does not exist.
const CAPABILITIES: readonly Capability[] = [
  { name: 'Accounts, sessions and multi-factor authentication', phase: 'Phase 3' },
  { name: 'Vault: personal key pair protected by your Vault Passphrase', phase: 'Phase 4' },
  { name: 'Secure Rooms with role-based access', phase: 'Phase 5' },
  { name: 'Client-side encrypted files, notes and one-time secrets', phase: 'Phases 7 to 9' },
  { name: 'Room key rotation and the Room Safety Code', phase: 'Phases 6 and 11' },
  { name: 'Tamper-evident audit ledger', phase: 'Phase 12' },
  { name: 'Crypto Inspector and Security Dashboard', phase: 'Phases 13 and 14' },
];

export default function HomePage() {
  return (
    <div className="space-y-10">
      <section className="space-y-3">
        <h1 className="text-3xl font-semibold tracking-tight">{PRODUCT_TAGLINE}</h1>
        <p className="max-w-3xl text-slate-300">
          CipherMesh will encrypt room content in your browser before it is uploaded, so the server stores ciphertext
          and wrapped keys rather than readable content. This build contains the application foundation only: no
          accounts, rooms or encryption features are available yet.
        </p>
      </section>

      <section aria-labelledby="planned-heading" className="space-y-4">
        <h2 id="planned-heading" className="text-xl font-semibold">
          Planned capabilities
        </h2>
        <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800">
          {CAPABILITIES.map((capability) => (
            <li key={capability.name} className="flex items-center justify-between gap-4 px-4 py-3">
              <span>{capability.name}</span>
              <span className="shrink-0 rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
                Not yet available · {capability.phase}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
