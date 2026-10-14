import { PRODUCT_TAGLINE } from '@ciphermesh/shared';
import Link from 'next/link';
import { Icon, type IconName } from '../components/icons';
import { Badge, buttonClass } from '../components/ui';

/**
 * The public start page. Every capability listed here is built and tested in this repository;
 * what is not built yet is said plainly (CLAUDE.md section 8: no claim stronger than the system).
 */

const CAPABILITIES: readonly { readonly icon: IconName; readonly title: string; readonly text: string }[] = [
  {
    icon: 'rooms',
    title: 'Secure rooms',
    text: 'Workspaces with owners, admins, members and viewers. Every request is authorized by the server against the stored membership.',
  },
  {
    icon: 'file',
    title: 'Encrypted files',
    text: 'Each file is encrypted in your browser with its own AES-256-GCM key before it travels to object storage.',
  },
  {
    icon: 'note',
    title: 'Encrypted notes',
    text: 'Every note revision gets a fresh key. Titles and bodies never reach the server in readable form.',
  },
  {
    icon: 'secret',
    title: 'Burn-after-reading secrets',
    text: 'One-time secrets wrapped to one recipient’s key and destroyed in the same transaction that reveals them.',
  },
  {
    icon: 'rotate',
    title: 'Key rotation',
    text: 'Removing a member locks the room until a new key version is made in a browser and signed by an owner or admin.',
  },
  {
    icon: 'fingerprint',
    title: 'Verifiable identities',
    text: 'Signed room statements, key fingerprints and a Room Safety Code that members compare outside the app.',
  },
];

const FLOW: readonly { readonly icon: IconName; readonly title: string; readonly text: string }[] = [
  { icon: 'browser', title: 'Your browser', text: 'Encrypts content and wraps its key. Keys stay in memory.' },
  { icon: 'server', title: 'CipherMesh API', text: 'Authorizes requests. Stores ciphertext and wrapped keys only.' },
  {
    icon: 'database',
    title: 'Database and storage',
    text: 'Hold encrypted records. Metadata such as sizes stays visible.',
  },
];

export default function HomePage() {
  return (
    <div className="space-y-20 pb-6">
      <section className="grid items-center gap-12 pt-6 lg:grid-cols-[1.1fr_0.9fr] lg:pt-12">
        <div className="space-y-6">
          <Badge tone="accent" icon="lock">
            Encryption happens on your device
          </Badge>
          <h1 className="text-4xl font-semibold leading-tight tracking-tight text-white sm:text-5xl">
            {PRODUCT_TAGLINE}
          </h1>
          <p className="max-w-xl text-lg leading-relaxed text-slate-300">
            CipherMesh encrypts files, notes and one-time secrets in your browser before they are uploaded. The server
            authorizes every request and stores ciphertext and wrapped keys, never your readable content or your keys.
          </p>
          <div className="flex flex-wrap gap-3">
            <Link className={buttonClass.primary} href="/register">
              Create an account
              <Icon name="arrowRight" className="size-4" />
            </Link>
            <Link className={buttonClass.secondary} href="/login">
              Sign in
            </Link>
            <Link className={buttonClass.ghost} href="/trust">
              <Icon name="trust" className="size-4" />
              How it is protected
            </Link>
          </div>
        </div>

        <figure
          aria-label="Where encryption happens"
          className="rounded-2xl border border-line bg-surface/80 p-6 shadow-2xl shadow-black/30"
        >
          <ol className="space-y-3">
            {FLOW.map((step, index) => (
              <li key={step.title} className="space-y-3">
                <div className="flex items-start gap-4 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                  <span className="grid size-10 place-items-center rounded-lg border border-accent-500/30 bg-accent-500/10 text-accent-300">
                    <Icon name={step.icon} />
                  </span>
                  <div className="space-y-0.5">
                    <p className="font-medium text-white">{step.title}</p>
                    <p className="text-sm text-slate-400">{step.text}</p>
                  </div>
                </div>
                {index < FLOW.length - 1 ? (
                  <p className="flex items-center gap-2 pl-8 text-xs font-medium text-accent-300">
                    <span className="flow-connector h-5 w-px" aria-hidden="true" />
                    {index === 0 ? 'Ciphertext and wrapped keys over HTTPS' : 'Encrypted records only'}
                  </p>
                ) : null}
              </li>
            ))}
          </ol>
          <figcaption className="mt-4 text-xs leading-relaxed text-slate-500">
            Client-side encryption cannot protect against a compromised device or a malicious application served by a
            compromised server. These limits are documented in the Trust Center.
          </figcaption>
        </figure>
      </section>

      <section aria-labelledby="capabilities-heading" className="space-y-6">
        <div className="space-y-2">
          <h2 id="capabilities-heading" className="text-2xl font-semibold tracking-tight text-white">
            Built for sensitive collaboration
          </h2>
          <p className="max-w-2xl text-slate-400">
            Each capability below is implemented, covered by automated tests and documented with its limits.
          </p>
        </div>
        <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CAPABILITIES.map((capability) => (
            <li key={capability.title} className="space-y-3 rounded-xl border border-line bg-surface/80 p-5">
              <span className="grid size-9 place-items-center rounded-lg bg-slate-800/80 text-accent-300">
                <Icon name={capability.icon} />
              </span>
              <h3 className="font-semibold text-white">{capability.title}</h3>
              <p className="text-sm leading-relaxed text-slate-400">{capability.text}</p>
            </li>
          ))}
        </ul>
      </section>

      <section
        aria-labelledby="trust-heading"
        className="grid gap-8 rounded-2xl border border-line bg-surface/80 p-6 sm:p-8 lg:grid-cols-[1fr_1.2fr]"
      >
        <div className="space-y-3">
          <h2 id="trust-heading" className="text-2xl font-semibold tracking-tight text-white">
            Security you can inspect
          </h2>
          <p className="text-slate-400">
            The Security &amp; Trust Center explains the cryptography, the deployment design and the risk management
            behind CipherMesh, and links every claim to its evidence and its limits.
          </p>
          <Link className={buttonClass.secondary} href="/trust">
            Open the Trust Center
          </Link>
        </div>
        <ul className="grid gap-3 sm:grid-cols-3">
          {(
            [
              { icon: 'key', title: 'Cryptography', href: '/trust/cryptography', status: 'Implemented and tested' },
              {
                icon: 'cloud',
                title: 'Cloud & infrastructure',
                href: '/trust/infrastructure',
                status: 'Designed · cloud not yet connected',
              },
              { icon: 'governance', title: 'Governance & risk', href: '/trust/governance', status: 'Documented ISMS' },
            ] as const
          ).map((pillar) => (
            <li key={pillar.title}>
              <Link
                href={pillar.href}
                className="flex h-full flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4 transition-colors hover:border-accent-500/40"
              >
                <Icon name={pillar.icon} className="size-6 text-accent-300" />
                <span className="font-medium text-white">{pillar.title}</span>
                <span className="mt-auto text-xs text-slate-400">{pillar.status}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
