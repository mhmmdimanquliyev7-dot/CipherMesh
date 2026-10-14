import Link from 'next/link';
import { Icon } from '../components/icons';
import { buttonClass } from '../components/ui';

export default function NotFound() {
  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-4 py-16 text-center">
      <span className="grid size-14 place-items-center rounded-2xl border border-slate-800 bg-surface text-accent-300">
        <Icon name="globe" className="size-7" />
      </span>
      <h1 className="text-2xl font-semibold tracking-tight text-white">Page not found</h1>
      <p className="text-slate-400">The page you requested does not exist.</p>
      <Link href="/" className={buttonClass.secondary}>
        Return to the start page
      </Link>
    </div>
  );
}
