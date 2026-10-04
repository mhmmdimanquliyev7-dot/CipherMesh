import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="text-slate-300">The page you requested does not exist.</p>
      <Link href="/" className="text-sky-300 underline underline-offset-4">
        Return to the start page
      </Link>
    </div>
  );
}
