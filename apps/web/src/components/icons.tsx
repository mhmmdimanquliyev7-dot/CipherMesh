import { useId, type ReactNode } from 'react';

/**
 * CipherMesh icon set: original, minimal stroke drawings on a 24-unit grid, rendered as inline SVG
 * elements (no icon font, no image requests, no inline styles, so the strict CSP holds). Icons are
 * decorative by default (aria-hidden); a meaningful icon is always accompanied by visible text.
 */
const PATHS = {
  overview: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="4.5" rx="1.5" />
      <rect x="13.5" y="11" width="7" height="9.5" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
    </>
  ),
  rooms: (
    <>
      <path d="M4 9.5 12 4l8 5.5V19a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 19z" />
      <rect x="9.5" y="13" width="5" height="7.5" rx="1" />
      <path d="M12 15.5v1.5" />
    </>
  ),
  invitations: (
    <>
      <rect x="3.5" y="6" width="17" height="12.5" rx="2" />
      <path d="m4 7 8 6 8-6" />
    </>
  ),
  vault: (
    <>
      <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
      <circle cx="12" cy="12" r="3.25" />
      <path d="M12 8.75V7M12 17v-1.75M15.25 12H17M7 12h1.75" />
    </>
  ),
  trust: (
    <>
      <path d="M12 3.5 19.5 6v5.5c0 4.5-3.2 8-7.5 9-4.3-1-7.5-4.5-7.5-9V6z" />
      <path d="m8.75 12 2.25 2.25 4.5-4.5" />
    </>
  ),
  account: (
    <>
      <circle cx="12" cy="8.5" r="3.75" />
      <path d="M4.5 20c.8-3.6 3.8-5.75 7.5-5.75s6.7 2.15 7.5 5.75" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15.5" r="4" />
      <path d="m10.9 12.6 8.6-8.6M16.5 7l2.5 2.5M14 9.5l2 2" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </>
  ),
  unlock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 7.6-1.75" />
    </>
  ),
  file: (
    <>
      <path d="M6.5 3.5h7l4.5 4.5v11a1.5 1.5 0 0 1-1.5 1.5h-10A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1.5-1.5z" />
      <path d="M13.5 3.5V8h4.5" />
    </>
  ),
  note: (
    <>
      <rect x="4.5" y="3.5" width="15" height="17" rx="2" />
      <path d="M8 8.5h8M8 12h8M8 15.5h5" />
    </>
  ),
  secret: (
    <>
      <path d="M12 3.5c2.5 3 5 5.2 5 9a5 5 0 0 1-10 0c0-1.9.8-3.4 2-4.75.3 1.5 1.1 2.4 2 2.75-.5-2.6.1-4.9 1-7z" />
    </>
  ),
  members: (
    <>
      <circle cx="9" cy="9" r="3.25" />
      <path d="M3.5 19c.6-3 2.9-4.75 5.5-4.75s4.9 1.75 5.5 4.75" />
      <path d="M15.5 6.2a3.25 3.25 0 0 1 0 5.6M17.5 14.6c1.6.6 2.7 2.1 3 4.4" />
    </>
  ),
  rotate: (
    <>
      <path d="M19.5 12a7.5 7.5 0 0 1-12.9 5.2M4.5 12a7.5 7.5 0 0 1 12.9-5.2" />
      <path d="M17.5 3.5v3.5H14M6.5 20.5V17H10" />
    </>
  ),
  settings: (
    <>
      <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </>
  ),
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  checkCircle: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m8.25 12.25 2.5 2.5 5-5" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4 21 19.5H3z" />
      <path d="M12 10v4M12 16.75v.25" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5M12 8v.25" />
    </>
  ),
  x: <path d="m6.5 6.5 11 11M17.5 6.5l-11 11" />,
  xCircle: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="m9.25 9.25 5.5 5.5M14.75 9.25l-5.5 5.5" />
    </>
  ),
  minusCircle: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.5 12h7" />
    </>
  ),
  dashedCircle: <circle cx="12" cy="12" r="8.5" strokeDasharray="3 3" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  chevronRight: <path d="m9.5 6 6 6-6 6" />,
  arrowRight: <path d="M4.5 12h15M13.5 6l6 6-6 6" />,
  external: (
    <>
      <path d="M13.5 4.5h6v6M19.5 4.5 11 13" />
      <path d="M17.5 14v4.5a1.5 1.5 0 0 1-1.5 1.5H5.5A1.5 1.5 0 0 1 4 18.5V8a1.5 1.5 0 0 1 1.5-1.5H10" />
    </>
  ),
  cloud: <path d="M7.5 18.5a4 4 0 0 1-.6-7.95A5.5 5.5 0 0 1 17.6 9.4a4.5 4.5 0 0 1-.6 9.1z" />,
  server: (
    <>
      <rect x="4" y="4" width="16" height="6.5" rx="1.5" />
      <rect x="4" y="13.5" width="16" height="6.5" rx="1.5" />
      <path d="M7.5 7.25h.01M7.5 16.75h.01M11 7.25h5M11 16.75h5" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="6" rx="7" ry="2.75" />
      <path d="M5 6v12c0 1.5 3.1 2.75 7 2.75s7-1.25 7-2.75V6M5 12c0 1.5 3.1 2.75 7 2.75s7-1.25 7-2.75" />
    </>
  ),
  bucket: (
    <>
      <path d="M4.5 6.5h15l-1.6 12.2a1.5 1.5 0 0 1-1.5 1.3H7.6a1.5 1.5 0 0 1-1.5-1.3z" />
      <ellipse cx="12" cy="6.5" rx="7.5" ry="2.25" />
    </>
  ),
  browser: (
    <>
      <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
      <path d="M3.5 9h17M7 6.75h.01M9.5 6.75h.01" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17M12 3.5c2.4 2.4 3.5 5.3 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.3-3.5-8.5S9.6 5.9 12 3.5z" />
    </>
  ),
  governance: (
    <>
      <path d="M4 9.5 12 4.5l8 5" />
      <path d="M6 10v7M10 10v7M14 10v7M18 10v7M4 20h16" />
    </>
  ),
  evidence: (
    <>
      <rect x="5" y="4" width="14" height="17" rx="2" />
      <path d="M9 4V3h6v1M8.5 11l2.25 2.25 4.75-4.75M8.5 17h7" />
    </>
  ),
  risk: (
    <>
      <path d="M12 3.5a8.5 8.5 0 1 0 8.5 8.5" />
      <path d="M12 12V3.5A8.5 8.5 0 0 1 20.5 12z" />
    </>
  ),
  signature: (
    <>
      <path d="M3.5 17c2.5-.5 3.5-8.5 6-8.5 2 0 .5 6.5 2.5 6.5 1.5 0 2-3 3.5-3 1.2 0 1 2 2.5 2h2.5" />
      <path d="M3.5 20.5h17" />
    </>
  ),
  fingerprint: (
    <>
      <path d="M6.5 17.5c.6-1.4 1-3.2 1-5.5a4.5 4.5 0 0 1 9 0c0 2.7-.4 5-1.2 7" />
      <path d="M12 12c0 3.4-.7 6.1-2 8.5M4.5 13.5V12a7.5 7.5 0 0 1 12.4-5.7M19.4 10.2c.1.6.1 1.2.1 1.8 0 1.2-.1 2.3-.3 3.4" />
    </>
  ),
  layers: (
    <>
      <path d="m12 4 8.5 4.5L12 13 3.5 8.5z" />
      <path d="m3.5 12.5 8.5 4.5 8.5-4.5M3.5 16.5 12 21l8.5-4.5" />
    </>
  ),
  play: <path d="M8 5.5v13l10.5-6.5z" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  upload: <path d="M12 15.5V4.5M7.5 9 12 4.5 16.5 9M4.5 15v3.5A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5V15" />,
  plus: <path d="M12 5v14M5 12h14" />,
  network: (
    <>
      <circle cx="12" cy="5.5" r="2" />
      <circle cx="5.5" cy="18" r="2" />
      <circle cx="18.5" cy="18" r="2" />
      <path d="M11 7.3 6.5 16.2M13 7.3l4.5 8.9M7.5 18h9" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  className = 'size-5',
  label,
}: {
  readonly name: IconName;
  readonly className?: string;
  /** Only for an icon that stands alone; otherwise the icon is decorative. */
  readonly label?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      {...(label === undefined ? { 'aria-hidden': true } : { role: 'img', 'aria-label': label })}
    >
      {PATHS[name]}
    </svg>
  );
}

/**
 * The CipherMesh mark: three verified nodes joined into one protected mesh inside a rounded
 * hexagon. Original artwork drawn for this project.
 */
export function BrandMark({ className = 'size-8' }: { readonly className?: string }) {
  // A unique gradient ID per instance: the mark appears more than once on some pages.
  const gradient = `cm-mark-${useId().replace(/:/g, '')}`;
  return (
    <svg viewBox="0 0 32 32" className={`shrink-0 ${className}`} aria-hidden="true">
      <defs>
        <linearGradient id={gradient} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#57e6d6" />
          <stop offset="1" stopColor="#6366f1" />
        </linearGradient>
      </defs>
      <path
        d="M16 2.5 27.7 9.25v13.5L16 29.5 4.3 22.75V9.25z"
        fill="#0f1626"
        stroke={`url(#${gradient})`}
        strokeWidth="1.75"
        strokeLinejoin="round"
      />
      <path
        d="M16 10.25 21.25 19.5H10.75z"
        fill="none"
        stroke="#92f5e6"
        strokeWidth="1.4"
        strokeLinejoin="round"
        opacity="0.85"
      />
      <circle cx="16" cy="10.25" r="2.4" fill="#27cdbf" />
      <circle cx="10.75" cy="19.5" r="2.4" fill="#57e6d6" />
      <circle cx="21.25" cy="19.5" r="2.4" fill="#818cf8" />
    </svg>
  );
}
