import { encode } from 'uqr';

/**
 * Renders a QR code as SVG rectangles built from the encoded module matrix. No image request, no
 * HTML string injection and no inline styles, so it works under the strict CSP. Used only for the
 * one-time TOTP enrollment URI, which is never stored by the client.
 */
export function QrCode({ value, label }: { readonly value: string; readonly label: string }) {
  const { data, size } = encode(value, { ecc: 'M', border: 2 });
  const cells: { x: number; y: number }[] = [];
  data.forEach((row, y) => {
    row.forEach((dark, x) => {
      if (dark) cells.push({ x, y });
    });
  });
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${String(size)} ${String(size)}`}
      width={224}
      height={224}
      shapeRendering="crispEdges"
      className="rounded bg-white"
    >
      {cells.map(({ x, y }) => (
        <rect key={`${String(x)}-${String(y)}`} x={x} y={y} width={1} height={1} fill="#000" />
      ))}
    </svg>
  );
}
