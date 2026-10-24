/**
 * Line icons on a 24×24 grid, one path each, drawn with `currentColor` at
 * stroke width 2. Shared by the React pages (components/Icon.tsx) and the
 * plain-DOM UI inside web pages (lib/dom.ts).
 */

function circle(cx: number, cy: number, r: number): string {
  return `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
}

function rect(x: number, y: number, w: number, h: number, r: number): string {
  return (
    `M${x + r} ${y}h${w - 2 * r}a${r} ${r} 0 0 1 ${r} ${r}v${h - 2 * r}a${r} ${r} 0 0 1 ${-r} ${r}` +
    `h${-(w - 2 * r)}a${r} ${r} 0 0 1 ${-r} ${-r}v${-(h - 2 * r)}a${r} ${r} 0 0 1 ${r} ${-r}z`
  );
}

export const ICONS = {
  search: `${circle(11, 11, 7)}M20 20l-3.5-3.5`,
  copy: `${rect(9, 9, 12, 12, 2)}M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1`,
  eye: `M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z${circle(12, 12, 3)}`,
  eyeOff:
    "M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6C3.9 8.4 2 12 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2",
  key: `${circle(8, 15, 4)}M10.8 12.2 20 3M16 7l3 3M14 9l2 2`,
  lock: `${rect(5, 11, 14, 10, 2)}M8 11V7a4 4 0 0 1 8 0v4`,
  settings: `M4 6h9m4 0h3M4 12h3m4 0h9M4 18h11m4 0h1${circle(15, 6, 2)}${circle(9, 12, 2)}${circle(17, 18, 2)}`,
  back: "M15 18l-6-6 6-6",
  chevron: "M9 18l6-6-6-6",
  plus: "M12 5v14M5 12h14",
  external: "M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  check: "M5 12l5 5 9-10",
  edit: "M4 20h4L19 9l-4-4L4 16v4zM14 6l4 4",
  trash: "M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7",
  close: "M6 6l12 12M18 6 6 18",
  user: `${circle(12, 8, 4)}M4 21a8 8 0 0 1 16 0`,
  globe: `${circle(12, 12, 9)}M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18`,
  folder: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  card: `${rect(3, 5, 18, 14, 2)}M3 10h18M7 15h4`,
  note: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6",
  terminal: `${rect(3, 4, 18, 16, 2)}M7 9l3 3-3 3M13 15h4`,
  file: "M6 3h9l4 4v14H6zM14 3v5h5",
  sparkle: "M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6",
  clock: `${circle(12, 12, 9)}M12 7v5l3 2`,
  alert: "M12 3 2 20h20zM12 10v4M12 17v.01",
  fill: "M4 12h11M11 8l4 4-4 4M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3",
} as const;

export type IconName = keyof typeof ICONS;
