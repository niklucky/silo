import { type IconName, ICONS } from "@/lib/icons";

export function Icon({ name, size = 16, strokeWidth = 2 }: { name: IconName; size?: number; strokeWidth?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      style={{ width: size, height: size }}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={ICONS[name]} />
    </svg>
  );
}

/** The Silo mark: a key on the accent color. */
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <span className="logo" style={{ width: size, height: size }}>
      <Icon name="key" size={Math.round(size * 0.64)} strokeWidth={2.6} />
    </span>
  );
}
