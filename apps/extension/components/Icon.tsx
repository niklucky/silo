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

/** The Silo sign: a password field with two asterisks. `size` is its width. */
export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg className="logo" width={size} height={Math.round((size * 548) / 968)} viewBox="0 0 968 548" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M110 0H858A110 110 0 0 1 968 110V438A110 110 0 0 1 858 548H110A110 110 0 0 1 0 438V110A110 110 0 0 1 110 0ZM110 76A34 34 0 0 0 76 110V438A34 34 0 0 0 110 472H858A34 34 0 0 0 892 438V110A34 34 0 0 0 858 76Z"
      />
      <path transform="translate(310 274)" d={STAR} />
      <path transform="translate(660 274)" d={STAR} />
    </svg>
  );
}

const STAR = "M-35-140H35V-60L108-106L143-47L70 0L143 47L108 106L35 60V140H-35V60L-108 106L-143 47L-70 0L-143-47L-108-106L-35-60Z";
