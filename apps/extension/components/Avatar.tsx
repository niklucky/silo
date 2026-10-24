import { avatarFor } from "@/lib/avatar";

export function Avatar({ label, large = false }: { label: string; large?: boolean }) {
  const { letter, color } = avatarFor(label);
  return (
    <span className={large ? "avatar large" : "avatar"} style={{ background: color }} aria-hidden="true">
      {letter}
    </span>
  );
}
