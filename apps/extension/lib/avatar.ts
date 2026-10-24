/** A letter and a color for a secret, from its site or title, so rows are told apart at a glance. */
export interface AvatarLook {
  letter: string;
  color: string;
}

export function avatarFor(label: string): AvatarLook {
  const clean = label.trim().replace(/^(https?:\/\/)?(\*\.)?(www\.)?/i, "");
  const letter = [...clean].find((c) => /[\p{L}\p{N}]/u.test(c)) ?? "?";
  let hash = 0;
  for (const c of clean.toLowerCase()) hash = (hash * 31 + (c.codePointAt(0) ?? 0)) >>> 0;
  // Mid lightness and saturation: white text stays readable in light and dark themes.
  return { letter, color: `hsl(${hash % 360} 45% 45%)` };
}
