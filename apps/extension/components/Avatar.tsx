import { useEffect, useState } from "react";
import { avatarFor } from "@/lib/avatar";
import { faviconFor } from "@/lib/favicon";

export function Avatar({ label, website, large = false }: { label: string; website?: string | null; large?: boolean }) {
  const { letter, color } = avatarFor(label);
  const [icon, setIcon] = useState<{ website: string; png: string } | null>(null);
  useEffect(() => {
    if (!website) return;
    let live = true;
    void faviconFor(website).then((png) => {
      if (live) setIcon(png ? { website, png } : null);
    });
    return () => { live = false; };
  }, [website]);
  const png = icon?.website === website ? icon?.png : null;
  return (
    <span className={`${large ? "avatar large" : "avatar"}${png ? " favicon" : ""}`} style={{ background: png ? undefined : color }} aria-hidden="true">
      {png ? <img src={png} alt="" onError={() => setIcon(null)} /> : letter}
    </span>
  );
}
