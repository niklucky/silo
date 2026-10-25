import type { ReactNode } from "react";
import { browser } from "wxt/browser";
import { websiteUrl } from "@/lib/website";
import { Icon } from "./Icon";

export function WebsiteLink({ pattern, children, className = "url", iconOnly = false }: {
  pattern: string;
  children?: ReactNode;
  className?: string;
  iconOnly?: boolean;
}) {
  const href = websiteUrl(pattern);
  const label = children ?? pattern.replace(/^https:\/\//i, "").replace(/\/$/, "");
  if (!href) return <span className={className}>{label}</span>;
  return (
    <a
      className={className}
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${href}`}
      aria-label={iconOnly ? `Open ${href}` : undefined}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        void browser.tabs.create({ url: href }).then(() => window.close());
      }}
      onKeyDown={(event) => event.stopPropagation()}
    >
      {!iconOnly && label}
      <Icon name="external" size={12} />
    </a>
  );
}
