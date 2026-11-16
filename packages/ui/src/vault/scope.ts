import type { SecretKind, SecretSummary } from "../protocol";

/** What the sidebar has selected; the list shows the secrets in it. */
export type Scope =
  | { type: "all" }
  | { type: "kind"; kind: SecretKind }
  | { type: "folder"; path: string }
  | { type: "tag"; tag: string };

export function inScope(item: SecretSummary, scope: Scope): boolean {
  switch (scope.type) {
    case "all":
      return true;
    case "kind":
      return item.meta.kind === scope.kind;
    case "folder":
      return item.meta.folder === scope.path || item.meta.folder.startsWith(`${scope.path}/`);
    case "tag":
      return (item.meta.tags ?? []).includes(scope.tag);
  }
}

export function sameScope(a: Scope, b: Scope): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export interface FolderNode {
  name: string;
  path: string;
  /** Secrets here and below. */
  count: number;
  children: FolderNode[];
}

/** Folder tree of every secret's folder and its ancestors, sorted by name. */
export function folderTree(items: readonly SecretSummary[]): FolderNode[] {
  const root: FolderNode = { name: "", path: "", count: 0, children: [] };
  for (const item of items) {
    if (!item.meta.folder) continue;
    let node = root;
    for (const segment of item.meta.folder.split("/")) {
      const path = node.path ? `${node.path}/${segment}` : segment;
      let child = node.children.find((c) => c.name === segment);
      if (!child) {
        child = { name: segment, path, count: 0, children: [] };
        node.children.push(child);
      }
      child.count++;
      node = child;
    }
  }
  const sort = (nodes: FolderNode[]) => {
    nodes.sort((a, b) => a.name.localeCompare(b.name));
    nodes.forEach((n) => sort(n.children));
  };
  sort(root.children);
  return root.children;
}

export function allFolders(items: readonly SecretSummary[]): string[] {
  const set = new Set<string>();
  for (const item of items) {
    const parts = item.meta.folder ? item.meta.folder.split("/") : [];
    for (let i = 1; i <= parts.length; i++) set.add(parts.slice(0, i).join("/"));
  }
  return [...set].sort();
}

export function allTags(items: readonly SecretSummary[]): { tag: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const item of items) for (const tag of item.meta.tags ?? []) counts.set(tag, (counts.get(tag) ?? 0) + 1);
  return [...counts].map(([tag, count]) => ({ tag, count })).sort((a, b) => a.tag.localeCompare(b.tag));
}

export function scopeTitle(scope: Scope): string {
  switch (scope.type) {
    case "all":
      return "All items";
    case "kind":
      return { login: "Logins", card: "Cards", env_set: "Environments", file: "Files", note: "Notes" }[scope.kind];
    case "folder":
      return scope.path.split("/").pop() ?? scope.path;
    case "tag":
      return `#${scope.tag}`;
  }
}
