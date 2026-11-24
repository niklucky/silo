/**
 * In-memory vault with made-up data, for the prototype and for UI work without
 * an agent. Any password unlocks it.
 */

import type { VaultClient } from "./client";
import type { NewSecret, SecretBody, SecretMeta, SecretSummary, SecretView, StatusInfo } from "./protocol";

const DAY = 86_400;

function b64(text: string): string {
  return btoa(unescape(encodeURIComponent(text)));
}

const DIAGRAM = `<svg xmlns="http://www.w3.org/2000/svg" width="480" height="240" viewBox="0 0 480 240">
<rect width="480" height="240" rx="16" fill="#1d7a4c"/>
<g fill="none" stroke="#e2f3e9" stroke-width="3">
<rect x="40" y="90" width="110" height="60" rx="10"/><rect x="185" y="90" width="110" height="60" rx="10"/><rect x="330" y="90" width="110" height="60" rx="10"/>
<path d="M150 120h35M295 120h35"/></g>
<g fill="#e2f3e9" font-family="system-ui" font-size="15" text-anchor="middle">
<text x="95" y="125">client</text><text x="240" y="125">api</text><text x="385" y="125">postgres</text></g></svg>`;

const SEED: { meta: Omit<SecretMeta, "created_at" | "updated_at">; body: SecretBody; age: number }[] = [
  {
    meta: { title: "GitHub", kind: "login", folder: "work", tags: ["dev"], urls: ["https://github.com"] },
    body: { login: { username: "alex@example.com", password: "Rosedu7-fanipo-Bakomi", totp: "JBSWY3DPEHPK3PXP", notes: "" } },
    age: 3,
  },
  {
    meta: { title: "GitHub", kind: "login", folder: "work", tags: ["dev"], urls: ["https://github.com"] },
    body: { login: { username: "acme-deploy-bot", password: "Hosimu-4-rakelo", totp: null, notes: "Machine user for CI." } },
    age: 20,
  },
  {
    meta: { title: "Staging", kind: "login", folder: "work", tags: ["dev"], urls: ["https://*.staging.acme.dev"], basic_auth: true },
    body: { login: { username: "acme", password: "kV9#pq2!xLm4", totp: null, notes: "Shared Basic Auth for every staging host." } },
    age: 40,
  },
  {
    meta: { title: "Grafana", kind: "login", folder: "work", tags: ["ops"], urls: ["https://grafana.acme.dev"] },
    body: { login: { username: "alex", password: "Tuvela-8-hosimu", totp: null, notes: "" } },
    age: 12,
  },
  {
    meta: { title: "AWS console", kind: "login", folder: "work", tags: ["ops", "cloud"], urls: ["https://signin.aws.amazon.com"] },
    body: { login: { username: "alex.admin", password: "q7$Lz!m2Pw9e", totp: "GEZDGNBVGY3TQOJQ", notes: "Account 1234-5678-9012" } },
    age: 90,
  },
  {
    meta: { title: "Google", kind: "login", folder: "personal", urls: ["https://accounts.google.com"] },
    body: { login: { username: "alex.doe@gmail.com", password: "Fanipo-rosedu-77", totp: null, notes: "" } },
    age: 200,
  },
  {
    meta: { title: "Netflix", kind: "login", folder: "family", tags: ["shared"], urls: ["https://netflix.com"] },
    body: { login: { username: "family@example.com", password: "movienight-2026", totp: null, notes: "" } },
    age: 15,
  },
  {
    meta: { title: "Home Wi-Fi", kind: "note", folder: "family", tags: ["shared"] },
    body: { note: { text: "Network: Doe-5G\nPassword: lemon-tree-42\n\nGuest network: Doe-Guest / welcome-home" } },
    age: 300,
  },
  {
    meta: { title: "Personal Visa", kind: "card", folder: "personal" },
    body: { card: { holder: "ALEX DOE", number: "4111111111111111", expiry_month: 8, expiry_year: 2029, cvv: "123", notes: "" } },
    age: 60,
  },
  {
    meta: { title: "Company Amex", kind: "card", folder: "work", tags: ["expenses"] },
    body: { card: { holder: "ALEX DOE", number: "378282246310005", expiry_month: 2, expiry_year: 2028, cvv: "4321", notes: "Travel and SaaS only." } },
    age: 120,
  },
  {
    meta: { title: "dev", kind: "env_set", folder: "projects/wallet", tags: ["env"] },
    body: {
      env_set: {
        vars: [
          { key: "DATABASE_URL", value: "postgres://wallet:wallet@localhost:5432/wallet" },
          { key: "REDIS_URL", value: "redis://localhost:6379/0" },
          { key: "STRIPE_SECRET_KEY", value: "sk_test_51Hx0cZ2eZvKYlo2C" },
          { key: "JWT_SECRET", value: "dev-only-not-secret" },
          { key: "LOG_LEVEL", value: "debug" },
        ],
      },
    },
    age: 2,
  },
  {
    meta: { title: "production", kind: "env_set", folder: "projects/wallet", tags: ["env", "prod"] },
    body: {
      env_set: {
        vars: [
          { key: "DATABASE_URL", value: "postgres://wallet:Zq81!xP@db.internal:5432/wallet" },
          { key: "REDIS_URL", value: "rediss://cache.internal:6380/0" },
          { key: "STRIPE_SECRET_KEY", value: "sk_live_51Hx0cZ2eZvKYlo2Cq9" },
          { key: "JWT_SECRET", value: "c8f1e0a2b7d94e3f8a6b1c2d3e4f5a6b" },
          { key: "LOG_LEVEL", value: "info" },
        ],
      },
    },
    age: 9,
  },
  {
    meta: { title: "service-account.json", kind: "file", folder: "projects/wallet", tags: ["gcp"] },
    body: {
      file: {
        name: "service-account.json",
        mime: "application/json",
        data: b64(
          JSON.stringify(
            { type: "service_account", project_id: "wallet-prod", client_email: "deploy@wallet-prod.iam.gserviceaccount.com", private_key_id: "3f2a…" },
            null,
            2,
          ),
        ),
      },
    },
    age: 30,
  },
  {
    meta: { title: "architecture.svg", kind: "file", folder: "projects/wallet" },
    body: { file: { name: "architecture.svg", mime: "image/svg+xml", data: b64(DIAGRAM) } },
    age: 31,
  },
  {
    meta: { title: "dev", kind: "env_set", folder: "projects/api", tags: ["env"] },
    body: { env_set: { vars: [{ key: "PORT", value: "8080" }, { key: "DATABASE_URL", value: "postgres://api@localhost/api" }, { key: "OPENAI_API_KEY", value: "sk-proj-dev-a1b2c3" }] } },
    age: 5,
  },
  {
    meta: { title: "staging", kind: "env_set", folder: "projects/api", tags: ["env"] },
    body: { env_set: { vars: [{ key: "PORT", value: "8080" }, { key: "DATABASE_URL", value: "postgres://api:s3cr3t@staging-db/api" }, { key: "OPENAI_API_KEY", value: "sk-proj-stg-d4e5f6" }] } },
    age: 7,
  },
  {
    meta: { title: "Runbook", kind: "note", folder: "projects/api" },
    body: { note: { text: "Rotate keys every 90 days.\n\n1. silo get projects/api/staging\n2. Update the key in the provider\n3. silo edit projects/api/staging" } },
    age: 45,
  },
  {
    meta: { title: "dev", kind: "env_set", folder: "projects/blog", tags: ["env"] },
    body: { env_set: { vars: [{ key: "CMS_TOKEN", value: "cms_live_9x8y7z" }, { key: "SITE_URL", value: "http://localhost:4321" }] } },
    age: 70,
  },
  {
    meta: { title: "id_ed25519", kind: "file", folder: "ssh", tags: ["ssh"] },
    body: {
      file: {
        name: "id_ed25519",
        mime: null,
        data: b64("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDemoDemoDemoDemoDemoDemoDemoDemoDemoDemoDemoAAAA\n-----END OPENSSH PRIVATE KEY-----\n"),
      },
    },
    age: 400,
  },
  {
    meta: { title: "Recovery codes", kind: "note", folder: "personal", tags: ["2fa"] },
    body: { note: { text: "GitHub\n  4f2a-81bc  9d0e-77aa  12cd-3e4f\n\nGoogle\n  8812 4410  5531 0092" } },
    age: 150,
  },
];

export function createMockClient(): VaultClient {
  const now = Math.floor(Date.now() / 1000);
  const store = new Map<string, SecretView[]>();
  let unlocked = false;
  let next = 1;

  const id = () => `00000000-0000-4000-8000-${String(next++).padStart(12, "0")}`;
  for (const seed of SEED) {
    const at = now - seed.age * DAY;
    const view: SecretView = { id: id(), revision: 1, meta: { ...seed.meta, created_at: at - 30 * DAY, updated_at: at }, body: seed.body };
    store.set(view.id, [view]);
  }

  const delay = <T>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(structuredClone(value)), 60));
  const fail = (message: string, code?: string) => Promise.reject(Object.assign(new Error(message), { code }));
  let lastSync = now - 120;
  let biometricEnabled = false;
  const latest = (key: string) => store.get(key)?.[0];
  const summary = ({ id, revision, meta }: SecretView): SecretSummary => ({ id, revision, meta });
  const status = (): StatusInfo => ({
    has_account: true,
    unlocked,
    fingerprint: "a1b2 c3d4 e5f6 0718",
    secrets: store.size,
    expires_in_secs: unlocked ? 3600 : null,
    biometric_available: true,
    biometric_enabled: biometricEnabled,
  });

  return {
    status: () => delay(status()),
    async unlock(password) {
      if (!password) return fail("Enter your master password.");
      unlocked = true;
      return delay(status());
    },
    async unlockBiometric() {
      if (!biometricEnabled) return fail("Biometric unlock is not enabled.");
      unlocked = true;
      return delay(status());
    },
    async enableBiometric() {
      if (!unlocked) return fail("The vault is locked.", "locked");
      biometricEnabled = true;
      return delay(status());
    },
    async disableBiometric() {
      biometricEnabled = false;
      return delay(status());
    },
    async lock() {
      unlocked = false;
    },
    list() {
      if (!unlocked) return fail("The vault is locked.", "locked");
      return delay([...store.values()].map((revs) => summary(revs[0]!)));
    },
    get(key) {
      const view = latest(key);
      return view ? delay(view) : fail(`No secret ${key}.`);
    },
    add(secret: NewSecret) {
      const at = Math.floor(Date.now() / 1000);
      const view: SecretView = {
        id: id(),
        revision: 1,
        meta: {
          title: secret.title,
          kind: kindOf(secret.body),
          folder: secret.folder ?? "",
          tags: secret.tags ?? [],
          urls: secret.urls ?? [],
          basic_auth: secret.basic_auth,
          created_at: at,
          updated_at: at,
        },
        body: secret.body,
      };
      store.set(view.id, [view]);
      return delay(summary(view));
    },
    update(update) {
      const revs = store.get(update.selector);
      const current = revs?.[0];
      if (!revs || !current) return fail(`No secret ${update.selector}.`);
      if (update.revision !== undefined && update.revision !== current.revision) {
        return fail("Changed in the meantime; reload and try again.");
      }
      const view: SecretView = {
        id: current.id,
        revision: current.revision + 1,
        meta: {
          ...current.meta,
          title: update.title ?? current.meta.title,
          folder: update.folder ?? current.meta.folder,
          tags: update.tags ?? current.meta.tags,
          urls: update.urls ?? current.meta.urls,
          basic_auth: update.basic_auth ?? current.meta.basic_auth,
          updated_at: Math.floor(Date.now() / 1000),
        },
        body: update.body ?? current.body,
      };
      revs.unshift(view);
      return delay(summary(view));
    },
    async remove(key) {
      store.delete(key);
    },
    history(key) {
      return delay(store.get(key)?.slice(1) ?? []);
    },
    syncStatus: () =>
      delay({ server: "https://silo.example.com", username: "alex", last_sync: lastSync, last_error: null, pending: unlocked ? 0 : null }),
    async sync() {
      await delay(null);
      lastSync = Math.floor(Date.now() / 1000);
    },
  };
}

function kindOf(body: SecretBody): SecretMeta["kind"] {
  if ("login" in body) return "login";
  if ("card" in body) return "card";
  if ("env_set" in body) return "env_set";
  if ("file" in body) return "file";
  return "note";
}
