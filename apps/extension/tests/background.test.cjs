const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const root = path.resolve(__dirname, "..");
const flush = () => new Promise((resolve) => setImmediate(resolve));

// Exercise the production background listeners without a live native host or browser.
function background(engine) {
  const listeners = {};
  const entries = [];
  const marked = [];
  const navigations = [];
  const timers = [];
  const rules = new Map();
  let unlocked = true;
  let now = 10_000;
  let requestId = 0;
  class AgentError extends Error {
    constructor(code) {
      super(code);
      this.code = code;
    }
  }
  // Prefixes, `scheme://*.parent` wildcards, and sites as the last two labels.
  const covers = (pattern, url) => {
    if (!pattern.includes("*.")) return url.startsWith(pattern);
    const p = new URL(pattern);
    const t = new URL(url);
    const parent = p.hostname.slice(2);
    return p.protocol === t.protocol && (t.hostname === parent || t.hostname.endsWith(`.${parent}`));
  };
  const site = (url) => new URL(url.replace("*.", "")).hostname.split(".").slice(-2).join(".");
  const meta = (e) => ({ title: e.id, folder: "", urls: e.urls, basic_auth: e.marked });
  const agent = {
    async matches(url, { site: sameSite = false } = {}) {
      if (!unlocked) throw new AgentError("locked");
      const here = entries.filter((e) => e.urls.some((u) => covers(u, url)));
      const others = sameSite
        ? entries.filter((e) => !here.includes(e) && e.urls.some((u) => site(u) === site(url)))
        : [];
      return [...here, ...others].map((e) => ({ id: e.id, revision: e.revision, meta: meta(e) }));
    },
    async site(url) {
      return site(url);
    },
    async get(id) {
      if (!unlocked) throw new AgentError("locked");
      const e = entries.find((e) => e.id === id);
      return { id, revision: e.revision, meta: meta(e), body: { login: { username: id, password: e.password, notes: "" } } };
    },
    async update({ selector, revision, urls }) {
      if (!unlocked) throw new AgentError("locked");
      const e = entries.find((e) => e.id === selector);
      if (revision !== e.revision) throw new AgentError("stale");
      if (urls) e.urls = urls;
      e.revision++;
      return { id: e.id, revision: e.revision, meta: meta(e) };
    },
    async credentials(id) {
      if (!unlocked) throw new AgentError("locked");
      const e = entries.find((e) => e.id === id);
      return { id, path: id, username: id, password: e.password, basicAuth: e.marked };
    },
    async markBasicAuth(id) {
      marked.push(id);
      entries.find((e) => e.id === id).marked = true;
    },
    async status() { return { unlocked }; },
    async call(request) {
      if (request.method === "lock") unlocked = false;
      if (request.method === "unlock") unlocked = true;
      return { status: { unlocked } };
    },
  };
  const event = (name) => ({ addListener(fn) { listeners[name] = fn; } });
  const browser = {
    webRequest: Object.fromEntries([
      "onBeforeSendHeaders", "onHeadersReceived", "onAuthRequired", "onBeforeRequest", "onCompleted", "onErrorOccurred",
    ].map((name) => [name, event(name)])),
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    tabs: {
      onRemoved: event("removed"),
      update: async (_id, options) => navigations.push(options.url),
    },
    runtime: {
      id: "test-extension",
      getURL: (url) => `moz-extension://test${url}`,
      onMessage: event("message"),
    },
  };
  class HeaderRules {
    async reset() { rules.clear(); }
    async set(origin, value) { rules.set(origin, value); }
    async remove(origin) { rules.delete(origin); }
    async clear() { rules.clear(); }
  }
  const stubs = {
    "wxt/browser": { browser },
    "@/lib/agent": {
      Agent: class { constructor() { return agent; } },
      AgentError,
      BridgeError: class extends Error {},
    },
    "@/lib/header-rules": { HeaderRules },
    "@/lib/settings": {},
  };
  const cache = new Map();
  function load(file) {
    if (cache.has(file)) return cache.get(file);
    const source = fs.readFileSync(file, "utf8").replaceAll("import.meta.env.", "__env.");
    const js = ts.transpileModule(source, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    const exports = {};
    cache.set(file, exports);
    vm.runInNewContext(js, {
      exports,
      require(name) {
        if (name in stubs) return stubs[name];
        assert.ok(name.startsWith("@/"), `unexpected import: ${name}`);
        return load(path.join(root, `${name.slice(2)}.ts`));
      },
      defineBackground: (config) => config,
      __env: { FIREFOX: engine === "firefox", SAFARI: engine === "safari" },
      URL, TextEncoder, btoa, crypto: require("node:crypto").webcrypto,
      Date: class extends Date { static now() { return now; } },
      setInterval: (fn) => timers.push(fn),
    }, { filename: file });
    return exports;
  }
  load(path.join(root, "entrypoints/background.ts")).default.main();

  const request = (url, extra = {}) => ({
    requestId: String(++requestId), url, method: "GET", type: "main_frame", tabId: 1, ...extra,
  });
  const send = (message) => new Promise((resolve) => listeners.message(
    message, { id: browser.runtime.id, url: "moz-extension://test/popup.html" }, resolve,
  ));
  async function challenge(details, realm = "site", scheme = "basic") {
    const response = {
      ...details, statusCode: 401, isProxy: false, realm, scheme,
      responseHeaders: [{ name: "WWW-Authenticate", value: `${scheme} realm="${realm}"` }],
    };
    if (engine === "firefox") return listeners.onHeadersReceived(response);
    if (engine === "safari") {
      listeners.onHeadersReceived(response);
      await flush();
      return { redirectUrl: navigations.at(-1) };
    }
    return new Promise((resolve) => listeners.onAuthRequired(response, resolve));
  }
  async function outgoing(details) {
    if (engine === "firefox") return listeners.onBeforeSendHeaders(details);
    listeners.onBeforeRequest(details);
    await flush();
    return { requestHeaders: [{ name: "Authorization", value: rules.get(new URL(details.url).origin) }] };
  }
  function complete(details, statusCode = 200) {
    listeners.onCompleted({ ...details, statusCode });
  }
  return {
    entries, marked, agent, request, send, challenge, outgoing, complete, rules,
    fail(details) { listeners.onErrorOccurred(details); },
    add(id, url, options = {}) { entries.push({ id, urls: [url], revision: 1, password: `password-${id}`, ...options }); },
    lock() { unlocked = false; },
    unlock() { unlocked = true; },
    advance() { now += 3_000; },
    async poll() { for (const fn of timers) fn(); await flush(); },
    async refused(origin) { return Array.from((await send({ kind: "basic_auth", origin })).refused); },
    asked(result) { return engine === "chromium" ? navigations.at(-1)?.includes("/auth.html") : result.redirectUrl?.includes("/auth.html"); },
    /** The id of the auth page a challenge was sent to. */
    authId(result) {
      const page = engine === "chromium" ? navigations.at(-1) : result.redirectUrl;
      return new URL(page).searchParams.get("id");
    },
  };
}

const origin = "https://example.test";
const url = `${origin}/private/page`;

for (const engine of ["firefox", "chromium", "safari"]) {
  test(`${engine}: retries another login and learns it after answering Basic Auth`, async () => {
    const s = background(engine);
    s.add("app", origin);
    s.add("gate", origin);
    await s.challenge(s.request(url));
    const wrong = s.request(url);
    await s.outgoing(wrong);
    await s.challenge(wrong);
    const correct = s.request(url);
    const sent = await s.outgoing(correct);
    assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("gate:password-gate")}`);
    s.complete(correct);
    await flush();
    assert.deepEqual(s.marked, ["gate"]);
    assert.deepEqual(await s.refused(origin), ["app"]);
  });

  for (const lockDetection of ["poll", "challenge"]) {
    test(`${engine}: ${lockDetection} clears refusals after the last session ends`, async () => {
      const s = background(engine);
      s.add("gate", origin);
      await s.challenge(s.request(url));
      const retry = s.request(url);
      await s.outgoing(retry);
      assert.ok(s.asked(await s.challenge(retry)));
      assert.deepEqual(await s.refused(origin), ["gate"]);
      s.lock();
      if (lockDetection === "poll") await s.poll();
      else await s.challenge(s.request(url));
      assert.deepEqual(await s.refused(origin), []);
      s.unlock();
      assert.ok(!s.asked(await s.challenge(s.request(url))));
      const sent = await s.outgoing(s.request(url));
      assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("gate:password-gate")}`);
    });
  }

  test(`${engine}: a different realm cannot blacklist a valid login`, async () => {
    const s = background(engine);
    const docs = `${origin}/docs/page`;
    const admin = `${origin}/admin/page`;
    s.add("docs", `${origin}/docs/`);
    s.add("admin", `${origin}/admin/`);
    await s.challenge(s.request(docs), "docs");
    const docsLoad = s.request(docs);
    await s.outgoing(docsLoad);
    s.complete(docsLoad);
    const adminLoad = s.request(admin);
    await s.outgoing(adminLoad);
    await s.challenge(adminLoad, "admin");
    const adminRetry = s.request(admin);
    await s.outgoing(adminRetry);
    s.complete(adminRetry);
    s.advance();
    const docsReturn = s.request(docs);
    await s.outgoing(docsReturn);
    assert.equal(s.marked.includes("docs"), true);
    // A challenge on the original realm must still be able to select its login.
    assert.ok(!s.asked(await s.challenge(s.request(docs), "docs")));
    const sent = await s.outgoing(s.request(docs));
    assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("docs:password-docs")}`);
  });

  test(`${engine}: public navigation never marks the app login as Basic Auth`, async () => {
    const s = background(engine);
    const publicUrl = `${origin}/login`;
    s.add("gate", `${origin}/private/`);
    s.add("app", publicUrl);
    await s.challenge(s.request(url));
    const privateLoad = s.request(url);
    await s.outgoing(privateLoad);
    s.complete(privateLoad);
    s.advance();
    const publicLoad = s.request(publicUrl);
    await s.outgoing(publicLoad);
    s.complete(publicLoad);
    await flush();
    assert.deepEqual(s.marked, ["gate"]);
  });

  test(`${engine}: redirecting to a public URL cannot prove challenge acceptance`, async () => {
    const s = background(engine);
    s.add("gate", origin);
    await s.challenge(s.request(url));
    const retry = s.request(url);
    await s.outgoing(retry);
    const redirected = { ...retry, url: `${origin}/public` };
    await s.outgoing(redirected);
    s.complete(redirected);
    await flush();
    assert.deepEqual(s.marked, []);
  });

  test(`${engine}: error response does not teach a Basic Auth flag`, async () => {
    const s = background(engine);
    s.add("gate", origin);
    await s.challenge(s.request(url));
    const retry = s.request(url);
    await s.outgoing(retry);
    s.complete(retry, 500);
    await flush();
    assert.deepEqual(s.marked, []);
  });
}

for (const engine of ["firefox", "chromium", "safari"]) {
  test(`${engine}: refuses the same credentials throughout a known realm`, async () => {
    const s = background(engine);
    s.add("wrong", origin);
    await s.challenge(s.request(url), "shared");
    const retry = s.request(url);
    await s.outgoing(retry);
    assert.ok(s.asked(await s.challenge(retry, "shared")));
    assert.ok(s.asked(await s.challenge(s.request(`${origin}/other/path`), "shared")));
  });

  test(`${engine}: a changed password is retried after refusal`, async () => {
    const s = background(engine);
    s.add("gate", origin);
    await s.challenge(s.request(url));
    const retry = s.request(url);
    await s.outgoing(retry);
    await s.challenge(retry);
    s.entries[0].password = "new-password";
    assert.ok(!s.asked(await s.challenge(s.request(url))));
    const sent = await s.outgoing(s.request(url));
    assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("gate:new-password")}`);
  });

  test(`${engine}: stops after three saved-login refusals`, async () => {
    const s = background(engine);
    for (let i = 1; i <= 4; i++) s.add(`login${i}`, origin);
    await s.challenge(s.request(url));
    for (let i = 1; i <= 3; i++) {
      const retry = s.request(url);
      const sent = await s.outgoing(retry);
      assert.equal(sent.requestHeaders[0].value, `Basic ${btoa(`login${i}:password-login${i}`)}`);
      const result = await s.challenge(retry);
      assert.equal(Boolean(s.asked(result)), i === 3);
    }
    assert.deepEqual(await s.refused(origin), ["login1", "login2", "login3"]);
  });

  for (const lockDetection of ["popup", "poll"]) {
    test(`${engine}: ${lockDetection} prevents an earlier lookup from restoring credentials`, async () => {
      const s = background(engine);
      s.add("gate", origin);
      let release, entered;
      const delayed = new Promise((resolve) => { release = resolve; });
      const started = new Promise((resolve) => { entered = resolve; });
      const credentials = s.agent.credentials;
      s.agent.credentials = async (id) => {
        const result = await credentials(id);
        entered();
        await delayed;
        return result;
      };
      const loading = s.challenge(s.request(url));
      await started;
      if (lockDetection === "popup") await s.send({ kind: "agent", request: { method: "lock" } });
      else { s.lock(); await s.poll(); }
      release();
      await loading;
      await flush();
      const sent = await s.outgoing(s.request(url));
      assert.ok(!sent.requestHeaders?.some((h) => h.value));
      assert.equal(s.rules.size, 0);
      assert.deepEqual(s.marked, []);
    });

  }

  test(`${engine}: a failed request cannot later learn the Basic Auth flag`, async () => {
    const s = background(engine);
    s.add("gate", origin);
    await s.challenge(s.request(url));
    const retry = s.request(url);
    await s.outgoing(retry);
    s.fail(retry);
    s.complete(retry);
    await flush();
    assert.deepEqual(s.marked, []);
  });
}

const dev = "https://id.dev.example.test";
const devUrl = `${dev}/home`;

for (const engine of ["firefox", "chromium", "safari"]) {
  test(`${engine}: links a login of another host and keeps the link once the site accepts it`, async () => {
    const s = background(engine);
    s.add("shared", "https://admin.dev.example.test");
    s.add("elsewhere", "https://other.test");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    const options = await s.send({ kind: "challenge_logins", id });
    assert.equal(options.kind, "link_options");
    assert.deepEqual(
      Array.from(options.logins, (o) => [o.id, Array.from(o.hosts), o.wildcard]),
      [["shared", ["admin.dev.example.test"], null]],
    );
    const linked = await s.send({ kind: "challenge_link", id, login: "shared", revision: 1, wildcard: null });
    assert.deepEqual({ ...linked }, { kind: "continue", url: devUrl });
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", dev]);
    const load = s.request(devUrl);
    const sent = await s.outgoing(load);
    assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("shared:password-shared")}`);
    s.complete(load);
    await flush();
    assert.deepEqual(s.marked, ["shared"]);
    // Accepted: a later refusal no longer takes the link back.
    s.advance();
    const later = s.request(devUrl);
    await s.outgoing(later);
    await s.challenge(later);
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", dev]);
  });

  test(`${engine}: undoes a link the site refuses and stops offering that login`, async () => {
    const s = background(engine);
    s.add("shared", "https://admin.dev.example.test");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    await s.send({ kind: "challenge_link", id, login: "shared", revision: 1, wildcard: null });
    const retry = s.request(devUrl);
    await s.outgoing(retry);
    const result = await s.challenge(retry);
    assert.ok(s.asked(result));
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test"]);
    assert.deepEqual(s.marked, []);
    const options = await s.send({ kind: "challenge_logins", id: s.authId(result) });
    assert.deepEqual(Array.from(options.logins), []);
  });

  test(`${engine}: widens a login on sibling hosts to a wildcard`, async () => {
    const s = background(engine);
    s.add("shared", "https://admin.dev.example.test");
    s.entries[0].urls.push("https://test.dev.example.test", "admin.dev.example.test", "https://example.test/x");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    const options = await s.send({ kind: "challenge_logins", id });
    assert.equal(options.logins[0].wildcard, "https://*.dev.example.test");
    await s.send({ kind: "challenge_link", id, login: "shared", revision: 1, wildcard: "https://*.dev.example.test" });
    assert.deepEqual(Array.from(s.entries[0].urls), [
      "admin.dev.example.test",
      "https://example.test/x",
      "https://*.dev.example.test",
    ]);
    const sent = await s.outgoing(s.request(devUrl));
    assert.equal(sent.requestHeaders[0].value, `Basic ${btoa("shared:password-shared")}`);
  });

  test(`${engine}: only links a login offered for the challenge`, async () => {
    const s = background(engine);
    s.add("elsewhere", "https://other.test");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    const reply = await s.send({ kind: "challenge_link", id, login: "elsewhere", revision: 1, wildcard: null });
    assert.equal(reply.kind, "error");
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://other.test"]);
  });

  test(`${engine}: does not link a login edited since the page showed it`, async () => {
    const s = background(engine);
    s.add("shared", "https://admin.dev.example.test");
    s.entries[0].urls.push("https://test.dev.example.test");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    const shown = (await s.send({ kind: "challenge_logins", id })).logins[0];
    assert.equal(shown.wildcard, "https://*.dev.example.test");
    // Edited elsewhere: the same request would now widen to the whole site.
    s.entries[0].urls = ["https://admin.dev.example.test", "https://www.example.test"];
    s.entries[0].revision++;
    const reply = await s.send({ kind: "challenge_link", id, login: "shared", revision: shown.revision, wildcard: shown.wildcard });
    assert.equal(reply.kind, "link_changed");
    assert.equal(reply.logins[0].wildcard, "https://*.example.test");
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", "https://www.example.test"]);
    // Only the wildcard shown is accepted, even at the current revision.
    const again = await s.send({ kind: "challenge_link", id, login: "shared", revision: 2, wildcard: shown.wildcard });
    assert.equal(again.kind, "link_changed");
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", "https://www.example.test"]);
  });

  test(`${engine}: a refusal in another realm keeps the link`, async () => {
    const s = background(engine);
    s.add("shared", "https://admin.dev.example.test");
    const id = s.authId(await s.challenge(s.request(devUrl)));
    await s.send({ kind: "challenge_link", id, login: "shared", revision: 1, wildcard: null });
    const load = s.request(devUrl);
    await s.outgoing(load);
    // A subresource in another realm refuses it before the page completes.
    const api = s.request(`${dev}/admin/api`, { type: "xmlhttprequest" });
    await s.outgoing(api);
    await s.challenge(api, "admin-only");
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", dev]);
    s.complete(load);
    await flush();
    assert.deepEqual(Array.from(s.entries[0].urls), ["https://admin.dev.example.test", dev]);
    assert.deepEqual(s.marked, ["shared"]);
  });
}
