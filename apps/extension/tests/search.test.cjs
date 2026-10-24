const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

function load(name, modules = {}) {
  const source = fs.readFileSync(path.resolve(__dirname, `../lib/${name}.ts`), "utf8");
  const js = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  vm.runInNewContext(js, { exports, URL, require: (id) => modules[id] });
  return exports;
}

const site = load("site");
const { search, hostsOf } = load("search", { "./site": site });

let n = 0;
const item = (title, { folder = "", urls = [], tags = [], kind = "login" } = {}) => ({
  id: String(n++),
  meta: { title, folder, urls, tags, kind, created_at: 0, updated_at: 0 },
});

const vault = [
  item("GitHub", { folder: "work", urls: ["https://github.com"], tags: ["dev"] }),
  item("gist", { folder: "work", urls: ["https://gist.github.com"] }),
  item("Staging admin", { folder: "projects/wallet", urls: ["https://admin.staging.wallet.io"] }),
  item("wallet API env", { folder: "projects/wallet", kind: "env_set" }),
  item("Bank", { folder: "personal", urls: ["https://www.mybank.com"], tags: ["money"] }),
  item("Docker Hub", { folder: "work", urls: ["hub.docker.com"] }),
];
const titles = (query) => Array.from(search(vault, query), (s) => s.meta.title);

test("an empty query lists everything by title", () => {
  assert.deepEqual(titles("  "), ["Bank", "Docker Hub", "gist", "GitHub", "Staging admin", "wallet API env"]);
});

test("finds by title and by a word inside it", () => {
  assert.deepEqual(titles("github"), ["GitHub", "gist"]);
  assert.deepEqual(titles("admin"), ["Staging admin"]);
});

test("a domain finds its logins first, then other hosts of the site", () => {
  assert.deepEqual(titles("github.com"), ["GitHub", "gist"]);
  assert.deepEqual(titles("mybank.com"), ["Bank"]);
});

// Sibling hosts need the public suffix list; the popup asks the agent for those.
test("a pasted URL searches by its host and its subdomains", () => {
  assert.deepEqual(titles("https://gist.github.com/me/abc"), ["gist", "GitHub"]);
  assert.deepEqual(titles("https://login.staging.wallet.io/x"), []);
  assert.deepEqual(titles("https://staging.wallet.io/x"), ["Staging admin"]);
});

test("every word must match, across folder, tag and host", () => {
  assert.deepEqual(titles("wallet api"), ["wallet API env"]);
  assert.deepEqual(titles("work dev"), ["GitHub"]);
  assert.deepEqual(titles("money"), ["Bank"]);
  assert.deepEqual(titles("docker"), ["Docker Hub"]);
  assert.deepEqual(titles("nothing-like-this"), []);
});

test("hosts drop www. and wildcard prefixes", () => {
  assert.deepEqual(
    Array.from(hostsOf({ urls: ["https://www.example.com/login", "https://*.dev.example.com", "example.com"] })),
    ["example.com", "dev.example.com"],
  );
});
