const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.resolve(__dirname, "../lib/site.ts"), "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const site = {};
vm.runInNewContext(js, { exports: site, URL });
const widen = (patterns, target) => {
  const result = site.widening(patterns, target);
  return result && { wildcard: result.wildcard, replaces: Array.from(result.replaces) };
};

test("widens two sibling hosts and the target to their parent", () => {
  assert.deepEqual(
    widen(["https://admin.dev.example.com", "https://test.dev.example.com/x"], "https://id.dev.example.com/"),
    {
      wildcard: "https://*.dev.example.com",
      replaces: ["https://admin.dev.example.com", "https://test.dev.example.com/x"],
    },
  );
});

test("needs two sibling hosts", () => {
  assert.equal(widen(["https://admin.dev.example.com"], "https://id.dev.example.com/"), null);
  assert.equal(
    widen(["https://admin.dev.example.com", "https://admin.dev.example.com/other"], "https://id.dev.example.com/"),
    null,
  );
});

test("prefers the most specific parent and leaves other hosts alone", () => {
  assert.deepEqual(
    widen(
      ["https://a.dev.example.com", "https://b.dev.example.com", "https://www.example.com", "https://x.other.com"],
      "https://c.dev.example.com",
    ),
    { wildcard: "https://*.dev.example.com", replaces: ["https://a.dev.example.com", "https://b.dev.example.com"] },
  );
});

test("keeps scheme and port, and never replaces broader patterns", () => {
  assert.deepEqual(
    widen(
      ["https://a.dev.example.com:8443", "https://b.dev.example.com:8443", "https://c.dev.example.com", "d.dev.example.com"],
      "https://id.dev.example.com:8443/",
    ),
    {
      wildcard: "https://*.dev.example.com:8443",
      replaces: ["https://a.dev.example.com:8443", "https://b.dev.example.com:8443"],
    },
  );
  assert.equal(widen(["http://a.dev.example.com", "http://b.dev.example.com"], "https://id.dev.example.com"), null);
});

test("never widens to a public suffix, a bare label or an address", () => {
  assert.equal(widen(["https://a.co.uk", "https://b.co.uk"], "https://c.co.uk"), null);
  assert.equal(widen(["https://a.com", "https://b.com"], "https://c.com"), null);
  assert.equal(widen(["http://10.0.0.1", "http://10.0.0.2"], "http://10.0.0.3"), null);
  assert.equal(widen(["http://a.localhost", "http://b.localhost"], "http://localhost"), null);
  assert.deepEqual(widen(["https://a.example.co.uk", "https://b.example.co.uk"], "https://c.example.co.uk"), {
    wildcard: "https://*.example.co.uk",
    replaces: ["https://a.example.co.uk", "https://b.example.co.uk"],
  });
});

test("lists the hosts of patterns", () => {
  assert.deepEqual(
    Array.from(site.patternHosts(["https://A.example.com/x", "b.example.com:8080", "*.c.example.com", "https://A.example.com"])),
    ["a.example.com", "b.example.com", "*.c.example.com"],
  );
});
