const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.resolve(__dirname, "../lib/website.ts"), "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const { websiteUrl, firstWebsite } = vm.runInNewContext(`${js}\nexports`, { exports: {}, URL });

test("website links preserve hosts, ports, paths and HTTP for local sites", () => {
  assert.equal(websiteUrl(" example.com/login?q=1#form "), "https://example.com/login?q=1#form");
  assert.equal(websiteUrl("http://localhost:8080/login"), "http://localhost:8080/login");
  assert.equal(websiteUrl("example.com:8443/path"), "https://example.com:8443/path");
  assert.equal(websiteUrl("[::1]:8080"), "https://[::1]:8080/");
});

test("a wildcard hostname opens the parent without altering the saved pattern", () => {
  assert.equal(websiteUrl("https://*.example.com:8443/login"), "https://example.com:8443/login");
  assert.equal(websiteUrl("*.example.com"), "https://example.com/");
  assert.equal(websiteUrl("https://example.com/*"), null);
});

test("invalid, non-web and credential-bearing addresses are not links or icon sources", () => {
  for (const pattern of ["", "not a url", "javascript:alert(1)", "data:text/html,hello", "file:///tmp/a", "ftp://example.com", "https://user:password@example.com", "https://*", "https://"])
    assert.equal(websiteUrl(pattern), null, pattern);
  assert.equal(firstWebsite(["file:///tmp/a", "https://*.example.com", "other.test"]), "https://example.com/");
  assert.equal(firstWebsite([]), null);
});
