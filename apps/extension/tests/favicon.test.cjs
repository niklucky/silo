const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const compile = (name) => ts.transpileModule(fs.readFileSync(path.resolve(__dirname, `../lib/${name}.ts`), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const website = vm.runInNewContext(`${compile("website")}\nexports`, { exports: {}, URL });
const faviconJs = compile("favicon");
const origin = "https://icons.test";
const png = "data:image/png;base64,dGVzdA==";

function fixture(declarations) {
  const requests = [];
  let stored;
  const browser = { storage: { local: {
    get: async () => ({}),
    set: async (value) => { stored = value; },
  } } };
  const exports = {};
  vm.runInNewContext(faviconJs, {
    exports, URL, Blob, AbortController, setTimeout, clearTimeout,
    require: (name) => name === "wxt/browser" ? { browser } : website,
    fetch: async (url) => {
      requests.push(url);
      if (url === `${origin}/`) return new Response("<html></html>", { headers: { "content-type": "text/html" } });
      if (url === `${origin}/favicon.ico`) return new Response(new Uint8Array([1]), { headers: { "content-type": "image/x-icon" } });
      return new Response(null, { status: 404 });
    },
    DOMParser: class {
      parseFromString() {
        return { querySelectorAll: () => declarations.map((href) => ({ getAttribute: () => href })) };
      }
    },
    // Decoding is covered by the browser check; this fixture checks candidate selection and caching.
    Image: class {
      naturalWidth = 16;
      naturalHeight = 16;
      set src(value) { if (value) queueMicrotask(() => this.onload?.()); }
    },
    document: { createElement: () => ({ getContext: () => ({ drawImage() {} }), toDataURL: () => png }) },
  });
  return { load: exports.faviconFor, requests, stored: () => stored };
}

test("reserves the fourth icon attempt for favicon.ico when many declared icons fail", async () => {
  const f = fixture(["/missing-1.png", "/missing-2.png", "/missing-3.png", "/missing-4.png", "/missing-5.png"]);
  assert.equal(await f.load(`${origin}/login`), png);
  assert.deepEqual(f.requests, [`${origin}/`, `${origin}/missing-1.png`, `${origin}/missing-2.png`, `${origin}/missing-3.png`, `${origin}/favicon.ico`]);
  assert.equal(f.stored()["website-favicons-v1"][origin].png, png);
  assert.equal(await f.load(`${origin}/other`), png);
  assert.equal(f.requests.length, 5, "successful fallback is cached");
});

test("duplicate declarations do not consume the reserved fallback slot", async () => {
  const f = fixture(["/missing-1.png", "/missing-1.png", "/missing-2.png", "/missing-3.png", "/missing-4.png"]);
  assert.equal(await f.load(origin), png);
  assert.deepEqual(f.requests, [`${origin}/`, `${origin}/missing-1.png`, `${origin}/missing-2.png`, `${origin}/missing-3.png`, `${origin}/favicon.ico`]);
});

test("preserves priority when the conventional icon is already declared first", async () => {
  const f = fixture(["/favicon.ico", "/favicon.ico", "/missing-1.png", "/missing-2.png", "/missing-3.png"]);
  assert.equal(await f.load(origin), png);
  assert.deepEqual(f.requests, [`${origin}/`, `${origin}/favicon.ico`]);
});
