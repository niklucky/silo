const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.resolve(__dirname, "../lib/usernames.ts"), "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const { createUsernameLoader } = vm.runInNewContext(`${js}\nexports`, { exports: {} });
const flush = () => new Promise((resolve) => setImmediate(resolve));

test("duplicate rows share a username lookup, but a new revision reloads it", async () => {
  let count = 0;
  const load = createUsernameLoader(async () => `user-${++count}`);
  const item = { id: "login", revision: 1 };
  const first = load(item);
  assert.equal(load(item), first);
  assert.equal(await first, "user-1");
  assert.equal(await load(item), "user-1");
  assert.equal(await load({ ...item, revision: 2 }), "user-2");
  assert.equal(count, 2);
});

test("empty usernames are preserved; failed lookups can be retried", async () => {
  let count = 0;
  const load = createUsernameLoader(async () => {
    if (++count === 1) throw new Error("temporarily unavailable");
    return "";
  });
  const item = { id: "login", revision: 1 };
  assert.equal(await load(item), null);
  assert.equal(await load(item), "");
  assert.equal(await load(item), "");
  assert.equal(count, 2);
});

test("visible rows queue at most four lookups at once", async () => {
  let active = 0;
  let peak = 0;
  const releases = [];
  const load = createUsernameLoader((id) => new Promise((resolve) => {
    peak = Math.max(peak, ++active);
    releases.push(() => { active--; resolve(id); });
  }));
  const jobs = Array.from({ length: 10 }, (_, index) => load({ id: `login-${index}`, revision: 1 }));
  await flush();
  assert.equal(releases.length, 4);
  while (releases.length) {
    releases.splice(0).forEach((release) => release());
    await flush();
  }
  assert.deepEqual(await Promise.all(jobs), Array.from({ length: 10 }, (_, index) => `login-${index}`));
  assert.equal(peak, 4);
});
