const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const flush = () => new Promise((resolve) => setImmediate(resolve));

// Keep the closed shadow UI observable here without exposing it to web pages.
function harness({ clipboardFails = false, clipboardUnavailable = false, unsaved = false } = {}) {
  class Node {
    children = [];
    attributes = {};
    listeners = {};
    style = { setProperty() {} };
    className = "";
    textContent = "";
    isConnected = false;
    offsetHeight = 100;
    offsetWidth = 300;
    classList = { add() {}, remove() {} };
    ownerDocument = document;
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute(key, value) { this.attributes[key] = value; }
    addEventListener(type, listener) { this.listeners[type] = listener; }
    attachShadow() { return (this.shadow = new Node()); }
    getBoundingClientRect() { return { top: 20, bottom: 40, left: 20, width: 300 }; }
    scrollIntoView() {}
    remove() { this.isConnected = false; }
    click(isTrusted = true) {
      this.listeners.click?.({ isTrusted, preventDefault() {}, stopPropagation() {} });
    }
  }
  const selectionAccess = [];
  const document = {
    createElement: () => new Node(),
    createElementNS: () => new Node(),
    createRange: () => {
      selectionAccess.push("createRange");
      return { selectNodeContents(node) { selectionAccess.push(node.textContent); } };
    },
    getSelection: () => {
      selectionAccess.push("getSelection");
      return { removeAllRanges() {}, addRange() {} };
    },
  };
  document.documentElement = new Node();
  const copied = [];
  const modules = new Map();
  function load(file) {
    if (modules.has(file)) return modules.get(file);
    const exports = {};
    modules.set(file, exports);
    const js = ts.transpileModule(fs.readFileSync(file, "utf8"), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    vm.runInNewContext(js, {
      exports,
      require: (name) => load(path.resolve(path.dirname(file), `${name}.ts`)),
      document,
      location: { host: "example.com" },
      window: { innerHeight: 800, innerWidth: 1200, addEventListener() {}, removeEventListener() {} },
      navigator: { clipboard: clipboardUnavailable ? undefined : { async writeText(value) {
        if (clipboardFails) throw new Error("Clipboard unavailable");
        copied.push(value);
      } } },
    });
    return exports;
  }
  const { Menu } = load(path.resolve(__dirname, "../lib/menu.ts"));
  const used = [];
  const menu = new Menu({ useGenerated: (...args) => used.push(args) });
  const options = [
    { style: "easy", password: "Bakomi-tuvela-rosedu7-fanipo", bits: 82 },
    { style: "random", password: "rN4!q7V#w9H@e3Z*o8F?", bits: 120 },
  ];
  const anchor = new Node();
  anchor.isConnected = true;
  menu.show(anchor, unsaved
    ? { kind: "unsaved", text: "Silo is locked", password: options[0].password }
    : { kind: "generate", options, saving: "saved", insecure: false });
  const box = document.documentElement.children[0].shadow.children[1];
  const rows = box.children.filter((node) => node.className === "suggestion");
  const status = box.children.find((node) => node.attributes.role === "status");
  return { menu, options, rows, status, copied, used, selectionAccess, box };
}

test("each suggestion copies independently without saving or filling, and can be copied again", async () => {
  const { options, rows, copied, used, status } = harness();
  for (const [index, row] of rows.entries()) {
    const [fill, copy] = row.children;
    copy.click();
    await flush();
    copy.click();
    await flush();
    assert.equal(fill.children[0].textContent, options[index].password);
  }
  assert.equal(rows.length, 2);
  assert.deepEqual(copied, options.flatMap((option) => [option.password, option.password]));
  assert.deepEqual(used, []);
  assert.match(status.textContent, /Password copied/);
});

test("arrow keys can choose copy while the fill action still uses the original password", async () => {
  const { menu, copied, used, options } = harness();
  menu.move(1); // fill the first suggestion
  menu.move(1); // copy the first suggestion
  assert.equal(menu.activate(), true);
  await flush();
  assert.deepEqual(copied, [options[0].password]);
  assert.deepEqual(used, []);
  menu.move(-1);
  menu.activate();
  assert.equal(used[0][0].password, options[0].password);
  assert.equal(used[0][1], "saved");
});

test("untrusted clicks cannot copy or fill a suggested password", async () => {
  const { rows, copied, used } = harness();
  for (const row of rows) for (const button of row.children) button.click(false);
  await flush();
  assert.deepEqual(copied, []);
  assert.deepEqual(used, []);
});

for (const failure of [{ clipboardFails: true }, { clipboardUnavailable: true }]) {
  for (const unsaved of [false, true]) {
    test(`${unsaved ? "unsaved" : "suggested"} password stays private when clipboard is ${failure.clipboardFails ? "denied" : "unavailable"}`, async () => {
      const { rows, options, status, copied, used, selectionAccess, box } = harness({ ...failure, unsaved });
      const button = unsaved ? box.children.find((node) => node.className === "item") : rows[0].children[1];
      button.click();
      await flush();
      const shown = unsaved ? box.children.find((node) => node.className === "pw secret") : rows[0].children[0].children[0];
      assert.equal(shown.textContent, options[0].password);
      assert.match(status.textContent, /Could not copy/);
      assert.deepEqual(selectionAccess, [], "must not expose secret text through the page's selection");
      assert.deepEqual(copied, []);
      assert.deepEqual(used, []);
    });
  }
}
