// Runs assets/console.js against a small fake page and drives the live poll by hand. Run by tests/live.rs.
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const assert = require("assert");

const source = fs.readFileSync(path.join(__dirname, "..", "assets", "console.js"), "utf8");

function element(extra) {
  const attrs = {};
  const el = Object.assign({
    attrs, textContent: "", innerHTML: "", tagName: "DIV",
    classList: { add() {} },
    setAttribute(k, v) { attrs[k] = String(v); },
    getAttribute(k) { return k in attrs ? attrs[k] : null; },
    querySelectorAll() { return []; },
    contains(other) { return other === el || (el.children || []).includes(other); },
  }, extra);
  return el;
}

// One scenario: a page at `pathname` whose poll answers from `answers` in order ("fail" is a network error).
function page(pathname, answers) {
  const main = element({ children: [] });
  const indicator = element({ textContent: "Checking requests" });
  indicator.attrs["data-live"] = "checking";
  const doc = {
    hidden: false, activeElement: null, listeners: {},
    documentElement: element(),
    addEventListener(type, fn) { (doc.listeners[type] = doc.listeners[type] || []).push(fn); },
    getElementById(id) { return id === "main" ? main : null; },
    querySelector(sel) { return sel === "[data-live]" ? indicator : null; },
    querySelectorAll() { return []; },
  };
  const timers = [];
  const calls = { poll: 0, page: 0 };
  const win = {
    document: doc, location: { pathname, search: "", href: pathname },
    matchMedia() { return { matches: false, addEventListener() {} }; },
    fetch(url) {
      if (url === "/console/live.json") {
        calls.poll++;
        const next = answers.shift();
        if (next === "fail") return Promise.reject(new Error("offline"));
        return Promise.resolve({ ok: true, json: () => Promise.resolve(next) });
      }
      calls.page++;
      return Promise.resolve({ ok: true, text: () => Promise.resolve("<main>new rows</main>") });
    },
    DOMParser: function () {
      this.parseFromString = (html) => ({ getElementById: () => ({ innerHTML: html.replace(/<\/?main>/g, "") }) });
    },
    setTimeout(fn) { timers.push(fn); return timers.length; },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    URLSearchParams,
    navigator: {},
  };
  win.window = win;
  vm.runInNewContext(source, win);
  (doc.listeners.DOMContentLoaded || []).forEach((fn) => fn());
  const settle = () => new Promise((r) => setImmediate(r));
  return {
    doc, main, indicator, calls,
    // Lets the pending request finish, then fires the next timer, as two seconds passing would.
    async first() { await settle(); await settle(); },
    async step() { await settle(); const fn = timers.shift(); if (fn) fn(); await settle(); await settle(); },
    state() { return indicator.attrs["data-live"]; },
  };
}

async function run() {
  // A signature change swaps the page's content in place.
  let p = page("/console/requests", [
    { signature: "1-1", last_request_ms: 1700000000000 },
    { signature: "2-2", last_request_ms: 1700000005000 },
  ]);
  await p.first();
  assert.strictEqual(p.state(), "live");
  assert.strictEqual(p.indicator.attrs["data-live-last-request"], "1700000000000");
  assert.strictEqual(p.calls.page, 0, "the first answer only records the signature");
  await p.step();
  assert.strictEqual(p.calls.page, 1, "a changed signature fetches the page");
  assert.strictEqual(p.main.innerHTML, "new rows", "and swaps it in place");
  assert.strictEqual(p.indicator.attrs["data-live-last-request"], "1700000005000");

  // Nothing is swapped while a form field in the page has focus; it is swapped once focus leaves.
  p = page("/console/requests", [
    { signature: "1-1", last_request_ms: 1 },
    { signature: "2-2", last_request_ms: 2 },
    { signature: "2-2", last_request_ms: 2 },
  ]);
  await p.first();
  const field = element({ tagName: "INPUT" });
  p.main.children.push(field);
  p.doc.activeElement = field;
  await p.step();
  assert.strictEqual(p.calls.page, 0, "a focused field blocks the swap");
  assert.strictEqual(p.main.innerHTML, "");
  assert.strictEqual(p.state(), "live", "the indicator still follows the poll");
  p.doc.activeElement = null;
  await p.step();
  assert.strictEqual(p.calls.page, 1, "the swap happens once the field is left");
  assert.strictEqual(p.main.innerHTML, "new rows");

  // The indicator works on a page that never swaps, and reads paused when the poll fails or the tab is hidden.
  p = page("/console/keys", [{ signature: "1-1", last_request_ms: null }, "fail", { signature: "1-1", last_request_ms: null }]);
  await p.first();
  assert.strictEqual(p.state(), "live");
  assert.strictEqual(p.indicator.attrs["data-live-last-request"], "");
  await p.step();
  assert.strictEqual(p.state(), "paused", "a failed poll pauses");
  await p.step();
  assert.strictEqual(p.state(), "live", "and the next good answer resumes");
  p.doc.hidden = true;
  await p.step();
  assert.strictEqual(p.state(), "paused", "a hidden tab pauses");
  assert.strictEqual(p.calls.page, 0, "a page without live content never swaps");
  console.log("ok");
}
run().catch((e) => { console.error(e); process.exit(1); });
