// The theme follows the browser. Loaded in <head> so the first paint is already in the right theme.
(function () {
  var dark = window.matchMedia("(prefers-color-scheme: dark)");
  function apply() { document.documentElement.setAttribute("data-theme", dark.matches ? "dark" : "light"); }
  apply();
  dark.addEventListener("change", apply);
})();

document.addEventListener("DOMContentLoaded", function () {
  // A button that copies the text of the element its data-copy names, such as the prompt for a coding agent.
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var source = document.getElementById(button.getAttribute("data-copy"));
      if (!source || !navigator.clipboard) return;
      navigator.clipboard.writeText(source.innerText).then(function () { button.textContent = "Copied"; });
    });
  });
  // A filter that is a select applies when it changes, as the pills do when pressed.
  document.querySelectorAll("select[data-submit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });
  // A destructive button stays disabled until the exact words are typed. The server checks them again.
  document.querySelectorAll("input[data-confirm]").forEach(function (input) {
    var button = document.getElementById(input.getAttribute("data-button"));
    function check() { button.disabled = input.value.trim() !== input.getAttribute("data-confirm"); }
    check();
    input.addEventListener("input", check);
  });
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var text = document.getElementById(button.getAttribute("data-copy")).textContent;
      navigator.clipboard.writeText(text);
    });
  });

  // Dialogs and sheets are pages of their own, so "return focus" spans two loads: the link that opened one is
  // remembered by its address, and focused again when the page comes back without it.
  var KEY = "gantry-opener";
  function remember(href) { try { sessionStorage.setItem(KEY, href); } catch (e) {} }
  document.addEventListener("click", function (event) {
    var link = event.target.closest && event.target.closest("a[href]");
    if (link && !link.closest("[aria-modal]") && /[?&](record|issue|revoke)=/.test(link.getAttribute("href"))) {
      remember(link.getAttribute("href"));
    }
  });
  var modal = document.querySelector('[role="dialog"][aria-modal="true"]');
  if (!modal) {
    var opener = null;
    try { opener = sessionStorage.getItem(KEY); sessionStorage.removeItem(KEY); } catch (e) {}
    // The result of what was just done (a toast, a verified chain) is where focus lands, so it is read out.
    var result = document.querySelector("[data-focus]");
    if (result) { result.focus(); return; }
    if (opener) {
      var back = Array.prototype.find.call(document.querySelectorAll("a[href]"), function (a) {
        return a.getAttribute("href") === opener;
      });
      if (back) back.focus();
    }
    return;
  }
  // What is behind a modal is out of reach: not focusable, not read.
  document.querySelectorAll(".g-shell > nav, .g-shell > main").forEach(function (el) { el.setAttribute("inert", ""); });
  var first = modal.querySelector("[autofocus]") || modal.querySelector("[data-close]") || modal;
  if (first === modal) modal.setAttribute("tabindex", "-1");
  first.focus();
  function focusable() {
    return Array.prototype.filter.call(
      modal.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])'),
      function (el) { return el.offsetParent !== null; });
  }
  // On the document: with the page behind inert, focus is in the modal or on the body.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      var close = modal.querySelector("[data-close]");
      if (close) { event.preventDefault(); close.click(); }
      return;
    }
    if (event.key !== "Tab") return;
    var items = focusable();
    if (!items.length) return;
    var last = items[items.length - 1];
    if (event.shiftKey && (document.activeElement === items[0] || document.activeElement === modal)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); items[0].focus();
    }
  });
});

// The policy editor's file field: the file's text replaces the editor's, so importing is a save like any other.
document.addEventListener("change", function (event) {
  var input = event.target;
  if (!input.matches || !input.matches("[data-load-into]") || !input.files || !input.files[0]) return;
  var into = document.getElementById(input.getAttribute("data-load-into"));
  if (!into) return;
  input.files[0].text().then(function (text) { into.value = text; into.focus(); });
});

// Start here: a listening step polls the checklist's state every 2 seconds while the tab is visible, and opens
// Start here again when it changes. Without a script the step's Check now link does the same.
document.addEventListener("DOMContentLoaded", function () {
  var box = document.querySelector("[data-start-poll]");
  var start = document.querySelector("[data-start-button]");
  if (start) {
    document.querySelectorAll('input[name="choice"]').forEach(function (input) {
      input.addEventListener("change", function () {
        var label = input.closest("label").querySelector(".t-body-strong").textContent;
        start.textContent = "Start with " + (input.getAttribute("data-button") || label);
      });
    });
  }
  if (!box || !window.fetch) return;
  var seen = box.getAttribute("data-start-poll");
  var track = new URLSearchParams(location.search).get("track");
  // The whole query, so a choice such as how the team pays for Claude Code is kept across the reload.
  var url = "/console/start/state.json" + location.search;
  var timer = null;
  function tick() {
    if (document.hidden) { timer = null; return; }
    fetch(url, { credentials: "same-origin", cache: "no-store" }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (state) {
        if (state && state.signature !== seen) { location.href = "/console/start" + location.search; return; }
        timer = setTimeout(tick, 2000);
      })
      .catch(function () { timer = setTimeout(tick, 2000); });
  }
  document.addEventListener("visibilitychange", function () { if (!document.hidden && !timer) tick(); });
  timer = setTimeout(tick, 2000);
});
