// The theme follows the browser. Loaded in <head> so the first paint is already in the right theme.
(function () {
  var dark = window.matchMedia("(prefers-color-scheme: dark)");
  function apply() { document.documentElement.setAttribute("data-theme", dark.matches ? "dark" : "light"); }
  apply();
  dark.addEventListener("change", apply);
})();

document.addEventListener("DOMContentLoaded", function () {
  // The console sent this person to sign in from a page and kept that page in a cookie: an app route lives after the
  // #, which never reaches the server, so it is added here and the person lands on it once signed in.
  if (location.pathname === "/console/sign-in" && location.hash) {
    var kept = document.cookie.split("; ").filter(function (c) { return c.indexOf("enterplace_next=") === 0; })[0];
    if (kept) {
      var next = decodeURIComponent(kept.slice("enterplace_next=".length));
      if (next.indexOf("#") < 0) {
        document.cookie = "enterplace_next=" + encodeURIComponent(next + location.hash) + "; path=/console; samesite=lax; max-age=600";
      }
    }
  }
  // A button that copies the text of the element its data-copy names, such as the prompt for a coding agent.
  // Listened for on the document, not on each button: pages that redraw in place (Start here, Requests) replace the
  // buttons, and a listener on the old one would be gone. Without the Clipboard API (a page served over plain http
  // from another machine) or when it refuses, a selected textarea and execCommand copy instead.
  function fallback(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("button[data-copy]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source) return;
    var text = source.textContent;
    var label = button.getAttribute("data-label") || button.innerHTML;
    button.setAttribute("data-label", label);
    function said(word) {
      button.textContent = word;
      setTimeout(function () { button.innerHTML = label; }, 2000);
    }
    var done = function () { said("Copied"); };
    var failed = function () { said(fallback(text) ? "Copied" : "Copy failed: select the text and copy it"); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, failed);
    } else {
      failed();
    }
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

  // Dialogs and sheets are pages of their own, so "return focus" spans two loads: the link that opened one is
  // remembered by its address, and focused again when the page comes back without it.
  var KEY = "enterplace-opener";
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

// Every console page polls /console/live.json every 2 seconds while the tab is visible. The sidebar's indicator
// (data-live: checking, live or paused; data-live-last-request: the last record's time in ms, empty when none)
// follows the poll: paused when the poll fails or the tab is hidden. Requests, Analytics, Audit log and Spend also
// show records as they arrive: when the audit log changed, the page fetches itself and swaps its content in place,
// with no reload, the scroll kept, and rows that were not there before marked for a moment.
// Nothing is swapped while a field has the focus or a record's sheet is open, so nobody loses what they are doing.
document.addEventListener("DOMContentLoaded", function () {
  var main = document.getElementById("main");
  var indicator = document.querySelector("[data-live]");
  var swaps = /^\/console\/(requests|analytics|audit|spend)\/?$/.test(location.pathname);
  if (!window.fetch || (!indicator && !(main && swaps && window.DOMParser))) return;
  var seen = null;
  var timer = null;
  function show(state, last) {
    if (!indicator) return;
    var known = typeof last === "number";
    indicator.setAttribute("data-live", state);
    indicator.setAttribute("data-live-last-request", known ? String(last) : "");
    var when = known ? "last request " + new Date(last).toLocaleTimeString() : "no requests yet";
    indicator.textContent = state === "live" ? "Live, " + when : state === "paused" ? "Paused" : "Checking requests";
  }
  function busy() {
    var at = document.activeElement;
    // An open section (such as "Add your name") or a field in use would be lost by a redraw.
    return /[?&]record=/.test(location.search) || !!(main && main.querySelector && main.querySelector("details[open]")) ||
      (at && main && main.contains(at) && /^(INPUT|SELECT|TEXTAREA)$/.test(at.tagName));
  }
  function redraw() {
    return fetch(location.href, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        var next = html && new DOMParser().parseFromString(html, "text/html").getElementById("main");
        if (!next) return;
        var before = {};
        main.querySelectorAll("tbody tr").forEach(function (row) { before[row.textContent] = true; });
        main.innerHTML = next.innerHTML;
        main.querySelectorAll("tbody tr").forEach(function (row) {
          if (!before[row.textContent]) row.classList.add("g-row--new");
        });
      });
  }
  function again() { timer = setTimeout(tick, 2000); }
  function tick() {
    if (document.hidden) { timer = null; show("paused"); return; }
    fetch("/console/live.json", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; })
      .then(function (state) {
        if (!state) { show("paused"); return; }
        show("live", state.last_request_ms);
        if (!swaps || !main) return;
        if (state.signature === seen || busy()) { if (seen === null) seen = state.signature; return; }
        var first = seen === null;
        seen = state.signature;
        if (!first) return redraw();
      })
      .then(again, again);
  }
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) show("paused");
    else if (!timer) tick();
  });
  tick();
});
