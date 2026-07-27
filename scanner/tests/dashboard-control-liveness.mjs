#!/usr/bin/env node
// ClaudeSec — dashboard control-liveness smoke harness.
//
// WHY THIS EXISTS
// ---------------
// The dashboard ships a meta-CSP with `script-src 'nonce-…' 'strict-dynamic'`
// and NO `'unsafe-inline'` (scanner/lib/dashboard-template.html). Every control
// is wired through a single delegated `data-action`/`data-change`/`data-input`
// dispatcher. Two regression classes silently kill a control IN-BROWSER while
// passing every source/pytest guard we have:
//   1. an inline `onclick=` is reintroduced  → CSP blocks it, control is dead;
//   2. a builder emits a `data-action` value with NO matching dispatcher case
//      (or the dispatcher case is renamed) → the click reaches the delegator
//      but nothing happens.
// pytest/source-pin guards catch (1)'s literal string but NOT (2)'s mismatch.
// This harness drives each control class in real headless Chrome via the
// DevTools Protocol and asserts the EXPECTED DOM EFFECT — so a dead control or
// a data-action↔dispatcher mismatch fails the check empirically.
//
// It selects each trigger by a STABLE STRUCTURAL selector (its CSS class / id),
// NOT by the data-action value. That is deliberate: if a builder renames the
// data-action to a value with no dispatcher case, the element is still found,
// the click still fires, but the DOM effect never happens → the assertion bites.
//
// HERMETIC / OFFLINE: it only loads a pre-generated local file:// dashboard
// (generated with CLAUDESEC_DASHBOARD_OFFLINE=1) and talks to a locally-spawned
// Chrome over CDP. No network, no npm dependencies — Node's built-in WebSocket
// (Node >= 21) and fetch are the only transport.
//
// Usage:
//   node dashboard-control-liveness.mjs --html <dashboard.html> [--chrome <path>]
// Exit code: 0 = every control live and zero CSP self-violations; 1 = a control
// is dead / a self-violation fired / a harness error.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// ── args ─────────────────────────────────────────────────────────────────────
function argOf(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : "";
}
const htmlPath = argOf("--html");
if (!htmlPath || !existsSync(htmlPath)) {
  console.error(`FATAL: --html <dashboard.html> is required and must exist (got: ${htmlPath || "<none>"})`);
  process.exit(1);
}

function resolveChrome() {
  const explicit = argOf("--chrome") || process.env.CHROME_BIN || process.env.CHROME_PATH;
  if (explicit && existsSync(explicit)) return explicit;
  const candidates = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  return "";
}
const chromeBin = resolveChrome();
if (!chromeBin) {
  console.error("FATAL: could not locate a Chrome/Chromium binary. Set CHROME_BIN or pass --chrome.");
  process.exit(1);
}

// ── CDP transport over the built-in WebSocket ─────────────────────────────────
class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.eventHandlers = new Map();
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message} (${JSON.stringify(msg.error)})`));
        else resolve(msg.result);
      } else if (msg.method) {
        const hs = this.eventHandlers.get(msg.method) || [];
        for (const h of hs) h(msg.params || {}, msg.sessionId);
      }
    });
  }
  on(method, handler) {
    if (!this.eventHandlers.has(method)) this.eventHandlers.set(method, []);
    this.eventHandlers.get(method).push(handler);
  }
  once(method, predicate) {
    return new Promise((resolve) => {
      const h = (params, sessionId) => {
        if (predicate && !predicate(params, sessionId)) return;
        const arr = this.eventHandlers.get(method) || [];
        const i = arr.indexOf(h);
        if (i >= 0) arr.splice(i, 1);
        resolve({ params, sessionId });
      };
      this.on(method, h);
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForDevtoolsPort(portFile, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (existsSync(portFile)) {
      const first = readFileSync(portFile, "utf8").split("\n")[0].trim();
      if (first) return parseInt(first, 10);
    }
    await sleep(50);
  }
  throw new Error("timed out waiting for Chrome DevToolsActivePort");
}

// Injected at document_start (bypasses page CSP because the debugger injects it):
// records securitypolicyviolation events and makes window.print observable so
// we can assert the print control actually fires without opening a print dialog.
const DOCUMENT_START = `
window.__cspViolations = [];
document.addEventListener('securitypolicyviolation', function(e){
  window.__cspViolations.push({
    directive: e.effectiveDirective || e.violatedDirective || '',
    blockedURI: e.blockedURI || '',
    sample: (e.sample || '').slice(0, 120),
    line: e.lineNumber || 0
  });
});
window.__printed = false;
window.print = function(){ window.__printed = true; };
`;

// Runs in the page. Drives every control class by STRUCTURAL selector and
// asserts the DOM effect. Returns { results:[{name, ok, detail}], violations }.
const ASSERT_CONTROLS = `(function(){
  var results = [];
  function rec(name, ok, detail){ results.push({name: name, ok: !!ok, detail: detail || ''}); }

  // toggleOwasp: .owasp-header click -> closest .owasp-item gains .expanded
  (function(){
    var t = document.querySelector('.owasp-header');
    if(!t){ rec('toggleOwasp', false, 'no .owasp-header trigger'); return; }
    var item = t.closest('.owasp-item');
    var before = item.classList.contains('expanded');
    t.click();
    var after = item.classList.contains('expanded');
    rec('toggleOwasp', !before && after, '.expanded ' + before + '->' + after);
  })();

  // toggleArch: .arch-header click -> closest .arch-domain gains .expanded
  (function(){
    var t = document.querySelector('.arch-header');
    if(!t){ rec('toggleArch', false, 'no .arch-header trigger'); return; }
    var item = t.closest('.arch-domain');
    var before = item.classList.contains('expanded');
    t.click();
    var after = item.classList.contains('expanded');
    rec('toggleArch', !before && after, '.expanded ' + before + '->' + after);
  })();

  // toggleComp: .comp-title click -> closest .comp-section gains .expanded
  (function(){
    var t = document.querySelector('.comp-title');
    if(!t){ rec('toggleComp', false, 'no .comp-title trigger'); return; }
    var item = t.closest('.comp-section');
    var before = item.classList.contains('expanded');
    t.click();
    var after = item.classList.contains('expanded');
    rec('toggleComp', !before && after, '.expanded ' + before + '->' + after);
  })();

  // openSetup: .env-pill click -> #setupModal gains .open (pick a pill whose
  // provider is present in SETUP_CONFIGS, since openSetup no-ops otherwise).
  (function(){
    var modal = document.getElementById('setupModal');
    if(!modal){ rec('openSetup', false, 'no #setupModal'); return; }
    var pills = Array.prototype.slice.call(document.querySelectorAll('.env-pill'));
    var configs = (typeof SETUP_CONFIGS !== 'undefined') ? SETUP_CONFIGS : {};
    var pill = pills.filter(function(p){ return configs[p.getAttribute('data-arg')]; })[0] || pills[0];
    if(!pill){ rec('openSetup', false, 'no .env-pill trigger'); return; }
    var before = modal.classList.contains('open');
    pill.click();
    var after = modal.classList.contains('open');
    rec('openSetup', !before && after, '#setupModal.open ' + before + '->' + after + ' via ' + (pill.getAttribute('data-arg')||'?'));
    var closeBtn = document.querySelector('.setup-modal-close');
    if(closeBtn) closeBtn.click();
  })();

  // switchTab jump-link: the "arch" tab button -> #tab-arch becomes .active
  (function(){
    var t = document.querySelector('.tab[aria-controls="tab-arch"]');
    if(!t){ rec('switchTab', false, 'no arch .tab button'); return; }
    t.click();
    var panel = document.getElementById('tab-arch');
    rec('switchTab', panel && panel.classList.contains('active'), '#tab-arch.active=' + (panel ? panel.classList.contains('active') : 'no-panel'));
  })();

  // switchProvTab: #provtab-gcp click -> #provpanel-gcp becomes .active
  (function(){
    var t = document.getElementById('provtab-gcp');
    if(!t){ rec('switchProvTab', false, 'no #provtab-gcp'); return; }
    t.click();
    var panel = document.getElementById('provpanel-gcp');
    rec('switchProvTab', panel && panel.classList.contains('active'), '#provpanel-gcp.active=' + (panel ? panel.classList.contains('active') : 'no-panel'));
  })();

  // print: .print-btn click -> window.print() fires (observed via override)
  (function(){
    var t = document.querySelector('.print-btn');
    if(!t){ rec('print', false, 'no .print-btn'); return; }
    window.__printed = false;
    t.click();
    rec('print', window.__printed === true, 'window.print fired=' + window.__printed);
  })();

  // scanner-category scope link: .scope-cat-link click -> overview tab active
  // AND its data-scroll target element exists (reachable jump).
  (function(){
    var t = document.querySelector('.scope-cat-link');
    if(!t){ rec('scannerCategoryLink', false, 'no .scope-cat-link'); return; }
    t.click();
    var overview = document.getElementById('tab-overview');
    var scrollTarget = document.getElementById(t.getAttribute('data-scroll') || '');
    var ok = overview && overview.classList.contains('active') && !!scrollTarget;
    rec('scannerCategoryLink', ok, 'overview.active=' + (overview ? overview.classList.contains('active') : '?') + ' target=' + (scrollTarget ? 'present' : 'MISSING'));
  })();

  return { results: results, violations: (window.__cspViolations || []) };
})()`;

// ── run ────────────────────────────────────────────────────────────────────
const userDataDir = mkdtempSync(join(tmpdir(), "claudesec-cdp-"));
let chrome;
let exitCode = 1;
try {
  chrome = spawn(
    chromeBin,
    [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--no-first-run",
      "--no-default-browser-check",
      "--remote-debugging-port=0",
      `--user-data-dir=${userDataDir}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] }
  );
  chrome.on("error", (e) => {
    console.error("FATAL: failed to spawn Chrome:", e.message);
  });

  const port = await waitForDevtoolsPort(join(userDataDir, "DevToolsActivePort"), 20000);
  const verRes = await fetch(`http://127.0.0.1:${port}/json/version`);
  const { webSocketDebuggerUrl } = await verRes.json();

  const ws = new WebSocket(webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error("browser WebSocket error")), { once: true });
  });

  const cdp = new CDP(ws);
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });

  await cdp.send("Page.enable", {}, sessionId);
  await cdp.send("Runtime.enable", {}, sessionId);
  await cdp.send("Log.enable", {}, sessionId);
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: DOCUMENT_START }, sessionId);

  const loaded = cdp.once("Page.loadEventFired", (_p, sid) => sid === sessionId);
  const fileUrl = pathToFileURL(htmlPath).href;
  await cdp.send("Page.navigate", { url: fileUrl }, sessionId);
  await loaded;
  await sleep(150); // let the delegated listeners + document_start settle

  const evalRes = await cdp.send(
    "Runtime.evaluate",
    { expression: ASSERT_CONTROLS, returnByValue: true, awaitPromise: true },
    sessionId
  );
  if (evalRes.exceptionDetails) {
    throw new Error("page evaluation threw: " + JSON.stringify(evalRes.exceptionDetails));
  }
  const { results, violations } = evalRes.result.value;

  // ── report ────────────────────────────────────────────────────────────────
  console.log("=== dashboard control-liveness ===");
  let dead = 0;
  for (const r of results) {
    console.log(`${r.ok ? "PASS" : "FAIL"}: ${r.name} — ${r.detail}`);
    if (!r.ok) dead++;
  }
  // A nonce/CSP regression (reintroduced inline handler, broken nonce) fires a
  // script-src* securitypolicyviolation. A healthy offline dashboard fires none
  // (no external subresources). Fail on ANY violation; flag script-src* loudly.
  const scriptViolations = violations.filter((v) => (v.directive || "").indexOf("script-src") === 0);
  console.log(`CSP self-violations: total=${violations.length} script-src=${scriptViolations.length}`);
  for (const v of violations) {
    console.log(`  VIOLATION: directive=${v.directive} blockedURI=${v.blockedURI} sample="${v.sample}" line=${v.line}`);
  }

  const controlsOk = dead === 0;
  const cspOk = violations.length === 0;
  console.log(
    `\nRESULT: controls ${results.length - dead}/${results.length} live, ${violations.length} CSP self-violation(s)`
  );
  exitCode = controlsOk && cspOk ? 0 : 1;

  try {
    ws.close();
  } catch (_) {
    /* ignore */
  }
} catch (err) {
  console.error("FATAL:", err && err.stack ? err.stack : String(err));
  exitCode = 1;
} finally {
  if (chrome) {
    try {
      chrome.kill("SIGKILL");
    } catch (_) {
      /* ignore */
    }
  }
  try {
    rmSync(userDataDir, { recursive: true, force: true });
  } catch (_) {
    /* ignore */
  }
}

process.exit(exitCode);
