/* ClaudeSec — control-liveness assertions for the ISMS ASSET dashboard.
 *
 * Evaluated verbatim in the page by scanner/tests/dashboard-control-liveness.mjs
 * (`--assert-file`). Driven by scanner/tests/test_asset_dashboard_control_liveness.sh,
 * which injects scanner/tests/fixtures/asset-dashboard-data.json into the checked-in
 * template claudesec-asset-dashboard.html and substitutes its {{CSP_NONCE}} placeholder.
 *
 * WHY THIS EXISTS
 * ---------------
 * claudesec-asset-dashboard.html ships the SAME strict meta-CSP as the scan
 * dashboard — `script-src 'nonce-…' 'strict-dynamic'`, no `'unsafe-inline'` — and
 * the same single delegated click dispatcher keyed on `data-action`. So it has the
 * same two silently-fatal regression classes:
 *   1. a reintroduced inline `on*=` handler → CSP blocks it, the control is dead;
 *   2. a `data-action` value emitted with NO matching dispatcher case (or a renamed
 *      case) → the click reaches the delegator and nothing happens.
 * Until now it had ZERO automated coverage: the static inline-handler guard did not
 * scan it and this harness only drove the scan dashboard.
 *
 * SELECTOR DISCIPLINE (same as the scan suite — preserve it)
 * ---------------------------------------------------------
 * Every trigger is found by a STABLE STRUCTURAL selector (container id + element
 * class, or ordinal within its container), NEVER by its `data-action` value. If a
 * builder renames the action to a value with no dispatcher case, the element is
 * still found, the click still fires, and the missing DOM effect is what fails.
 * Selecting by `[data-action="x"]` would instead make the element vanish and turn
 * the assertion into a "trigger not found" that reads like a fixture problem.
 *
 * ASSERTED EFFECT DISCIPLINE
 * --------------------------
 * Each filter chip records TWO effects: (a) the `.on` class moving to the clicked
 * chip, which only the dispatcher's handler does, and (b) a data-driven measure
 * (a count element's text, or the rendered row/card count) changing to the value
 * the filter implies. (a) alone proves the case fired; (b) makes the assertion
 * non-vacuous even if `.on` were ever set from somewhere else.
 *
 * SYNCHRONOUS: no `await`, no timers. Every render path in this dashboard is
 * synchronous once the data is in (`switchTab` renders the lazy panel inline), so
 * run-to-completion means an earlier click cannot land between a later block's
 * "before" read and its click.
 */
(function () {
  var results = [];
  function rec(name, ok, detail, skip) {
    results.push({ name: name, ok: !!ok, detail: detail || "", skip: !!skip });
  }

  function textOf(sel) {
    var el = document.querySelector(sel);
    return el ? el.textContent : "(missing " + sel + ")";
  }
  function countOf(sel) {
    return String(document.querySelectorAll(sel).length);
  }

  /* Click a tab by its data-p (the panel key — markup structure, not an action
     name) and report whether the matching panel became .active. */
  function openTab(key) {
    var t = document.querySelector('.tab[data-p="' + key + '"]');
    if (!t) return false;
    t.click();
    var panel = document.getElementById("p-" + key);
    return !!(panel && panel.classList.contains("active"));
  }

  /* Shared filter-chip driver. Clicks the first chip in `containerSel` that is not
     already `.on`, then asserts the `.on` marker moved to it AND that `measure()`
     changed (the re-render actually applied the filter). */
  function driveChip(name, containerSel, chipSel, measureLabel, measure) {
    var chips = Array.prototype.slice.call(
      document.querySelectorAll(containerSel + " " + chipSel)
    );
    if (chips.length < 2) {
      rec(name, false, "need >=2 chips in " + containerSel + ", found " + chips.length);
      return;
    }
    var target = chips.filter(function (c) {
      return !c.classList.contains("on");
    })[0];
    if (!target) {
      rec(name, false, "every chip in " + containerSel + " is already .on");
      return;
    }
    var before = measure();
    target.click();
    var onMoved =
      target.classList.contains("on") &&
      chips.filter(function (c) {
        return c !== target && c.classList.contains("on");
      }).length === 0;
    var after = measure();
    rec(
      name,
      onMoved && after !== before,
      ".on moved=" + onMoved + ", " + measureLabel + " '" + before + "'->'" + after + "'"
    );
  }

  /* Shared expandable-card driver: clicks the first card matching `containerSel`
     and asserts its `detailSel` child toggles display none -> block. */
  function driveCard(name, containerSel, detailSel) {
    var card = document.querySelector(containerSel);
    if (!card) {
      rec(name, false, "no card at " + containerSel);
      return;
    }
    var det = card.querySelector(detailSel);
    if (!det) {
      rec(name, false, "card has no " + detailSel + " detail");
      return;
    }
    var before = det.style.display;
    card.click();
    var after = det.style.display;
    rec(name, before === "none" && after === "block", detailSel + " display " + before + "->" + after);
  }

  /* ── switchTab: the #tabs delegated click listener ───────────────────────── */
  (function () {
    var opened = openTab("sec");
    rec("switchTab", opened, "#p-sec.active=" + opened);
  })();

  /* ── themeToggle: #theme-toggle click flips <html data-theme> ────────────── */
  (function () {
    var t = document.getElementById("theme-toggle");
    if (!t) {
      rec("themeToggle", false, "no #theme-toggle button");
      return;
    }
    var before = document.documentElement.getAttribute("data-theme");
    t.click();
    var after = document.documentElement.getAttribute("data-theme");
    t.click(); // restore
    rec("themeToggle", !!before && !!after && before !== after, "data-theme " + before + "->" + after);
  })();

  /* ── _fCsSev: ClaudeSec finding severity chips. #scan-fc holds the unfiltered
        total and is never rewritten, so the measure is the rendered card count. ── */
  driveChip("_fCsSev", "#cs-sev-fb", ".fb-btn", "#cs-findings-list cards", function () {
    return countOf("#cs-findings-list > div");
  });

  /* ── toggle-cs-det: expandable ClaudeSec finding card ────────────────────── */
  driveCard("toggle-cs-det", "#cs-findings-list > div", ".cs-det");

  /* ── _fprow: Prowler provider chips; _renderProw rewrites #prow-c ────────── */
  driveChip("_fprow", "#sec-fb", ".fb-btn", "#prow-c", function () {
    return textOf("#prow-c");
  });

  /* ── _fProwSev: Prowler severity chips. Reset the provider filter first, so
        the count genuinely changes (the _fprow click above already narrowed it). ── */
  (function () {
    var reset = document.querySelector("#sec-fb .fb-btn");
    if (reset) reset.click();
    driveChip("_fProwSev", "#prow-sev-fb", ".fb-btn", "#prow-c", function () {
      return textOf("#prow-c");
    });
  })();

  /* ── toggle-prow-det: expandable Prowler finding card ────────────────────── */
  driveCard("toggle-prow-det", "#t-prow > div", ".prow-det");

  /* ── _fpc: Apple-device platform chips (asset tab) ───────────────────────── */
  (function () {
    if (!openTab("asset")) {
      rec("_fpc", false, "asset tab did not activate");
      return;
    }
    driveChip("_fpc", "#pc-fb", ".fb-btn", "#pc-c", function () {
      return textOf("#pc-c");
    });
  })();

  /* ── tableSearch: mkSearch()'s `input` listener hides non-matching rows. Not a
        data-action control, but it lives in the same nonce'd script and is reused
        by four tables, so a CSP/nonce regression kills it silently too. ──────── */
  (function () {
    var resetChip = document.querySelector("#pc-fb .fb-btn");
    if (resetChip) resetChip.click(); // undo the _fpc filter above
    var input = document.getElementById("pc-search");
    var table = document.getElementById("t-pc");
    if (!input || !table) {
      rec("tableSearch", false, "no #pc-search / #t-pc");
      return;
    }
    var total = table.querySelectorAll("tbody tr").length;
    if (total < 2) {
      rec("tableSearch", false, "need >=2 device rows, found " + total);
      return;
    }
    function hiddenRows() {
      return Array.prototype.filter.call(table.querySelectorAll("tbody tr"), function (tr) {
        return tr.style.display === "none";
      }).length;
    }
    input.value = "zzz-no-such-device";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    var hidden = hiddenRows();
    input.value = "";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    var restored = hiddenRows();
    rec(
      "tableSearch",
      hidden === total && restored === 0,
      "hidden=" + hidden + "/" + total + " on no-match, hidden=" + restored + " after clear"
    );
  })();

  /* ── _fInfra: unified-server environment chips (infra tab) ───────────────── */
  (function () {
    if (!openTab("infra")) {
      rec("_fInfra", false, "infra tab did not activate");
      return;
    }
    driveChip("_fInfra", "#infra-fb", ".fb-btn", "#srv-unified-c", function () {
      return textOf("#srv-unified-c");
    });
  })();

  /* ── _fSaaS: SaaS category chips. #saas-c is a static total, so the measure is
        the rendered row count of the table _applyFilter re-renders. ─────────── */
  (function () {
    if (!openTab("saas")) {
      rec("_fSaaS", false, "saas tab did not activate");
      return;
    }
    driveChip("_fSaaS", "#saas-cats", ".cat-chip", "#t-saas rows", function () {
      return countOf("#t-saas tbody tr");
    });
  })();

  /* ── sortHeader: mkT()'s per-<th> click listener re-sorts the tbody. It is the
        ONLY consumer of sortKey(), so it runs right before the sortKey pins. ── */
  (function () {
    var table = document.getElementById("t-saas");
    if (!table) {
      rec("sortHeader", false, "no #t-saas");
      return;
    }
    var resetChip = document.querySelector("#saas-cats .cat-chip");
    if (resetChip) resetChip.click(); // restore the unfiltered row set
    var th = table.querySelectorAll("th")[2]; // the asset-name column (text)
    if (!th) {
      rec("sortHeader", false, "#t-saas has no 3rd <th>");
      return;
    }
    function order() {
      return Array.prototype.map
        .call(table.querySelectorAll("tbody tr"), function (tr) {
          return tr.cells[2] ? tr.cells[2].textContent : "";
        })
        .join("|");
    }
    var initial = order();
    th.click();
    var asc = order();
    th.click();
    var desc = order();
    rec(
      "sortHeader",
      initial.length > 0 && th.classList.contains("sorted") && asc !== desc,
      "th.sorted=" + th.classList.contains("sorted") + ", asc='" + asc + "' desc='" + desc + "'"
    );
  })();

  /* ── sortKey() behaviour pins (PR #398 changed it and shipped no test) ─────
     Regression-pins the key shapes the comparator depends on. sortKey is a
     top-level function in the page's nonce'd script, so it is a global here. */
  (function () {
    if (typeof sortKey !== "function") {
      rec("sortKeyPins", false, "sortKey is not a global function");
      return;
    }
    var TH = "<!--T-->"; // the _TH trusted-chip marker sortKey keys off
    var failures = [];
    function eq(label, actual, expected) {
      if (actual !== expected) {
        failures.push(label + ": got " + JSON.stringify(actual) + " want " + JSON.stringify(expected));
      }
    }

    /* non-string -> '' (mkT passes `a[ci]||''`, but a numeric cell arrives raw) */
    eq("non-string", sortKey(42), "");
    eq("null", sortKey(null), "");

    /* plain (non-chip) value: used VERBATIM, only trimmed — never tag-stripped */
    eq("plain-trim", sortKey("  Sample CRM  "), "Sample CRM");
    eq("plain-keeps-angle-bracket", sortKey("a < b"), "a < b");

    /* trusted chip markup: reduced to its text content */
    eq("chip-text", sortKey(TH + '<span class="ch ch-r">Critical</span>'), "Critical");

    /* numeric key: the comparator strips to [0-9.-] and parseFloats it */
    var moneyKey = sortKey(TH + '<span class="ch ch-b">₩120,000</span>');
    eq("chip-numeric-key", moneyKey, "₩120,000");
    var moneyNum = parseFloat(moneyKey.replace(/[^0-9.\-]/g, ""));
    if (moneyNum !== 120000) failures.push("chip-numeric-parse: got " + moneyNum + " want 120000");

    /* entity DECODING is the documented behaviour change of the DOMParser path */
    eq("chip-entity-decoded", sortKey(TH + '<span class="ch ch-m">a&amp;b</span>'), "a&b");

    /* ko collation: the comparator sorts keys with localeCompare(_, 'ko') */
    var ka = sortKey(TH + '<span class="ch ch-m">가</span>');
    var kb = sortKey(TH + '<span class="ch ch-m">나</span>');
    if (!(ka.localeCompare(kb, "ko") < 0)) {
      failures.push("ko-collation: '" + ka + "' did not sort before '" + kb + "'");
    }

    /* memoisation (the #398 perf fix): a repeated key is cached, not recomputed */
    var memoInput = TH + '<span class="ch ch-g">memo-probe</span>';
    var first = sortKey(memoInput);
    eq("memo-stable", sortKey(memoInput), first);
    if (
      typeof _sortKeyCache === "undefined" ||
      !Object.prototype.hasOwnProperty.call(_sortKeyCache, memoInput)
    ) {
      failures.push("memo-cache: _sortKeyCache has no entry for the probed chip");
    }

    /* Documented quirk, pinned so a change is deliberate: DOMParser's
       body.textContent includes a <script> element's TEXT, so script source inside
       a chip leaks into the sort key. Harmless — the key is only compared or
       parseFloat'd, never re-inserted into the DOM (mkT re-reads the ORIGINAL
       cell) — and the script does not RUN (see sortKeyInert). */
    eq(
      "chip-script-text-leaks-into-key",
      sortKey(TH + '<span class="ch ch-m"><scr' + "ipt>var x=1</scr" + "ipt>tail</span>"),
      "var x=1tail"
    );

    rec("sortKeyPins", failures.length === 0, failures.length ? failures.join(" | ") : "10 key shapes pinned");
  })();

  /* ── sortKey inertness: the DOMParser document must fetch no subresource.
        This assertion feeds sortKey() an <img> whose URL carries the runner's
        `must-not-load` sentinel; dashboard-control-liveness.mjs watches every
        Network.requestWillBeSent and fails the run if it is ever requested.

        NO page-side flag here, deliberately. The first version also set
        `window.__sortKeyPwned` from an `onerror` handler and asserted it was
        false — which it always is: `onerror` fires asynchronously and the
        assertion reads it on the very next synchronous line. Reverting sortKey()
        to a live `div.innerHTML` container still printed
        `PASS: sortKeyInert — onerror fired=false` while the Network sentinel
        correctly reported `LEAKED REQUEST` (adversarial review of #401, F1).
        A check that cannot fail is worse than no check, so it is gone; the
        sentinel is the real detector and the runner now fails closed if this
        file stops embedding it.

        `key === "hostile"` stays: it is a genuine assertion that the markup was
        reduced to its text. Script EXECUTION is not asserted here — DOMParser
        never runs scripts even in a live document, so it could not discriminate;
        that shape is pinned in sortKeyPins instead. ───────────────────────── */
  (function () {
    if (typeof sortKey !== "function") {
      rec("sortKeyInert", false, "sortKey is not a global function");
      return;
    }
    var TH = "<!--T-->";
    /* Declared back to the runner via `probes` below, so the coupling between
       this URL and the runner's sentinel is checked on the VALUE, not by
       sniffing this file's text (a text scan is satisfied by any prose mention
       of the sentinel — including the paragraph above). */
    window.__forbiddenProbes = (window.__forbiddenProbes || []);
    var probeUrl = "sortkey-probe-must-not-load.png";
    window.__forbiddenProbes.push(probeUrl);
    var hostile =
      TH +
      '<span class="ch ch-r">' +
      '<img src="' + probeUrl + '">' +
      "hostile</span>";
    var key = sortKey(hostile);
    rec(
      "sortKeyInert",
      key === "hostile",
      "key=" + JSON.stringify(key) +
        " (the no-request claim is asserted ONLY by the runner's sentinel)"
    );
  })();

  /* ── _fCost: monthly-spend chips (cost tab) ──────────────────────────────── */
  (function () {
    if (!openTab("cost")) {
      rec("_fCost", false, "cost tab did not activate");
      return;
    }
    driveChip("_fCost", "#cost-fb", ".fb-btn", "#cost-c", function () {
      return textOf("#cost-c");
    });
  })();

  /* ── noInlineHandlers: DOM sweep over the FULLY RENDERED page ────────────
     Every tab has been opened by the blocks above, so every builder's markup is
     in the DOM. Any element carrying an `on*` attribute here is a control the
     meta-CSP silently kills. This is the half the static guard
     (scanner/tests/test_dashboard_no_inline_handlers.py) structurally cannot
     reach: that scan strips `<script>` bodies, and this dashboard emits nearly
     all of its markup as JS strings inside its one script block. Runs last so it
     also sees markup produced by the filter/expand clicks above. */
  (function () {
    var offenders = [];
    var all = document.querySelectorAll("*");
    for (var i = 0; i < all.length; i++) {
      var attrs = all[i].attributes;
      for (var j = 0; j < attrs.length; j++) {
        if (/^on[a-z]+$/i.test(attrs[j].name)) {
          offenders.push(all[i].tagName.toLowerCase() + "[" + attrs[j].name + "]");
        }
      }
    }
    rec(
      "noInlineHandlers",
      offenders.length === 0,
      offenders.length
        ? "CSP-dead inline handler(s) in the rendered DOM: " + offenders.slice(0, 10).join(", ")
        : "scanned " + all.length + " elements, 0 inline on* attributes"
    );
  })();

  /* ── EXPLICIT SKIPS (recorded, not silently omitted) ─────────────────────── */

  /* _fPS2: the dispatcher carries a `_fPS2` case, but the only markup that emits
     data-action="_fPS2" is renderSec(), which is unreachable — render() registers
     `renderers.sec = renderSecUnified`, so renderSec() never runs. Nothing to
     click. This is the SAFE direction of the mismatch (a dispatcher case with no
     emitter, guarded by `&& window._fPS2` so a stray click is a no-op); the
     dangerous direction (an emitter with no case) is what the driven assertions
     above cover. Reported as dead code, deliberately not deleted here. */
  rec("_fPS2", true, "SKIP: only emitted by renderSec(), which render() never registers (renderers.sec = renderSecUnified) — dead code, no element to click", true);

  /* toggle-audit: same shape. The `.audit-card` markup is emitted only by
     renderSig(), which is never registered in `renderers` AND writes into a panel
     id ('p-sig') that does not exist in this template, so it can never run. */
  rec("toggle-audit", true, "SKIP: only emitted by renderSig(), which is unregistered and targets a non-existent #p-sig panel — dead code, no element to click", true);

  return {
    results: results,
    violations: window.__cspViolations || [],
    probes: window.__forbiddenProbes || [],
  };
})();
