/* DetectLens — app.js
 * Vanilla SPA. Views are functions rendering into #view.
 * Built against the /api/* contract; every data view shows inline error
 * states on failure, never a blank page.
 */
(function () {
  "use strict";
  var api = window.DetectLens.api;

  /* ---------------- utils ---------------- */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function fmt(n) { return Number(n || 0).toLocaleString("en-US"); }
  function el(html) {
    var t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }
  function debounce(fn, ms) {
    var t; return function () { var a = arguments, c = this; clearTimeout(t); t = setTimeout(function () { fn.apply(c, a); }, ms); };
  }

  /* ---------------- icons (1.5px stroke, currentColor) ---------------- */
  var ICONS = {
    chev: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>',
    close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>',
    lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
    download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12M6 11l6 6 6-6"/><path d="M4 21h16"/></svg>',
    warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>',
    check: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>',
    spark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/><circle cx="12" cy="12" r="4"/></svg>'
  };
  function icon(name) { return ICONS[name] || ""; }

  /* ---------------- severity (triple-coded: color + shape + label) ---------------- */
  var SEV_ICON = { critical: "\u25CF", high: "\u25B2", medium: "\u25C6", low: "\u25A0", info: "\u25CB" };
  var SEV_ORDER = ["critical", "high", "medium", "low", "info"]; // keys 1-5
  function sevBadge(sev) {
    sev = (sev || "info").toLowerCase();
    if (!SEV_ICON[sev]) sev = "info";
    return '<span class="sev-badge sev-' + sev + '"><span class="sev-icon" aria-hidden="true">' +
      SEV_ICON[sev] + '</span>' + esc(sev) + "</span>";
  }
  function statusPill(st) {
    if (!st) return "";
    var cls = st.toLowerCase().replace(/[^a-z]/g, "");
    return '<span class="status-pill status-' + esc(cls) + '">' + esc(st) + "</span>";
  }
  function kindChip(kind) { return '<span class="kind-chip">' + esc(kind || "") + "</span>"; }
  function mchip(v) { return '<span class="mchip">' + esc(v) + "</span>"; }

  /* ---------------- toast ---------------- */
  function toast(msg, sev) {
    var box = $("#toasts");
    var t = el('<div class="toast sev-' + (sev || "info") + '" role="status"><span>' + esc(msg) + "</span></div>");
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 4000);
  }

  /* ---------------- error state ---------------- */
  function errorState(title, err, onRetry) {
    var wrap = el('<div class="errstate"><h3>' + esc(title) + "</h3></div>");
    var p = document.createElement("p");
    p.textContent = err && err.message ? err.message : "Unknown error";
    wrap.appendChild(p);
    if (err && err.status) {
      var c = document.createElement("div");
      c.className = "mono";
      c.textContent = "HTTP " + err.status + " " + (err.url || "");
      wrap.appendChild(c);
    }
    if (onRetry) {
      var b = el('<button class="btn btn-sm">Retry</button>');
      b.addEventListener("click", onRetry);
      wrap.appendChild(b);
    }
    return wrap;
  }
  function loadingRow(msg) {
    return el('<div class="loading-row"><span class="spin" aria-hidden="true"></span><span>' + esc(msg || "Loading…") + "</span></div>");
  }

  /* ---------------- state ---------------- */
  var state = {
    view: "overview",
    aiMode: "local",      // "local" | "ai"
    provider: null,
    model: null,
    glossary: null,
    glossaryLoading: null,
    cache: {}             // overview, heatmap, findings, rules
  };

  async function refreshAiStatus() {
    try {
      var s = await api.aiStatus();
      state.aiMode = s.mode === "ai" ? "ai" : "local";
      state.provider = s.provider || null;
      state.model = s.model || null;
    } catch (e) {
      state.aiMode = "local"; state.provider = null;
    }
    renderModeChip();
  }
  function renderModeChip() {
    var chip = $("#mode-chip"), label = $("#mode-chip-label");
    if (state.aiMode === "ai") {
      chip.classList.remove("mode-local"); chip.classList.add("mode-ai");
      label.textContent = "\u2726 AI connected" + (state.provider ? ": " + state.provider : "");
      chip.title = "AI provider connected" + (state.model ? " — " + state.model : "");
    } else {
      chip.classList.remove("mode-ai"); chip.classList.add("mode-local");
      label.textContent = "\u25CF Local mode";
      chip.title = "No AI provider configured — all analysis runs locally";
    }
  }

  /* ---------------- drawer ---------------- */
  var drawer = {
    open: function (titleHtml, bodyNode) {
      var d = $("#drawer");
      $("#drawer-title").innerHTML = titleHtml; // titles are built with esc()'d content
      var b = $("#drawer-body"); b.innerHTML = ""; b.appendChild(bodyNode);
      $("#drawer-scrim").hidden = false; d.hidden = false;
      $("#drawer-close").focus();
    },
    close: function () {
      $("#drawer").hidden = true; $("#drawer-scrim").hidden = true;
    },
    isOpen: function () { return !$("#drawer").hidden; }
  };
  $("#drawer-close").addEventListener("click", drawer.close);
  $("#drawer-scrim").addEventListener("click", drawer.close);

  /* ---------------- modal ---------------- */
  var modal = {
    open: function (node) {
      var m = $("#modal"); m.innerHTML = ""; m.appendChild(node);
      $("#modal-scrim").hidden = false; m.hidden = false;
    },
    close: function () { $("#modal").hidden = true; $("#modal-scrim").hidden = true; },
    isOpen: function () { return !$("#modal").hidden; }
  };
  $("#modal-scrim").addEventListener("click", modal.close);

  function cheatsheet() {
    var rows = [
      ["<kbd>j</kbd><kbd>k</kbd>", "Move in lists"],
      ["<kbd>Enter</kbd>", "Open selected row"],
      ["<kbd>/</kbd>", "Focus global search"],
      ["<kbd>?</kbd>", "This cheatsheet"],
      ["<kbd>Esc</kbd>", "Close topmost panel"],
      ["<kbd>[</kbd> <kbd>]</kbd>", "Previous / next finding in drawer"],
      ["<kbd>g</kbd> then <kbd>o</kbd>", "Overview"],
      ["<kbd>g</kbd> then <kbd>h</kbd>", "Heatmap"],
      ["<kbd>g</kbd> then <kbd>f</kbd>", "Findings"],
      ["<kbd>g</kbd> then <kbd>r</kbd>", "Rules"],
      ["<kbd>g</kbd> then <kbd>a</kbd>", "AI Studio"],
      ["<kbd>g</kbd> then <kbd>e</kbd>", "Reports"],
      ["<kbd>g</kbd> then <kbd>s</kbd>", "Settings"]
    ];
    var n = el('<div><h2>Keyboard shortcuts</h2><table class="kbd-table"></table></div>');
    var tb = $("table", n);
    rows.forEach(function (r) {
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + r[0] + "</td><td>" + esc(r[1]) + "</td>";
      tb.appendChild(tr);
    });
    modal.open(n);
  }
  $("#btn-help").addEventListener("click", cheatsheet);
  $("#btn-shortcuts").addEventListener("click", cheatsheet);

  /* ---------------- glossary tooltips ---------------- */
  function ensureGlossary() {
    if (state.glossary) return Promise.resolve(state.glossary);
    if (state.glossaryLoading) return state.glossaryLoading;
    state.glossaryLoading = api.glossary().then(function (g) {
      state.glossary = (g && g.terms) || {};
      return state.glossary;
    }).catch(function () { state.glossary = {}; return {}; });
    return state.glossaryLoading;
  }
  var tip = $("#tooltip");
  function bindGlossary(root) {
    $all("[data-term]", root).forEach(function (n) {
      if (n._glossBound) return; n._glossBound = true;
      n.addEventListener("mouseenter", function () {
        ensureGlossary().then(function (terms) {
          var def = terms[n.getAttribute("data-term")];
          if (!def) return;
          tip.innerHTML = '<span class="tt-term">' + esc(n.getAttribute("data-term")) + "</span>" + esc(def);
          tip.hidden = false;
          var r = n.getBoundingClientRect();
          tip.style.left = Math.min(window.innerWidth - 300, r.left) + "px";
          tip.style.top = (r.bottom + 8) + "px";
        });
      });
      n.addEventListener("mouseleave", function () { tip.hidden = true; });
    });
  }

  /* ---------------- router ---------------- */
  function navigate(view, arg) {
    state.view = view;
    $all(".rail-btn[data-view]").forEach(function (b) {
      b.classList.toggle("is-active", b.getAttribute("data-view") === view);
    });
    var v = $("#view"); v.innerHTML = "";
    v.appendChild(loadingRow("Loading " + view + "…"));
    (window.DetectLens.VIEWS[view] || function (r) {
      r.innerHTML = ""; r.appendChild(errorState("Unknown view", { message: "No view registered for '" + view + "'" }));
    })(v, arg);
    v.focus({ preventScroll: true });
  }
  $all(".rail-btn[data-view]").forEach(function (b) {
    b.addEventListener("click", function () { navigate(b.getAttribute("data-view")); });
  });

  /* ---------------- list keyboard (j/k/enter) ---------------- */
  function listNav(container, onOpen) {
    var rows = $all(".frow", container);
    var idx = -1;
    function select(i) {
      rows.forEach(function (r) { r.classList.remove("is-selected"); });
      idx = Math.max(0, Math.min(rows.length - 1, i));
      if (rows[idx]) { rows[idx].classList.add("is-selected"); rows[idx].scrollIntoView({ block: "nearest" }); }
    }
    return {
      key: function (e) {
        if (e.key === "j") { select(idx + 1); e.preventDefault(); return true; }
        if (e.key === "k") { select(idx - 1); e.preventDefault(); return true; }
        if (e.key === "Enter" && idx >= 0 && rows[idx]) { onOpen(rows[idx], idx); e.preventDefault(); return true; }
        return false;
      },
      refresh: function () { rows = $all(".frow", container); idx = -1; }
    };
  }
  var activeListNav = null;

  /* ---------------- global keyboard ---------------- */
  var pendingG = false;
  document.addEventListener("keydown", function (e) {
    var tag = (e.target.tagName || "").toLowerCase();
    var typing = tag === "input" || tag === "textarea" || tag === "select" || e.target.isContentEditable;
    if (e.key === "Escape") {
      if (modal.isOpen()) modal.close();
      else if (drawer.isOpen()) drawer.close();
      else if (state.view === "findings" && drawer._findingNav) { drawer._findingNav = null; }
      else if ($("#onboard").hidden === false) skipOnboard();
      return;
    }
    if (typing) return;
    if (activeListNav && activeListNav.key(e)) return;
    if (e.key === "/") { e.preventDefault(); $("#global-search").focus(); return; }
    if (e.key === "?") { e.preventDefault(); cheatsheet(); return; }
    if (e.key === "[" || e.key === "]") {
      if (drawer.isOpen() && drawer._findingNav) { drawer._findingNav(e.key === "]" ? 1 : -1); e.preventDefault(); }
      return;
    }
    if (pendingG) {
      pendingG = false;
      var map = { o: "overview", h: "heatmap", f: "findings", r: "rules", a: "ai", e: "reports", s: "settings" };
      if (map[e.key]) { e.preventDefault(); navigate(map[e.key]); }
      return;
    }
    if (e.key === "g") { pendingG = true; setTimeout(function () { pendingG = false; }, 800); }
  });

  /* ---------------- backend health ---------------- */
  async function checkBackend() {
    try {
      var h = await api.health();
      if (h && h.ok) { $("#backend-banner").hidden = true; return true; }
    } catch (e) { /* fall through */ }
    $("#backend-banner").hidden = false;
    return false;
  }
  $("#btn-retry-backend").addEventListener("click", function () {
    checkBackend().then(function (ok) { if (ok) { state.cache = {}; navigate(state.view); toast("Backend reachable", "low"); } });
  });

  /* ---------------- markdown (report preview) ---------------- */
  function mdToHtml(md) {
    var lines = String(md || "").split("\n");
    var html = "", inList = false, inTable = false, inCode = false, codeBuf = [];
    function inline(s) {
      s = esc(s);
      s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
      s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
      return s;
    }
    function closeBlocks() {
      if (inList) { html += "</ul>"; inList = false; }
      if (inTable) { html += "</tbody></table>"; inTable = false; }
    }
    lines.forEach(function (ln) {
      if (/^```/.test(ln)) {
        if (inCode) { html += "<pre><code>" + esc(codeBuf.join("\n")) + "</code></pre>"; codeBuf = []; inCode = false; }
        else { closeBlocks(); inCode = true; }
        return;
      }
      if (inCode) { codeBuf.push(ln); return; }
      var hm = ln.match(/^(#{1,3})\s+(.*)/);
      if (hm) { closeBlocks(); html += "<h" + hm[1].length + ">" + inline(hm[2]) + "</h" + hm[1].length + ">"; return; }
      if (/^\s*[-*]\s+/.test(ln)) {
        closeBlocks() || true;
        if (inTable) { html += "</tbody></table>"; inTable = false; }
        if (!inList) { html += "<ul>"; inList = true; }
        html += "<li>" + inline(ln.replace(/^\s*[-*]\s+/, "")) + "</li>"; return;
      }
      if (/^\|.*\|$/.test(ln)) {
        if (/^\|[\s:\-|]+\|$/.test(ln)) return; // separator row
        if (!inTable) { closeBlocks(); html += '<table><tbody>'; inTable = true; }
        var cells = ln.split("|").slice(1, -1).map(function (c) { return "<td>" + inline(c.trim()) + "</td>"; }).join("");
        html += "<tr>" + cells + "</tr>"; return;
      }
      if (/^\s*$/.test(ln)) { closeBlocks(); return; }
      closeBlocks();
      html += "<p>" + inline(ln) + "</p>";
    });
    closeBlocks();
    return html;
  }

  function downloadFile(name, text, mime) {
    var blob = new Blob([text], { type: mime || "text/plain" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  /* expose internals to view functions below */
  var DL = { esc: esc, $, $all: $all, fmt: fmt, el: el, icon: icon, sevBadge: sevBadge,
    statusPill: statusPill, kindChip: kindChip, mchip: mchip, toast: toast,
    errorState: errorState, loadingRow: loadingRow, state: state, drawer: drawer,
    modal: modal, cheatsheet: cheatsheet, bindGlossary: bindGlossary,
    navigate: navigate, listNav: listNav, mdToHtml: mdToHtml, downloadFile: downloadFile,
    refreshAiStatus: refreshAiStatus, debounce: debounce };
  DL.setActiveListNav = function (n) { activeListNav = n; };
  window.DetectLens.DL = DL;
})();

/* ---------------- VIEW: Overview ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;

  function scoreRing(score) {
    score = Math.max(0, Math.min(100, Math.round(score || 0)));
    var r = 38, c = 2 * Math.PI * r;
    var color = score >= 70 ? "var(--status-contained)" : score >= 40 ? "var(--sev-medium)" : "var(--sev-critical)";
    return '<svg class="score-ring" viewBox="0 0 88 88" role="img" aria-label="Posture score ' + score + ' of 100">' +
      '<circle cx="44" cy="44" r="' + r + '" fill="none" stroke="var(--bg-raised)" stroke-width="8"/>' +
      '<circle cx="44" cy="44" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="8" ' +
      'stroke-linecap="round" stroke-dasharray="' + (c * score / 100).toFixed(1) + " " + c.toFixed(1) +
      '" transform="rotate(-90 44 44)"/>' +
      '<text x="44" y="50" text-anchor="middle" fill="var(--text-primary)" font-size="20" font-weight="600" font-family="JetBrains Mono, monospace">' +
      score + "</text></svg>";
  }

  function kpi(label, value, sub, valueClass) {
    return '<div class="kpi"><div class="kpi-label">' + DL.esc(label) + '</div>' +
      '<div class="kpi-value ' + (valueClass || "") + '">' + value + "</div>" +
      (sub ? '<div class="kpi-sub">' + sub + "</div>" : "") + "</div>";
  }

  function renderOverview(root) {
    root.innerHTML = "";
    var head = DL.el('<div class="view-head"><div><div class="view-title">Detection posture</div>' +
      '<div class="view-sub">How well the deployed Wazuh ruleset covers ATT&amp;CK, and where it is weak. Coverage % means techniques with at least one mapped rule.</div></div></div>');
    root.appendChild(head);
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading posture overview…"));

    api.overview().then(function (o) {
      DL.state.cache.overview = o;
      body.innerHTML = "";
      var t = o.totals || {};
      var covPct = t.techniques ? Math.round(100 * ((t.covered || 0) + (t.partial || 0)) / t.techniques) : 0;

      var strip = DL.el('<div class="kpi-strip"></div>');
      var scoreCard = DL.el('<div class="kpi" style="display:flex;gap:16px;align-items:center"></div>');
      scoreCard.innerHTML = scoreRing(o.posture_score) +
        '<div><div class="kpi-label">Posture score</div><div class="kpi-sub">Window: <span class="mono">' +
        DL.esc(o.window_days || "—") + " days</span> of alerts</div></div>";
      strip.appendChild(scoreCard);
      strip.innerHTML += kpi("ATT&CK coverage", '<span class="mono">' + covPct + "%</span>",
        DL.esc(t.covered || 0) + " covered / " + DL.esc(t.techniques || 0) + " techniques · " + DL.esc(t.partial || 0) + " partial");
      strip.innerHTML += kpi("Dead rules", '<span class="mono sev-critical">' + DL.fmt(t.dead) + "</span>",
        "rules that never fired in window");
      strip.innerHTML += kpi("Noisy rules", '<span class="mono sev-medium">' + DL.fmt(t.noisy) + "</span>",
        "fire rate above noise threshold");
      strip.innerHTML += kpi("Alerts", '<span class="mono">' + DL.fmt(t.alerts) + "</span>",
        DL.esc(t.rules_fired || 0) + " of " + DL.fmt(t.rules) + " rules fired");
      strip.innerHTML += kpi("Healthy rules", '<span class="mono" style="color:var(--status-contained)">' + DL.fmt(t.healthy) + "</span>",
        "of " + DL.fmt(t.rules) + " total rules");
      body.appendChild(strip);

      var grid = DL.el('<div class="grid-2"></div>');
      // coverage by tactic
      var tacticCard = DL.el('<div class="card"><div class="card-title">Coverage by tactic</div></div>');
      var cbt = o.coverage_by_tactic || {};
      var names = Object.keys(cbt);
      if (!names.length) {
        tacticCard.appendChild(DL.el('<div class="empty"><h3>No tactic data</h3><p>The overview response contained no coverage-by-tactic breakdown.</p></div>'));
      } else {
        names.forEach(function (name) {
          var d = cbt[name] || {}, total = d.total || 1;
          var pc = Math.round(100 * (d.covered || 0) / total),
              pp = Math.round(100 * (d.partial || 0) / total);
          var row = DL.el('<div class="tactic-bar"><div class="tactic-bar-head">' +
            '<span class="tactic-name">' + DL.esc(name) + '</span>' +
            '<span class="mono">' + DL.esc(d.covered || 0) + "/" + DL.esc(total) + "</span></div>" +
            '<div class="bar-track" role="img" aria-label="' + DL.esc(name) + ': ' + pc + '% covered">' +
            '<div class="bar-seg bar-covered" style="width:' + pc + '%"></div>' +
            '<div class="bar-seg bar-partial" style="width:' + pp + '%"></div>' +
            "</div></div>");
          tacticCard.appendChild(row);
        });
        tacticCard.appendChild(DL.el('<div class="legend">' +
          '<span class="legend-item"><span class="legend-swatch" style="background:var(--accent)"></span>covered</span>' +
          '<span class="legend-item"><span class="legend-swatch" style="background:var(--sev-medium)"></span>partial</span>' +
          '<span class="legend-item"><span class="legend-swatch" style="background:var(--bg-input);border:1px solid var(--border-strong)"></span>uncovered</span>' +
          "</div>"));
      }
      grid.appendChild(tacticCard);

      // heatmap preview
      var prevCard = DL.el('<div class="card"><div class="card-title">Heatmap preview <span class="mono">— top tactics</span></div></div>');
      var prevWrap = DL.el('<div class="heatmap-wrap"></div>');
      prevCard.appendChild(prevWrap);
      var goBtn = DL.el('<button class="btn btn-ghost btn-sm" style="margin-top:12px">Open full heatmap</button>');
      goBtn.addEventListener("click", function () { DL.navigate("heatmap"); });
      prevCard.appendChild(goBtn);
      grid.appendChild(prevCard);
      body.appendChild(grid);

      api.heatmap().then(function (h) {
        DL.state.cache.heatmap = h;
        prevWrap.appendChild(heatmapSvg(h, { preview: true, maxCols: 7 }));
        DL.bindGlossary(prevCard);
      }).catch(function (e) {
        prevWrap.appendChild(DL.errorState("Heatmap preview failed", e, function () { DL.navigate("overview"); }));
      });

      // top findings
      var fCard = DL.el('<div class="card"><div class="card-title">Top findings</div><div class="topfindings"></div></div>');
      var list = $(".topfindings", fCard);
      var tf = o.top_findings || [];
      if (!tf.length) {
        list.appendChild(DL.el('<div class="empty"><h3>No findings</h3><p>Nothing flagged in this window. Open the findings view to run a fresh review.</p><button class="btn btn-sm">Open findings</button></div>'));
        $("button", list).addEventListener("click", function () { DL.navigate("findings"); });
      } else {
        tf.slice(0, 6).forEach(function (f) {
          var b = DL.el('<button class="topfinding"></button>');
          b.innerHTML = DL.sevBadge(f.severity) +
            '<span class="tf-title">' + DL.esc(f.title || f.id) + "</span>" +
            '<span class="tf-meta">' + DL.kindChip(f.kind) + DL.statusPill(f.status) + "</span>";
          b.addEventListener("click", function () { DL.navigate("findings", { open: f.id }); });
          list.appendChild(b);
        });
      }
      body.appendChild(fCard);
      DL.bindGlossary(body);
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load overview", e, function () { DL.navigate("overview"); }));
    });
  }

  /* Shared heatmap SVG builder. preview=true renders a compact strip. */
  function heatmapSvg(h, opts) {
    opts = opts || {};
    var tactics = (h.tactics || []).slice();
    if (opts.preview) tactics = tactics.slice(0, opts.maxCols || 7);
    var byTactic = {};
    tactics.forEach(function (t) { byTactic[t] = []; });
    (h.cells || []).forEach(function (c) {
      if (byTactic[c.tactic]) byTactic[c.tactic].push(c);
    });
    var CELL = opts.preview ? 26 : 44, GAP = 6, COLW = opts.preview ? 0 : 120;
    var svgNS = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("class", "heatmap-svg");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "ATT&CK coverage heatmap");

    var maxRule = 1;
    (h.cells || []).forEach(function (c) { maxRule = Math.max(maxRule, c.rule_count || 0); });

    var x = 0, maxH = 0;
    tactics.forEach(function (tactic) {
      var cells = byTactic[tactic];
      var cols = 1;
      if (!opts.preview) cols = Math.max(1, Math.min(3, Math.ceil(Math.sqrt(cells.length / 6))));
      var colW = opts.preview ? cells.length * (CELL + GAP) : cols * (CELL + GAP);
      var g = document.createElementNS(svgNS, "g");
      g.setAttribute("transform", "translate(" + x + ",0)");

      var label = document.createElementNS(svgNS, "text");
      label.setAttribute("class", "hm-col-label");
      label.setAttribute("x", "2"); label.setAttribute("y", "14");
      label.textContent = tactic.length > (opts.preview ? 18 : 26) ? tactic.slice(0, opts.preview ? 17 : 25) + "…" : tactic;
      g.appendChild(label);

      var y = 24;
      cells.forEach(function (c, i) {
        var cx = opts.preview ? i * (CELL + GAP) : (i % cols) * (CELL + GAP);
        var cy = opts.preview ? y : y + Math.floor(i / cols) * (CELL + GAP);
        var state2 = (c.state || "uncovered").toLowerCase();
        var rect = document.createElementNS(svgNS, "rect");
        rect.setAttribute("x", cx); rect.setAttribute("y", cy);
        rect.setAttribute("width", CELL); rect.setAttribute("height", CELL);
        rect.setAttribute("rx", "4"); rect.setAttribute("class", "cell");
        var intensity = 0.15 + 0.85 * Math.min(1, (c.rule_count || 0) / maxRule);
        if (state2 === "covered") {
          rect.setAttribute("fill", "rgba(56,189,248," + (0.35 * intensity).toFixed(2) + ")");
          rect.setAttribute("stroke", "rgba(56,189,248,.55)");
        } else if (state2 === "partial") {
          rect.setAttribute("fill", "rgba(253,176,34," + (0.30 * intensity).toFixed(2) + ")");
          rect.setAttribute("stroke", "rgba(253,176,34,.55)");
        } else {
          rect.setAttribute("fill", "transparent");
          rect.style.stroke = "var(--border-strong)"; // presentation attrs don't support var()
          rect.setAttribute("stroke-dasharray", "3 3");
        }
        var wrap = document.createElementNS(svgNS, "g");
        wrap.setAttribute("class", "hm-cell");
        wrap.setAttribute("tabindex", "0");
        wrap.setAttribute("role", "button");
        wrap.setAttribute("aria-label", c.technique_id + " " + c.name + " — " + state2 +
          ", " + (c.rule_count || 0) + " rules, " + (c.fire_count || 0) + " fires");
        wrap.appendChild(rect);
        wrap._cell = c;
        if (!opts.preview) {
          wrap.addEventListener("click", function () { DL.navigate("heatmap", { select: c.technique_id }); });
          wrap.addEventListener("keydown", function (ev) {
            if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); DL.navigate("heatmap", { select: c.technique_id }); }
          });
        }
        // hover tooltip via native title is noisy; use custom cell tooltip
        wrap.addEventListener("mouseenter", function (ev) { showCellTip(c, ev); });
        wrap.addEventListener("mouseleave", hideCellTip);
        g.appendChild(wrap);
        if (!opts.preview) {
          var totalH = y + (Math.floor((cells.length - 1) / cols) + 1) * (CELL + GAP);
          maxH = Math.max(maxH, totalH);
        } else {
          maxH = Math.max(maxH, y + CELL + GAP);
        }
      });
      svg.appendChild(g);
      x += (opts.preview ? cells.length * (CELL + GAP) : cols * (CELL + GAP)) + (opts.preview ? 16 : 28);
    });
    svg.setAttribute("width", Math.max(1, x));
    svg.setAttribute("height", Math.max(1, maxH));
    svg.setAttribute("viewBox", "0 0 " + Math.max(1, x) + " " + Math.max(1, maxH));
    return svg;
  }

  var cellTip = null;
  function showCellTip(c, ev) {
    hideCellTip();
    cellTip = DL.el('<div class="tooltip"><span class="tt-term">' + DL.esc(c.technique_id) + " — " + DL.esc(c.name) +
      '</span><div class="mono" style="font-size:11px;color:var(--text-secondary)">' +
      DL.esc(c.state) + " · " + DL.fmt(c.rule_count) + " rules · " + DL.fmt(c.fire_count) + " fires</div></div>");
    document.body.appendChild(cellTip);
    cellTip.style.left = Math.min(window.innerWidth - 300, ev.clientX + 12) + "px";
    cellTip.style.top = (ev.clientY + 12) + "px";
  }
  function hideCellTip() { if (cellTip) { cellTip.remove(); cellTip = null; } }

  /* ---------------- VIEW: Heatmap ---------------- */
  function renderHeatmap(root, arg) {
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">Coverage heatmap</div>' +
      '<div class="view-sub">Tactics as columns, techniques as cells. Covered cells fill with accent; partial fills amber; uncovered cells are dashed outlines. Intensity scales with mapped rule count. Click a cell for detail.</div></div></div>'));
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading heatmap…"));

    Promise.all([
      api.heatmap(),
      api.rules().catch(function () { return { rules: [] }; })
    ]).then(function (res) {
      var h = res[0], rules = res[1].rules || [];
      DL.state.cache.heatmap = h; DL.state.cache.rules = rules;
      body.innerHTML = "";
      var detail = DL.el('<div class="heatmap-detail"></div>');
      var wrap = DL.el('<div class="card"><div class="heatmap-wrap"></div></div>');
      wrap.firstChild.appendChild(heatmapSvg(h, {}));
      wrap.firstChild.appendChild(DL.el('<div class="legend">' +
        '<span class="legend-item"><span class="legend-swatch" style="background:rgba(56,189,248,.35)"></span>covered</span>' +
        '<span class="legend-item"><span class="legend-swatch" style="background:rgba(253,176,34,.3)"></span>partial</span>' +
        '<span class="legend-item"><span class="legend-swatch" style="background:transparent;border:1px dashed var(--border-strong)"></span>uncovered</span>' +
        '<span class="legend-item">darker = more mapped rules</span></div>'));
      var side = DL.el('<div class="card" id="hm-side"><div class="card-title">Technique detail</div></div>');
      detail.appendChild(wrap); detail.appendChild(side);
      body.appendChild(detail);

      var rulesByTech = {};
      rules.forEach(function (r) {
        (r.mitre_ids || []).forEach(function (t) {
          (rulesByTech[t] = rulesByTech[t] || []).push(r);
        });
      });

      function selectCell(techId) {
        var cell = (h.cells || []).find(function (c) { return c.technique_id === techId; });
        side.innerHTML = '<div class="card-title">Technique detail</div>';
        if (!cell) {
          side.appendChild(DL.el('<div class="empty"><h3>Nothing selected</h3><p>Click a heatmap cell to see its mapped rules and fire counts.</p></div>'));
          return;
        }
        var mapped = rulesByTech[cell.technique_id] || [];
        var info = DL.el("<div></div>");
        info.innerHTML =
          '<div style="margin-bottom:12px"><span class="mono" style="color:var(--accent-hover);font-size:12px">' + DL.esc(cell.technique_id) + "</span>" +
          '<div style="font-size:14px;font-weight:600;margin-top:4px">' + DL.esc(cell.name) + "</div>" +
          '<div style="font-size:11px;color:var(--text-tertiary);margin-top:4px">' + DL.esc(cell.tactic) + " · " + DL.esc(cell.state) + "</div></div>" +
          '<div class="facts">' +
          '<div class="fact"><div class="fact-label">Mapped rules</div><div class="fact-value mono">' + DL.fmt(cell.rule_count) + "</div></div>" +
          '<div class="fact"><div class="fact-label">Fires in window</div><div class="fact-value mono">' + DL.fmt(cell.fire_count) + "</div></div>" +
          "</div>";
        side.appendChild(info);
        if (mapped.length) {
          var tbl = DL.el('<table class="data"><thead><tr><th>Rule</th><th>Level</th><th>Fires</th></tr></thead><tbody></tbody></table>');
          var tb = $("tbody", tbl);
          mapped.slice(0, 12).forEach(function (r) {
            var tr = document.createElement("tr");
            tr.innerHTML = "<td>" + DL.mchip(r.id) + "</td><td>" + DL.esc(r.level) + "</td>" +
              '<td class="mono">' + DL.fmt(r.fire_count) + "</td>";
            tb.appendChild(tr);
          });
          side.appendChild(tbl);
          if (mapped.length > 12) side.appendChild(DL.el('<div class="kpi-sub" style="margin-top:8px">+' + (mapped.length - 12) + " more mapped rules</div>"));
        } else {
          side.appendChild(DL.el('<div class="empty" style="padding:16px"><h3>No mapped rules</h3><p>This technique has no rule coverage in the deployed ruleset.</p></div>'));
        }
        var cta = DL.el('<button class="btn btn-primary btn-sm" style="margin-top:16px;width:100%">Draft rule for ' + DL.esc(cell.technique_id) + "</button>");
        cta.addEventListener("click", function () { DL.navigate("ai", { technique: cell.technique_id }); });
        side.appendChild(cta);
        DL.bindGlossary(side);
      }
      selectCell(arg && arg.select ? arg.select : null);
      // store selector so clicking cells without re-navigate updates panel
      $all(".hm-cell", wrap).forEach(function (w) {
        w.addEventListener("click", function () { selectCell(w._cell.technique_id); });
      });
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load heatmap", e, function () { DL.navigate("heatmap"); }));
    });
  }

  var V = window.DetectLens.VIEWS || (window.DetectLens.VIEWS = {});
  V.overview = renderOverview;
  V.heatmap = renderHeatmap;
  V._heatmapSvg = heatmapSvg;
})();

/* ---------------- VIEW: Findings ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;
  var KINDS = ["all", "dead", "noisy", "gap", "telemetry"];
  // Chip keys are display labels; finding.kind values are the full names.
  var KIND_MAP = { dead: "dead_rule", noisy: "noisy_rule", gap: "coverage_gap", telemetry: "missing_telemetry" };
  DL.KIND_MAP = KIND_MAP; // shared with the AI Studio query applier

  function renderFindings(root, arg) {
    DL.setActiveListNav(null);
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">Findings</div>' +
      '<div class="view-sub">Dead and noisy rules, coverage gaps, and missing telemetry. Filter by kind or severity (keys 1–5). <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>Enter</kbd> opens.</div></div></div>'));
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading findings…"));

    api.findings().then(function (res) {
      DL.state.cache.findings = res.findings || [];
      body.innerHTML = "";
      // Initial filters may arrive via navigate("findings", {kind, severity}).
      var fKind = (arg && arg.kind && KIND_MAP[arg.kind]) ? arg.kind : "all";
      var fSev = (arg && arg.severity) ? String(arg.severity).toLowerCase() : null;
      var toolbar = DL.el('<div class="toolbar"></div>');
      var chipRow = DL.el('<div class="chips" role="group" aria-label="Kind filter"></div>');
      KINDS.forEach(function (k) {
        var c = DL.el('<button class="chip' + (k === fKind ? " is-active" : "") + '">' + DL.esc(k) + "</button>");
        c.addEventListener("click", function () {
          fKind = k;
          $all(".chip", chipRow).forEach(function (x) { x.classList.remove("is-active"); });
          c.classList.add("is-active");
          renderList();
        });
        chipRow.appendChild(c);
      });
      var sevHint = DL.el('<span class="kpi-sub">severity keys: <span class="mono">1</span> critical · <span class="mono">2</span> high · <span class="mono">3</span> medium · <span class="mono">4</span> low · <span class="mono">5</span> info</span>');
      toolbar.appendChild(chipRow); toolbar.appendChild(sevHint);
      body.appendChild(toolbar);
      var list = DL.el('<div class="list-stack" role="list"></div>');
      body.appendChild(list);

      var filtered = [];
      function current() {
        return DL.state.cache.findings.filter(function (f) {
          if (fKind !== "all" && (f.kind || "") !== (KIND_MAP[fKind] || fKind)) return false;
          if (fSev && (f.severity || "info").toLowerCase() !== fSev) return false;
          return true;
        });
      }
      function renderList() {
        list.innerHTML = "";
        filtered = current();
        if (!filtered.length) {
          var e = DL.el('<div class="empty"><h3>No findings match</h3><p>' +
            (fKind === "all" && !fSev ? "No findings were returned for this window." : "Try clearing the kind or severity filter.") +
            "</p></div>");
          list.appendChild(e);
        } else {
          filtered.forEach(function (f) {
            var row = DL.el('<button class="frow" role="listitem"></button>');
            row.setAttribute("data-id", f.id);
            var chips = DL.kindChip(f.kind);
            (f.technique_ids || []).slice(0, 3).forEach(function (t) { chips += DL.mchip(t); });
            (f.rule_ids || []).slice(0, 3).forEach(function (r) { chips += DL.mchip(r); });
            var counts = f.counts || {};
            var countVal = counts.fires != null ? counts.fires : (counts.rules != null ? counts.rules : "");
            row.innerHTML = DL.sevBadge(f.severity) +
              '<span class="frow-title">' + DL.esc(f.title || f.id) + "</span>" +
              '<span class="frow-chips">' + chips + "</span>" +
              (countVal !== "" ? '<span class="frow-count">' + DL.fmt(countVal) + "</span>" : "") +
              '<span class="frow-chev">' + DL.icon("chev") + "</span>";
            row.addEventListener("click", function () { openFinding(f.id); });
            list.appendChild(row);
          });
        }
        var nav = DL.listNav(list, function (row) { openFinding(row.getAttribute("data-id")); });
        DL.setActiveListNav(nav);
      }
      renderList();

      // severity filter keys 1-5
      var sevKeyHandler = function (e) {
        var tag = (e.target.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea") return;
        var i = ["1", "2", "3", "4", "5"].indexOf(e.key);
        if (i >= 0 && DL.state.view === "findings" && !DL.drawer.isOpen()) {
          fSev = DL.state._fSev === DL.SEV_ORDER[i] ? null : DL.SEV_ORDER[i];
          DL.state._fSev = fSev;
          renderList();
          DL.toast(fSev ? "Severity filter: " + fSev : "Severity filter cleared", fSev || "info");
        }
      };
      DL.state._fSev = null;
      if (!DL._sevKeyBound) {
        DL._sevKeyBound = true;
        document.addEventListener("keydown", sevKeyHandler);
      }

      if (arg && arg.open) openFinding(arg.open);
      DL.bindGlossary(body);
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load findings", e, function () { DL.navigate("findings"); }));
    });
  }
  DL.SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  function openFinding(id) {
    var cached = (DL.state.cache.findings || []).find(function (f) { return String(f.id) === String(id); });
    var body = DL.el("<div></div>");
    body.appendChild(DL.loadingRow("Loading finding…"));
    DL.drawer.open('<span class="mono" style="font-size:11px;color:var(--text-tertiary)">finding</span><div>' + DL.esc(id) + "</div>", body);

    function stepFinding(dir) {
      var list = DL.state.cache.findings || [];
      var i = list.findIndex(function (f) { return String(f.id) === String(id); });
      var n = list[(i + dir + list.length) % list.length];
      if (n) openFinding(n.id);
    }
    DL.drawer._findingNav = stepFinding;

    api.finding(id).then(function (res) {
      var f = res.finding || res || cached || { id: id };
      renderFindingDrawer(body, f);
    }).catch(function (e) {
      if (cached) { renderFindingDrawer(body, cached); DL.toast("Detail endpoint failed; showing list data", "medium"); }
      else { body.innerHTML = ""; body.appendChild(DL.errorState("Could not load finding " + id, e, function () { openFinding(id); })); }
    });
  }

  function renderFindingDrawer(body, f) {
    body.innerHTML = "";
    var head = DL.el("<div></div>");
    head.innerHTML = '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap">' +
      DL.sevBadge(f.severity) + DL.kindChip(f.kind) + DL.statusPill(f.status) + "</div>" +
      '<div style="font-size:15px;font-weight:600;margin-bottom:8px">' + DL.esc(f.title || f.id) + "</div>";
    body.appendChild(head);

    var tabs = DL.el('<div class="drawer-tabs" role="tablist"></div>');
    var panes = DL.el("<div></div>");
    body.appendChild(tabs); body.appendChild(panes);
    var tabNames = ["Overview", "Evidence", "AI analysis", "Lesson"];

    function factsGrid(pairs) {
      var g = DL.el('<div class="facts"></div>');
      pairs.forEach(function (p) {
        g.appendChild(DL.el('<div class="fact"><div class="fact-label">' + DL.esc(p[0]) + '</div><div class="fact-value' + (p[2] ? " mono" : "") + '">' + p[1] + "</div></div>"));
      });
      return g;
    }

    var panesHtml = {
      "Overview": function (p) {
        if (f.explanation) p.appendChild(DL.el('<p style="font-size:12px;color:var(--text-secondary);margin-bottom:8px">' + DL.esc(f.explanation) + "</p>"));
        var counts = f.counts || {};
        var pairs = [
          ["Finding id", DL.esc(f.id), true],
          ["Kind", DL.esc(f.kind || "—"), false],
          ["Severity", DL.sevBadge(f.severity), false],
          ["Status", f.status ? DL.statusPill(f.status) : "—", false]
        ];
        Object.keys(counts).slice(0, 4).forEach(function (k) {
          pairs.push([k.replace(/_/g, " "), DL.fmt(counts[k]), true]);
        });
        p.appendChild(factsGrid(pairs));
      },
      "Evidence": function (p) {
        var rules = f.rule_ids || [], techs = f.technique_ids || [];
        if (rules.length) {
          var tbl = DL.el('<table class="data"><thead><tr><th>Rule</th></tr></thead><tbody></tbody></table>');
          var tb = $("tbody", tbl);
          rules.forEach(function (r) {
            var tr = document.createElement("tr");
            tr.innerHTML = "<td>" + DL.mchip(r) + "</td>";
            tb.appendChild(tr);
          });
          p.appendChild(DL.el('<div class="card-title">Mapped rules</div>'));
          p.appendChild(tbl);
        }
        if (techs.length) {
          p.appendChild(DL.el('<div class="card-title" style="margin-top:16px">Techniques</div>'));
          var tc = DL.el('<div style="display:flex;gap:6px;flex-wrap:wrap"></div>');
          techs.forEach(function (t) { tc.appendChild(DL.el(DL.mchip(t))); });
          p.appendChild(tc);
        }
        if (!rules.length && !techs.length) {
          p.appendChild(DL.el('<div class="empty"><h3>No evidence attached</h3><p>This finding carries no mapped rules or techniques in the API response.</p></div>'));
        }
      },
      "AI analysis": function (p) { renderAiAnalysis(p, f); },
      "Lesson": function (p) {
        if (f.lesson) {
          p.appendChild(DL.el('<div class="lesson-card">' + DL.esc(f.lesson) + "</div>"));
        } else {
          p.appendChild(DL.el('<div class="empty"><h3>No lesson recorded</h3><p>The API returned no lesson text for this finding.</p></div>'));
        }
        p.appendChild(DL.el('<div class="kpi-sub">Terms in the lesson may be defined in the glossary — hover dotted terms.</div>'));
      }
    };

    tabNames.forEach(function (name, i) {
      var t = DL.el('<button class="tab' + (i === 0 ? " is-active" : "") + '" role="tab">' + name + "</button>");
      t.addEventListener("click", function () {
        $all(".tab", tabs).forEach(function (x) { x.classList.remove("is-active"); });
        t.classList.add("is-active");
        panes.innerHTML = "";
        var pane = DL.el("<div></div>");
        panesHtml[name](pane);
        panes.appendChild(pane);
        DL.bindGlossary(panes);
      });
      tabs.appendChild(t);
    });
    var first = DL.el("<div></div>");
    panesHtml["Overview"](first);
    panes.appendChild(first);

    var nav = DL.el('<div class="drawer-nav" style="margin-top:16px"><button class="btn btn-ghost btn-sm" id="fprev">← prev [</button><button class="btn btn-ghost btn-sm" id="fnext">next ] →</button></div>');
    body.appendChild(nav);
    $("#fprev", body).addEventListener("click", function () { DL.drawer._findingNav(-1); });
    $("#fnext", body).addEventListener("click", function () { DL.drawer._findingNav(1); });
    DL.bindGlossary(body);
  }

  function renderAiAnalysis(p, f) {
    var wrap = DL.el("<div></div>");
    // Local mode degrades to the deterministic template explanation
    // (backend returns source "template") — never a dead end.
    var note = DL.state.aiMode !== "ai"
      ? DL.el('<div class="kpi-sub" style="margin-bottom:12px">Local mode: showing the built-in explanation template. <a href="#" id="ai-connect-link" style="color:var(--accent)">Connect a provider</a> for AI-written analysis.</div>')
      : null;
    if (note) {
      wrap.appendChild(note);
      $("#ai-connect-link", note).addEventListener("click", function (e) { e.preventDefault(); DL.drawer.close(); DL.navigate("settings"); });
    }
    var btn = DL.el('<button class="btn btn-primary btn-sm">' +
      (DL.state.aiMode === "ai" ? "Explain with AI" : "Show explanation") + "</button>");
    var out = DL.el('<div style="margin-top:12px"></div>');
    btn.addEventListener("click", function () {
      btn.disabled = true;
      out.innerHTML = "";
      out.appendChild(DL.loadingRow(DL.state.aiMode === "ai" ? "Asking provider…" : "Loading explanation…"));
      api.aiExplain(f.id).then(function (r) {
        out.innerHTML = "";
        var card = DL.el('<div class="ai-result"><span class="src">source: ' + DL.esc(r.source || "template") + "</span></div>");
        card.appendChild(document.createTextNode(r.text || "(empty response)"));
        out.appendChild(card);
        if (r.error) DL.toast(r.error, "medium");
      }).catch(function (e) {
        out.innerHTML = "";
        out.appendChild(DL.errorState("Explanation failed", e, null));
      }).then(function () { btn.disabled = false; });
    });
    wrap.appendChild(btn); wrap.appendChild(out);
    p.appendChild(wrap);
  }

  var V = window.DetectLens.VIEWS;
  V.findings = renderFindings;
  DL.openFinding = openFinding;
})();

/* ---------------- VIEW: Rules ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;
  var TABS = ["healthy", "dead", "noisy"];

  function renderRules(root) {
    DL.setActiveListNav(null);
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">Rules</div>' +
      '<div class="view-sub">The deployed Wazuh ruleset, grouped by health. <kbd>j</kbd>/<kbd>k</kbd> move, <kbd>Enter</kbd> opens.</div></div></div>'));
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading rules…"));

    api.rules().then(function (res) {
      var rules = res.rules || [];
      DL.state.cache.rules = rules;
      body.innerHTML = "";
      var tab = "healthy", query = "";
      var tabs = DL.el('<div class="tabs" role="tablist"></div>');
      TABS.forEach(function (t) {
        var n = rules.filter(function (r) { return (r.state || "") === t; }).length;
        var b = DL.el('<button class="tab' + (t === "healthy" ? " is-active" : "") + '" role="tab">' + t + '<span class="mono">' + n + "</span></button>");
        b.addEventListener("click", function () {
          tab = t;
          $all(".tab", tabs).forEach(function (x) { x.classList.remove("is-active"); });
          b.classList.add("is-active");
          renderList();
        });
        tabs.appendChild(b);
      });
      body.appendChild(tabs);
      var toolbar = DL.el('<div class="toolbar"><input class="search-input" id="rule-search" placeholder="Search id, description, group…" aria-label="Search rules"><span class="spacer"></span></div>');
      body.appendChild(toolbar);
      var list = DL.el('<div class="list-stack" role="list"></div>');
      body.appendChild(list);
      var search = $("#rule-search", toolbar);
      search.addEventListener("input", DL.debounce(renderList, 150));

      function renderList() {
        query = (search.value || "").toLowerCase();
        list.innerHTML = "";
        var rows = rules.filter(function (r) {
          if ((r.state || "") !== tab) return false;
          if (!query) return true;
          var hay = [r.id, r.description, (r.groups || []).join(" "), (r.mitre_ids || []).join(" "), r.source_file].join(" ").toLowerCase();
          return hay.indexOf(query) !== -1;
        });
        if (!rows.length) {
          var msg = rules.length ? "No " + tab + " rules match." : "No rules returned by the API.";
          list.appendChild(DL.el('<div class="empty"><h3>' + DL.esc(msg) + "</h3>" +
            '<p>' + (rules.length ? "Try a different search or tab." : "Point the backend at a rules directory and reload.") + "</p></div>"));
        }
        rows.slice(0, 400).forEach(function (r) {
          var row = DL.el('<button class="frow" role="listitem"></button>');
          row.setAttribute("data-id", r.id);
          var chips = "";
          (r.groups || []).slice(0, 3).forEach(function (g) { chips += DL.mchip(g); });
          (r.mitre_ids || []).slice(0, 3).forEach(function (t) { chips += DL.mchip(t); });
          var stateCls = r.state === "dead" ? "sev-critical" : r.state === "noisy" ? "sev-medium" : "sev-info";
          row.innerHTML =
            '<span class="mchip">' + DL.esc(r.id) + "</span>" +
            '<span class="mchip" title="level">' + DL.esc(r.level) + "</span>" +
            '<span class="frow-title">' + DL.esc(r.description || "") + "</span>" +
            '<span class="frow-chips">' + chips + "</span>" +
            '<span class="frow-count">' + DL.fmt(r.fire_count) + "</span>" +
            '<span class="sev-badge ' + stateCls + '">' + DL.esc(r.state || "") + "</span>" +
            '<span class="frow-chev">' + DL.icon("chev") + "</span>";
          row.addEventListener("click", function () { openRule(r.id); });
          list.appendChild(row);
        });
        if (rows.length > 400) list.appendChild(DL.el('<div class="kpi-sub">Showing first 400 of ' + rows.length + " — refine the search.</div>"));
        var nav = DL.listNav(list, function (rw) { openRule(rw.getAttribute("data-id")); });
        DL.setActiveListNav(nav);
      }
      renderList();
      DL.bindGlossary(body);
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load rules", e, function () { DL.navigate("rules"); }));
    });
  }

  function openRule(id) {
    var cached = (DL.state.cache.rules || []).find(function (r) { return String(r.id) === String(id); });
    var body = DL.el("<div></div>");
    body.appendChild(DL.loadingRow("Loading rule…"));
    DL.drawer._findingNav = null;
    DL.drawer.open('<span class="mono" style="font-size:11px;color:var(--text-tertiary)">rule</span><div class="mono">' + DL.esc(id) + "</div>", body);
    api.rule(id).then(function (res) {
      renderRuleDrawer(body, res.rule || res || cached || { id: id });
    }).catch(function (e) {
      if (cached && cached.xml) { renderRuleDrawer(body, cached); DL.toast("Detail endpoint failed; showing cached rule", "medium"); }
      else { body.innerHTML = ""; body.appendChild(DL.errorState("Could not load rule " + id, e, function () { openRule(id); })); }
    });
  }

  function renderRuleDrawer(body, r) {
    body.innerHTML = "";
    var head = DL.el("<div></div>");
    head.innerHTML = '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">' +
      '<span class="mchip">level ' + DL.esc(r.level) + "</span>" +
      (r.state ? '<span class="sev-badge ' + (r.state === "dead" ? "sev-critical" : r.state === "noisy" ? "sev-medium" : "sev-info") + '">' + DL.esc(r.state) + "</span>" : "") +
      "</div>" +
      '<div style="font-size:14px;font-weight:600;margin-bottom:4px">' + DL.esc(r.description || "") + "</div>" +
      '<div class="mono" style="font-size:11px;color:var(--text-tertiary);margin-bottom:16px">' + DL.esc(r.source_file || "") + " · " + DL.fmt(r.fire_count) + " fires</div>";
    body.appendChild(head);

    var chips = DL.el('<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px"></div>');
    (r.groups || []).forEach(function (g) { chips.appendChild(DL.el(DL.mchip("group:" + g))); });
    (r.mitre_ids || []).forEach(function (t) { chips.appendChild(DL.el(DL.mchip(t))); });
    if (chips.children.length) body.appendChild(chips);

    if (r.xml) {
      body.appendChild(DL.el('<div class="card-title">Rule XML</div>'));
      var pre = DL.el('<pre class="xml-block"></pre>');
      pre.textContent = r.xml;
      body.appendChild(pre);
    } else {
      body.appendChild(DL.el('<div class="empty"><h3>No XML returned</h3><p>The rule detail endpoint did not include XML for this rule.</p></div>'));
    }

    if (r.validation) {
      var v = r.validation;
      var vb = DL.el('<div class="validation ' + (v.ok ? "ok" : "fail") + '">' + DL.icon(v.ok ? "check" : "warn") +
        "<span><strong>" + (v.ok ? "Validation passed" : "Validation failed") + "</strong></span></div>");
      if (!v.ok && v.errors && v.errors.length) {
        var ul = document.createElement("ul");
        v.errors.forEach(function (err) { var li = document.createElement("li"); li.textContent = err; ul.appendChild(li); });
        $("span", vb).appendChild(ul);
      }
      body.appendChild(vb);
    }

    var actions = DL.el('<div class="output-actions"></div>');
    var explainBtn = DL.el('<button class="btn btn-sm">Explain rule</button>');
    explainBtn.addEventListener("click", function () { explainRule(r, body); });
    actions.appendChild(explainBtn);
    if ((r.state || "") === "noisy") {
      var supBtn = DL.el('<button class="btn btn-sm">Propose suppression</button>');
      supBtn.addEventListener("click", function () { proposeSuppression(r, body); });
      actions.appendChild(supBtn);
    }
    var aiOut = DL.el('<div style="margin-top:12px" id="rule-ai-out"></div>');
    body.appendChild(actions); body.appendChild(aiOut);
    DL.bindGlossary(body);
  }

  function explainRule(r, body) {
    var out = $("#rule-ai-out", body);
    // Local mode degrades to the deterministic template summary
    // (backend returns source "template") — never a dead end.
    out.innerHTML = "";
    if (DL.state.aiMode !== "ai") {
      out.appendChild(DL.el('<div class="kpi-sub" style="margin-bottom:12px">Local mode: showing the built-in rule summary. Connect a provider in settings for AI-written analysis.</div>'));
    }
    out.appendChild(DL.loadingRow(DL.state.aiMode === "ai" ? "Asking provider…" : "Loading summary…"));
    // Dedicated rule-explain endpoint (local mode degrades to a template summary).
    api.aiExplainRule(r.id).then(function (res) {
      out.innerHTML = "";
      var card = DL.el('<div class="ai-result"><span class="src">source: ' + DL.esc(res.source || "template") + "</span></div>");
      card.appendChild(document.createTextNode(res.text || "(empty response)"));
      out.appendChild(card);
      if (res.error) DL.toast(res.error, "medium");
    }).catch(function (e) {
      out.innerHTML = "";
      out.appendChild(DL.errorState("Explanation failed", e, null));
    });
  }

  function proposeSuppression(r, body) {
    var out = $("#rule-ai-out", body);
    out.innerHTML = "";
    out.appendChild(DL.loadingRow("Drafting suppression…"));
    api.aiSuppression(String(r.id)).then(function (res) {
      out.innerHTML = "";
      if (res.plan) {
        var pc = DL.el('<div class="lesson-card"></div>');
        pc.textContent = res.plan;
        out.appendChild(pc);
      }
      if (res.xml) {
        var pre = DL.el('<pre class="xml-block"></pre>');
        pre.textContent = res.xml;
        out.appendChild(pre);
      }
      var acts = DL.el('<div class="output-actions"></div>');
      if (res.xml) {
        var cp = DL.el('<button class="btn btn-sm">' + DL.icon("copy") + " Copy XML</button>");
        cp.addEventListener("click", function () {
          navigator.clipboard.writeText(res.xml).then(function () { DL.toast("Suppression XML copied", "low"); });
        });
        acts.appendChild(cp);
      }
      out.appendChild(acts);
      if (res.source) out.appendChild(DL.el('<div class="kpi-sub" style="margin-top:8px">source: ' + DL.esc(res.source) + ". Validate locally before deploying.</div>"));
    }).catch(function (e) {
      out.innerHTML = "";
      out.appendChild(DL.errorState("Suppression draft failed", e, null));
    });
  }

  var V = window.DetectLens.VIEWS;
  V.rules = renderRules;
  DL.openRule = openRule;
})();

/* ---------------- VIEW: AI Studio ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;

  function renderStudio(root, arg) {
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">AI Studio</div>' +
      '<div class="view-sub">Gap to draft to validated rule. Pick an uncovered technique, review the redacted prompt, generate XML.</div></div></div>'));
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading uncovered techniques…"));

    var selTech = arg && arg.technique ? arg.technique : null;

    api.heatmap().then(function (h) {
      DL.state.cache.heatmap = h;
      body.innerHTML = "";
      var uncovered = (h.cells || []).filter(function (c) { return (c.state || "").toLowerCase() === "uncovered"; });

      /* --- Ask about your posture (NL -> filter spec, shown editable first) --- */
      var askCard = DL.el('<div class="card" style="margin-bottom:16px"><div class="card-title">Ask about your posture</div></div>');
      var askRow = DL.el('<div style="display:flex;gap:8px"></div>');
      var askInput = DL.el('<input class="input" style="flex:1" aria-label="Ask about your posture" placeholder=\'e.g. "which persistence techniques lack coverage?"\'>');
      var askBtn = DL.el('<button class="btn btn-primary">Ask</button>');
      askRow.appendChild(askInput); askRow.appendChild(askBtn);
      askCard.appendChild(askRow);
      var askOut = DL.el('<div style="margin-top:12px"></div>');
      if (DL.state.aiMode !== "ai") {
        askCard.appendChild(DL.el('<div class="kpi-sub" style="margin-top:8px">NL queries need a connected provider. Quick filters:</div>'));
        var quick = DL.el('<div class="chips" style="margin-top:8px"></div>');
        [["critical findings", { severity: "critical" }], ["dead rules", { kind: "dead" }], ["noisy rules", { kind: "noisy" }]].forEach(function (q) {
          var b = DL.el('<button class="chip">' + DL.esc(q[0]) + "</button>");
          b.addEventListener("click", function () { DL.navigate("findings", q[1]); });
          quick.appendChild(b);
        });
        askCard.appendChild(quick);
      } else {
        askCard.appendChild(DL.el('<div class="kpi-sub" style="margin-top:8px">The generated filter spec is shown and editable before it runs. Nothing is filtered until you press Apply.</div>'));
      }
      askCard.appendChild(askOut);
      body.appendChild(askCard);

      function applySpec(spec) {
        if (!spec || spec.entity !== "findings") {
          DL.toast("Only findings filters apply automatically — copy the spec for other views.", "medium");
          return;
        }
        var kind = null, sev = null, km = DL.KIND_MAP || {};
        (spec.filters || []).forEach(function (fl) {
          var vals = fl.op === "in" ? fl.value : [fl.value];
          if (!vals || !vals.length) return;
          if (fl.field === "severity" && (fl.op === "eq" || fl.op === "in")) sev = String(vals[0]).toLowerCase();
          if (fl.field === "kind" && (fl.op === "eq" || fl.op === "in")) {
            var v = String(vals[0]);
            kind = Object.keys(km).filter(function (k) { return km[k] === v || k === v; })[0] || null;
          }
        });
        DL.navigate("findings", { kind: kind, severity: sev });
      }

      askBtn.addEventListener("click", function () {
        var q = (askInput.value || "").trim();
        if (!q) return;
        if (DL.state.aiMode !== "ai") { DL.toast("Connect a provider in settings for NL queries.", "medium"); return; }
        askBtn.disabled = true;
        askOut.innerHTML = "";
        askOut.appendChild(DL.loadingRow("Thinking…"));
        api.aiQuery(q).then(function (r) {
          askOut.innerHTML = "";
          if (r.error) DL.toast(r.error, "medium");
          if (!r.spec) {
            askOut.appendChild(DL.el('<div class="kpi-sub">' + DL.esc(r.note || "No filter spec generated.") + "</div>"));
            return;
          }
          var ta = DL.el('<textarea class="input mono" rows="6" style="width:100%;font-size:11px" aria-label="Generated filter spec (editable)"></textarea>');
          ta.value = JSON.stringify(r.spec, null, 2);
          askOut.appendChild(ta);
          var applyRow = DL.el('<div class="output-actions" style="margin-top:8px"></div>');
          var applyBtn = DL.el('<button class="btn btn-sm btn-primary">Apply filters</button>');
          applyBtn.addEventListener("click", function () {
            try {
              applySpec(JSON.parse(ta.value));
            } catch (e) {
              DL.toast("Filter spec is not valid JSON: " + e.message, "high");
            }
          });
          applyRow.appendChild(applyBtn);
          var cp = DL.el('<button class="btn btn-sm">Copy spec</button>');
          cp.addEventListener("click", function () {
            navigator.clipboard.writeText(ta.value).then(function () { DL.toast("Spec copied", "low"); });
          });
          applyRow.appendChild(cp);
          askOut.appendChild(applyRow);
        }).catch(function (e) {
          askOut.innerHTML = "";
          askOut.appendChild(DL.errorState("Query failed", e, null));
        }).then(function () { askBtn.disabled = false; });
      });
      askInput.addEventListener("keydown", function (e) { if (e.key === "Enter") askBtn.click(); });

      var grid = DL.el('<div class="studio-grid"></div>');
      var left = DL.el('<div class="card"><div class="card-title">Uncovered techniques <span class="mono">' + uncovered.length + "</span></div></div>");
      var picker = DL.el('<div class="picker-list" role="listbox" aria-label="Uncovered techniques"></div>');
      left.appendChild(picker);
      var right = DL.el('<div class="card"><div class="card-title">Draft rule</div></div>');
      var rightBody = DL.el("<div></div>");
      right.appendChild(rightBody);
      grid.appendChild(left); grid.appendChild(right);
      body.appendChild(grid);

      function promptPreview(c) {
        return "technique_id: " + c.technique_id + "\n" +
          "technique_name: " + c.name + "\n" +
          "tactic: " + c.tactic + "\n" +
          "mapped_rules: " + (c.rule_count || 0) + "\n" +
          "redaction: [REDACTED IPs] [REDACTED hostnames] [REDACTED usernames]\n" +
          "note: only technique metadata is sent. Raw alert logs are never sent by default.";
      }

      function select(c) {
        selTech = c.technique_id;
        $all(".picker-item", picker).forEach(function (x) {
          x.classList.toggle("is-active", x.getAttribute("data-id") === c.technique_id);
        });
        renderRight(c);
      }

      function renderRight(c) {
        rightBody.innerHTML = "";
        rightBody.appendChild(DL.el('<div style="margin-bottom:12px"><span class="mono" style="color:var(--accent-hover)">' +
          DL.esc(c.technique_id) + '</span><div style="font-size:14px;font-weight:600;margin-top:4px">' + DL.esc(c.name) + "</div></div>"));
        rightBody.appendChild(DL.el('<div class="card-title">Prompt preview (redacted)</div>'));
        var pp = DL.el('<div class="prompt-preview"></div>');
        pp.textContent = promptPreview(c);
        rightBody.appendChild(pp);

        if (DL.state.aiMode !== "ai") {
          // Local mode: the deterministic offline draft is still available —
          // the backend returns source "offline". Never a dead end.
          rightBody.appendChild(DL.el('<div class="kpi-sub" style="margin-bottom:12px">Local mode: drafts use the built-in template. <a href="#" id="studio-connect" style="color:var(--accent)">Connect a provider</a> for AI-drafted rules.</div>'));
          $("#studio-connect", rightBody).addEventListener("click", function (e) { e.preventDefault(); DL.navigate("settings"); });
        }
        var gen = DL.el('<button class="btn btn-primary">' +
          (DL.state.aiMode === "ai" ? "Generate rule XML" : "Generate offline draft") + "</button>");
        var out = DL.el('<div style="margin-top:16px"></div>');
        gen.addEventListener("click", function () {
          gen.disabled = true;
          out.innerHTML = "";
          out.appendChild(DL.loadingRow("Drafting…"));
          api.aiDraftRule(c.technique_id).then(function (r) {
              out.innerHTML = "";
              var badge = DL.el('<div class="validation ' + (r.validation && r.validation.ok ? "ok" : "fail") + '">' +
                DL.icon(r.validation && r.validation.ok ? "check" : "warn") +
                "<span><strong>Validation " + (r.validation && r.validation.ok ? "passed" : "failed") +
                "</strong> · source: " + DL.esc(r.source || "ai") + "</span></div>");
              out.appendChild(badge);
              if (r.validation && !r.validation.ok && r.validation.errors) {
                var ul = document.createElement("ul");
                r.validation.errors.forEach(function (e2) { var li = document.createElement("li"); li.textContent = e2; ul.appendChild(li); });
                $("span", badge).appendChild(ul);
              }
              if (r.note) out.appendChild(DL.el('<div class="kpi-sub" style="margin-bottom:8px">' + DL.esc(r.note) + "</div>"));
              if (r.xml) {
                var pre = DL.el('<pre class="xml-block"></pre>');
                pre.textContent = r.xml;
                out.appendChild(pre);
                var acts = DL.el('<div class="output-actions"></div>');
                var cp = DL.el('<button class="btn btn-sm">' + DL.icon("copy") + " Copy</button>");
                cp.addEventListener("click", function () {
                  navigator.clipboard.writeText(r.xml).then(function () { DL.toast("Rule XML copied", "low"); });
                });
                var dl = DL.el('<button class="btn btn-sm">' + DL.icon("download") + " Download .xml</button>");
                dl.addEventListener("click", function () {
                  DL.downloadFile("detectlens-" + c.technique_id + ".xml", r.xml, "application/xml");
                });
                acts.appendChild(cp); acts.appendChild(dl);
                out.appendChild(acts);
              }
            }).catch(function (e) {
              out.innerHTML = "";
              out.appendChild(DL.errorState("Draft failed", e, null));
            }).then(function () { gen.disabled = false; });
          });
          rightBody.appendChild(gen);
          rightBody.appendChild(out);
        rightBody.appendChild(DL.el('<div class="step-note">Drafts are validated locally; run wazuh-analysisd -t on your manager before deploying. Nothing is auto-applied.</div>'));
      }

      if (!uncovered.length) {
        picker.appendChild(DL.el('<div class="empty"><h3>No uncovered techniques</h3><p>Every technique has at least one mapped rule. Nothing to draft.</p></div>'));
        rightBody.appendChild(DL.el('<div class="empty"><h3>Select a technique</h3><p>There are no uncovered techniques in the current heatmap.</p></div>'));
      } else {
        uncovered.forEach(function (c) {
          var it = DL.el('<button class="picker-item" role="option"></button>');
          it.setAttribute("data-id", c.technique_id);
          it.innerHTML = '<span class="pi-id">' + DL.esc(c.technique_id) + '</span><span class="pi-name">' + DL.esc(c.name) + "</span>";
          it.addEventListener("click", function () { select(c); });
          picker.appendChild(it);
        });
        var initial = uncovered.find(function (c) { return c.technique_id === selTech; }) || uncovered[0];
        select(initial);
      }
      DL.bindGlossary(body);
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load heatmap data", e, function () { DL.navigate("ai"); }));
    });
  }

  var V = window.DetectLens.VIEWS;
  V.ai = renderStudio;
})();

/* ---------------- VIEW: Reports ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;

  function renderReports(root) {
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">Reports</div>' +
      '<div class="view-sub">The posture report as generated by the backend. Download it or review below.</div></div>' +
      '<div><button class="btn" id="dl-report">' + DL.icon("download") + " Download .md</button></div></div>"));
    var body = DL.el("<div></div>");
    root.appendChild(body);
    body.appendChild(DL.loadingRow("Loading report…"));

    api.reportMarkdown().then(function (md) {
      body.innerHTML = "";
      var prev = DL.el('<div class="report-preview"></div>');
      prev.innerHTML = DL.mdToHtml(md) || '<div class="empty"><h3>Empty report</h3><p>The backend returned an empty report.</p></div>';
      body.appendChild(prev);

      var narr = DL.el('<div class="card" style="margin-top:16px;max-width:860px"><div class="card-title">Executive summary</div></div>');
      var narrBody = DL.el("<div></div>");
      narr.appendChild(narrBody);
      var genNarr = DL.el('<button class="btn btn-primary btn-sm">' +
        (DL.state.aiMode === "ai" ? "Generate AI narrative" : "Generate summary") + "</button>");
      narrBody.appendChild(genNarr);
      if (DL.state.aiMode !== "ai") {
        narrBody.appendChild(DL.el('<div class="kpi-sub" style="margin:8px 0">Local mode: uses the built-in template summary. Connect a provider for an AI-written narrative.</div>'));
      }
      var narrOut = DL.el('<div style="margin-top:12px"></div>');
      narrBody.appendChild(narrOut);
      genNarr.addEventListener("click", function () {
        genNarr.disabled = true;
        narrOut.innerHTML = "";
        narrOut.appendChild(DL.loadingRow("Generating…"));
        api.aiReportNarrative().then(function (r) {
          narrOut.innerHTML = "";
          var card = DL.el('<div class="ai-result"><span class="src">source: ' + DL.esc(r.source || "template") + "</span></div>");
          card.appendChild(document.createTextNode(r.text || "(empty response)"));
          narrOut.appendChild(card);
          if (r.error) DL.toast(r.error, "medium");
        }).catch(function (e) {
          narrOut.innerHTML = "";
          narrOut.appendChild(DL.errorState("Summary failed", e, null));
        }).then(function () { genNarr.disabled = false; });
      });
      body.appendChild(narr);

      $("#dl-report").addEventListener("click", function () {
        DL.downloadFile("detectlens-report.md", md, "text/markdown");
        DL.toast("Report downloaded", "low");
      });
      DL.bindGlossary(body);
    }).catch(function (e) {
      body.innerHTML = "";
      body.appendChild(DL.errorState("Could not load report", e, function () { DL.navigate("reports"); }));
    });
  }

  var V = window.DetectLens.VIEWS;
  V.reports = renderReports;
})();

/* ---------------- VIEW: Settings ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;

  function renderSettings(root) {
    root.innerHTML = "";
    root.appendChild(DL.el('<div class="view-head"><div><div class="view-title">Settings</div>' +
      '<div class="view-sub">AI provider, redaction, and data sources. Keys stay in the backend; they are never logged or echoed.</div></div></div>'));
    var body = DL.el('<div class="settings-grid"></div>');
    root.appendChild(body);

    // AI provider card
    var aiCard = DL.el('<div class="card"><div class="card-title">AI provider</div></div>');
    var form = DL.el("<div></div>");
    function field(label, inner, hint) {
      var f = DL.el('<div class="field"><label>' + DL.esc(label) + "</label></div>");
      f.appendChild(inner);
      if (hint) f.appendChild(DL.el('<div class="hint">' + DL.esc(hint) + "</div>"));
      return f;
    }
    var prov = DL.el('<select id="s-provider"><option value="none">none (local mode)</option><option value="openai_compat">openai_compat</option><option value="anthropic">anthropic</option><option value="ollama">ollama</option></select>');
    var baseUrl = DL.el('<input type="url" id="s-base" placeholder="https://…">');
    var model = DL.el('<input type="text" id="s-model" placeholder="model name">');
    var key = DL.el('<input type="password" id="s-key" placeholder="API key" autocomplete="new-password">');
    form.appendChild(field("Provider", prov));
    form.appendChild(field("Base URL", baseUrl, "Required for openai_compat and ollama."));
    form.appendChild(field("Model", model));
    form.appendChild(field("API key", key, "Sent to the backend once on save. Never displayed again."));
    var testRow = DL.el('<div style="display:flex;gap:12px;align-items:center;margin-bottom:16px"></div>');
    var testBtn = DL.el('<button class="btn btn-sm">Test connection</button>');
    var testBadge = DL.el('<span class="status-badge" id="s-test-badge" hidden></span>');
    testRow.appendChild(testBtn); testRow.appendChild(testBadge);
    form.appendChild(testRow);

    var rIps = DL.el('<input type="checkbox" id="s-rip" checked>');
    var rHost = DL.el('<input type="checkbox" id="s-rhost" checked>');
    var rUser = DL.el('<input type="checkbox" id="s-ruser" checked>');
    var localOnly = DL.el('<input type="checkbox" id="s-local">');
    function checkrow(input, label, hint) {
      var r = DL.el('<label class="checkrow"></label>');
      r.appendChild(input);
      r.appendChild(DL.el("<span>" + DL.esc(label) + "</span>"));
      if (hint) r.appendChild(DL.el('<span class="hint">' + DL.esc(hint) + "</span>"));
      return r;
    }
    form.appendChild(DL.el('<div class="card-title" style="margin-top:8px">Redaction (default on)</div>'));
    form.appendChild(checkrow(rIps, "Redact IP addresses"));
    form.appendChild(checkrow(rHost, "Redact hostnames"));
    form.appendChild(checkrow(rUser, "Redact usernames"));
    form.appendChild(checkrow(localOnly, "Local-only mode", "Block all outbound AI calls"));

    var saveBtn = DL.el('<button class="btn btn-primary">Save settings</button>');
    form.appendChild(DL.el('<div style="margin-top:16px"></div>').appendChild(saveBtn).parentNode);
    aiCard.appendChild(form);
    body.appendChild(aiCard);

    testBtn.addEventListener("click", function () {
      testBadge.hidden = false;
      testBadge.className = "status-badge";
      testBadge.innerHTML = '<span class="spin"></span> testing…';
      api.aiTestConnection().then(function (r) {
        testBadge.classList.add(r.ok ? "ok" : "fail");
        testBadge.textContent = (r.ok ? "OK — " : "Failed — ") + (r.message || "");
        DL.refreshAiStatus();
      }).catch(function (e) {
        testBadge.classList.add("fail");
        testBadge.textContent = "Failed — " + e.message;
      });
    });
    saveBtn.addEventListener("click", function () {
      saveBtn.disabled = true;
      var payload = {
        provider: prov.value,
        base_url: baseUrl.value.trim(),
        model: model.value.trim(),
        api_key: key.value,
        redact_ips: rIps.checked,
        redact_hostnames: rHost.checked,
        redact_usernames: rUser.checked,
        local_only: localOnly.checked
      };
      api.saveSettings(payload).then(function (r) {
        key.value = "";
        DL.toast("Settings saved — mode: " + (r.mode || "local"), "low");
        return DL.refreshAiStatus();
      }).catch(function (e) {
        DL.toast("Save failed: " + e.message, "critical");
      }).then(function () { saveBtn.disabled = false; });
    });

    // prefill from ai/status
    api.aiStatus().then(function (s) {
      if (s.provider && prov.querySelector('option[value="' + s.provider + '"]')) prov.value = s.provider;
      if (s.model) model.value = s.model;
      if (s.redaction) {
        rIps.checked = s.redaction.ips !== false;
        rHost.checked = s.redaction.hostnames !== false;
        rUser.checked = s.redaction.usernames !== false;
      }
      localOnly.checked = !!s.local_only;
    }).catch(function () { /* defaults stand */ });

    // data sources card
    var dsCard = DL.el('<div class="card"><div class="card-title">Data sources</div></div>');
    var dsForm = DL.el("<div></div>");
    var rulesDir = DL.el('<input type="text" id="s-rulesdir" placeholder="/var/ossec/etc/rules">');
    dsForm.appendChild(field("Rules directory", rulesDir, "Path the backend reads deployed rules from."));
    var alertsFile = DL.el('<input type="file" id="s-alerts" accept=".json,.log,.gz">');
    dsForm.appendChild(field("Alerts file", alertsFile, "Upload Wazuh alert JSON to refresh the analysis window."));
    var dsRow = DL.el('<div style="display:flex;gap:8px;margin-top:8px"></div>');
    var uploadBtn = DL.el('<button class="btn btn-sm">Upload alerts</button>');
    var reloadBtn = DL.el('<button class="btn btn-sm btn-ghost">Reload data</button>');
    dsRow.appendChild(uploadBtn); dsRow.appendChild(reloadBtn);
    dsForm.appendChild(dsRow);
    dsForm.appendChild(DL.el('<div class="hint" style="margin-top:12px;font-size:11px;color:var(--text-tertiary)">Note: rules directory and reload are sent through the settings save above; the backend applies them on save. Alert uploads apply immediately.</div>'));
    dsCard.appendChild(dsForm);
    body.appendChild(dsCard);

    uploadBtn.addEventListener("click", function () {
      var f = alertsFile.files[0];
      if (!f) { DL.toast("Choose an alerts file first", "medium"); return; }
      uploadBtn.disabled = true;
      api.uploadAlerts(f).then(function (r) {
        DL.toast("Loaded " + DL.fmt(r.alerts_loaded) + " alerts (" + r.window_days + "d window)", "low");
        DL.state.cache = {};
      }).catch(function (e) {
        DL.toast("Upload failed: " + e.message, "critical");
      }).then(function () { uploadBtn.disabled = false; });
    });
    reloadBtn.addEventListener("click", function () {
      reloadBtn.disabled = true;
      api.health().then(function () {
        DL.state.cache = {};
        DL.toast("Data reload requested — refreshing views", "low");
        DL.navigate("settings");
      }).catch(function (e) {
        DL.toast("Backend unreachable: " + e.message, "critical");
      }).then(function () { reloadBtn.disabled = false; });
    });

    // privacy explainer
    var priv = DL.el('<div class="card" style="grid-column:1/-1"><div class="card-title">What data leaves your network</div></div>');
    priv.appendChild(DL.el('<ul class="payload-list">' +
      '<li><span class="mono">POST /api/ai/explain</span> — finding id, title, severity, and mapped rule/technique ids. No raw alerts.</li>' +
      '<li><span class="mono">POST /api/ai/draft-rule</span> — technique id, name, tactic, and mapped rule count. No raw alerts.</li>' +
      '<li><span class="mono">POST /api/ai/suppression</span> — rule id, level, description, and fire counts. No raw alerts.</li>' +
      '<li><span class="mono">POST /api/ai/test-connection</span> — provider handshake only. No detection data.</li>' +
      '<li>Raw alert logs are never sent by default. Redaction toggles apply to IPs, hostnames, and usernames before any payload leaves.</li>' +
      '<li>Local-only mode blocks all outbound AI calls; every AI surface shows a locked state instead.</li>' +
      "</ul>"));
    body.appendChild(priv);
    DL.bindGlossary(body);
  }

  var V = window.DetectLens.VIEWS;
  V.settings = renderSettings;
})();

/* ---------------- global search ---------------- */
(function () {
  var DL = window.DetectLens.DL, api = window.DetectLens.api;
  var input = document.getElementById("global-search");
  var drop = DL.el('<div class="search-results" role="listbox"></div>');
  document.body.appendChild(drop);
  var data = null;

  function loadData() {
    if (data) return Promise.resolve(data);
    return Promise.all([
      api.rules().catch(function () { return { rules: [] }; }),
      api.findings().catch(function () { return { findings: [] }; }),
      api.heatmap().catch(function () { return { cells: [] }; })
    ]).then(function (r) {
      data = { rules: r[0].rules || [], findings: r[1].findings || [], cells: r[2].cells || [] };
      return data;
    });
  }

  function position() {
    var r = input.getBoundingClientRect();
    drop.style.left = r.left + "px";
    drop.style.top = (r.bottom + 6) + "px";
    drop.style.width = Math.max(320, r.width) + "px";
  }

  function search(q) {
    q = q.toLowerCase().trim();
    drop.innerHTML = "";
    if (!q) { drop.classList.remove("open"); return; }
    loadData().then(function (d) {
      var out = [];
      d.rules.forEach(function (r) {
        if ((String(r.id) + " " + (r.description || "")).toLowerCase().indexOf(q) !== -1)
          out.push({ type: "rule", id: String(r.id), label: r.description || "" });
      });
      d.findings.forEach(function (f) {
        if ((String(f.id) + " " + (f.title || "")).toLowerCase().indexOf(q) !== -1)
          out.push({ type: "finding", id: String(f.id), label: f.title || "" });
      });
      d.cells.forEach(function (c) {
        if ((c.technique_id + " " + c.name).toLowerCase().indexOf(q) !== -1)
          out.push({ type: "technique", id: c.technique_id, label: c.name });
      });
      out = out.slice(0, 12);
      if (!out.length) {
        drop.appendChild(DL.el('<div style="padding:12px;font-size:12px;color:var(--text-tertiary)">No matches for "' + DL.esc(q) + '"</div>'));
      } else {
        out.forEach(function (m) {
          var b = DL.el('<button class="search-result" role="option"></button>');
          b.innerHTML = '<span class="mono">' + DL.esc(m.id) + '</span><span class="sr-label">' + DL.esc(m.label) + '</span><span class="kind-chip">' + m.type + "</span>";
          b.addEventListener("click", function () { go(m); });
          drop.appendChild(b);
        });
      }
      position();
      drop.classList.add("open");
    });
  }

  function go(m) {
    drop.classList.remove("open");
    input.value = "";
    input.blur();
    if (m.type === "rule") DL.navigate("rules");
    else if (m.type === "finding") DL.navigate("findings", { open: m.id });
    else DL.navigate("heatmap", { select: m.id });
    if (m.type === "rule") setTimeout(function () { DL.openRule(m.id); }, 300);
  }

  input.addEventListener("input", DL.debounce(function () { search(input.value); }, 200));
  input.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { drop.classList.remove("open"); input.blur(); }
    if (e.key === "Enter") {
      var first = drop.querySelector(".search-result");
      if (first) first.click();
    }
  });
  document.addEventListener("click", function (e) {
    if (e.target !== input && !drop.contains(e.target)) drop.classList.remove("open");
  });
})();

/* ---------------- onboarding tour ---------------- */
(function () {
  var DL = window.DetectLens.DL;
  var STEPS = [
    { title: "Welcome to DetectLens", body: "DetectLens audits your deployed Wazuh ruleset: ATT&CK coverage, dead and noisy rules, gaps, and missing telemetry. This tour takes under a minute.", view: "overview" },
    { title: "Connect your data", body: "Point the backend at your Wazuh rules directory and upload alert JSON to set the analysis window. Without data, views explain what is missing instead of failing silently.", view: "settings" },
    { title: "Posture score", body: "The overview rolls coverage, dead rules, and noise into one score, broken down by tactic. Coverage % means techniques with at least one mapped rule.", view: "overview" },
    { title: "Coverage heatmap", body: "Tactics as columns, techniques as cells. Dashed cells are uncovered — click one to see mapped rules and draft a fix.", view: "heatmap" },
    { title: "Fix your first finding", body: "Findings rank what to fix first: dead rules to remove, noisy rules to tune, gaps to draft rules for. Press ? any time for shortcuts.", view: "findings" }
  ];
  var idx = 0;
  function show() {
    var s = STEPS[idx];
    DL.navigate(s.view);
    document.getElementById("onboard-step").textContent = (idx + 1) + " / " + STEPS.length;
    document.getElementById("onboard-title").textContent = s.title;
    document.getElementById("onboard-body").textContent = s.body;
    document.getElementById("onboard-back").disabled = idx === 0;
    document.getElementById("onboard-next").textContent = idx === STEPS.length - 1 ? "Finish" : "Next";
    document.getElementById("onboard").hidden = false;
  }
  function done() {
    document.getElementById("onboard").hidden = true;
    try { localStorage.setItem("detectlens.onboarded", "1"); } catch (e) { /* ignore */ }
  }
  window.skipOnboard = done;
  document.getElementById("onboard-next").addEventListener("click", function () {
    if (idx === STEPS.length - 1) { done(); DL.navigate("overview"); } else { idx++; show(); }
  });
  document.getElementById("onboard-back").addEventListener("click", function () { if (idx > 0) { idx--; show(); } });
  document.getElementById("onboard-skip").addEventListener("click", done);
  DL.maybeOnboard = function () {
    var seen = null;
    try { seen = localStorage.getItem("detectlens.onboarded"); } catch (e) { seen = "1"; }
    if (!seen) { idx = 0; show(); }
  };
})();

/* ---------------- init ---------------- */
(function () {
  var DL = window.DetectLens.DL;
  DL.refreshAiStatus();
  DL.navigate("overview");
  // health check runs quietly; banner appears only on failure
  var api = window.DetectLens.api;
  api.health().then(function (h) {
    if (!(h && h.ok)) document.getElementById("backend-banner").hidden = false;
  }).catch(function () {
    document.getElementById("backend-banner").hidden = false;
  });
  setTimeout(function () { DL.maybeOnboard(); }, 600);
})();
