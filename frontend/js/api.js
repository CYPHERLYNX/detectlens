/* DetectLens — api.js
 * Fetch layer for the DetectLens backend. Built against the API contract
 * (backend not yet reachable from here). Every call throws an ApiError on
 * non-2xx or network failure; views render inline error states from it.
 */
(function (global) {
  "use strict";

  function ApiError(message, status, url) {
    this.name = "ApiError";
    this.message = message || "Request failed";
    this.status = status || 0;
    this.url = url || "";
  }
  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  async function req(method, path, opts) {
    opts = opts || {};
    var init = { method: method, headers: {} };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (opts.form) init.body = opts.form; // multipart, browser sets content-type
    var res;
    try {
      res = await fetch(path, init);
    } catch (e) {
      throw new ApiError("Backend unreachable (" + e.message + ")", 0, path);
    }
    var ct = res.headers.get("content-type") || "";
    var data = null;
    if (opts.raw) {
      data = await res.text();
    } else if (ct.indexOf("application/json") !== -1) {
      try { data = await res.json(); } catch (e) { data = null; }
    } else {
      data = await res.text();
    }
    if (!res.ok) {
      var msg = (data && data.error) || ("HTTP " + res.status + " " + path);
      throw new ApiError(msg, res.status, path);
    }
    return data;
  }

  var api = {
    ApiError: ApiError,

    health: function () { return req("GET", "/api/health"); },
    overview: function () { return req("GET", "/api/overview"); },
    heatmap: function () { return req("GET", "/api/heatmap"); },
    findings: function () { return req("GET", "/api/findings"); },
    finding: function (id) { return req("GET", "/api/findings/" + encodeURIComponent(id)); },
    rules: function () { return req("GET", "/api/rules"); },
    rule: function (id) { return req("GET", "/api/rules/" + encodeURIComponent(id)); },
    uploadAlerts: function (file) {
      var fd = new FormData();
      fd.append("file", file);
      return req("POST", "/api/alerts/upload", { form: fd });
    },
    reportMarkdown: function () { return req("GET", "/api/report.md", { raw: true }); },
    aiStatus: function () { return req("GET", "/api/ai/status"); },
    aiTestConnection: function () { return req("POST", "/api/ai/test-connection"); },
    aiExplain: function (findingId) { return req("POST", "/api/ai/explain", { body: { finding_id: findingId } }); },
    aiExplainRule: function (ruleId) { return req("POST", "/api/ai/explain-rule", { body: { rule_id: ruleId } }); },
    aiDraftRule: function (techniqueId) { return req("POST", "/api/ai/draft-rule", { body: { technique_id: techniqueId } }); },
    aiSuppression: function (ruleId) { return req("POST", "/api/ai/suppression", { body: { rule_id: ruleId } }); },
    aiQuery: function (question) { return req("POST", "/api/ai/query", { body: { question: question } }); },
    aiReportNarrative: function () { return req("POST", "/api/ai/report-narrative"); },
    saveSettings: function (settings) { return req("POST", "/api/settings", { body: settings }); },
    glossary: function () { return req("GET", "/api/glossary"); }
  };

  global.DetectLens = global.DetectLens || {};
  global.DetectLens.api = api;
})(window);
