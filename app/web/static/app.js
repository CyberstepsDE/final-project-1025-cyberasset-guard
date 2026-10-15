/* CyberAsset Guard — web UI.
 * Small hash-routed single page on top of the REST API. No build step.
 * Every value from the API is HTML-escaped before rendering.
 * The UI hides actions the user's role does not allow; the server enforces them regardless.
 */
"use strict";

const view = document.getElementById("view");
let OPTIONS = null;          // controlled vocabularies from GET /assets/options
let ME = null;               // current user from GET /auth/me (null = not logged in)
let JIRA = null;             // Jira integration status from GET /integrations/jira (cached briefly)
let JIRA_AT = 0;

const can = (permission) => !!ME?.permissions.includes(permission);
const ROLE_LABELS = { viewer: "Viewer", analyst: "Analyst", admin: "Administrator" };

/* ---------- helpers ---------- */

const esc = (v) => String(v ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const label = (field, value) =>
  OPTIONS?.[field]?.find((o) => o.value === value)?.label ?? value ?? "";

const fmtDate = (iso) => iso
  ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";

const dash = (v) => (v === null || v === undefined || v === "" ? '<span class="muted">—</span>' : esc(v));

function toast(message) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 3500);
}

class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : `Request failed (${status})`);
    this.status = status;
    this.detail = detail;
  }
}

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && ME && !path.startsWith("/auth/")) {
    // Session expired or was ended elsewhere (logout, role change, deactivation).
    ME = null;
    toast("Your session has ended. Please sign in again.");
    renderLogin();
    return new Promise(() => {});        // the page that made the call is gone - never resolve
  }
  if (!res.ok) throw new ApiError(res.status, data?.detail ?? res.statusText);
  return data;
}

/** Map FastAPI 422 details onto {field: message}; model-level errors go to "_form". */
function fieldErrors(detail) {
  const out = {};
  if (!Array.isArray(detail)) return { _form: String(detail) };
  for (const err of detail) {
    const loc = err.loc || [];
    const field = loc.length > 1 ? loc[1] : "_form";
    const msg = String(err.msg || "Invalid value").replace(/^Value error, /, "");
    out[field] = out[field] ? `${out[field]} ${msg}` : msg;
  }
  return out;
}

const critBadge = (c) =>
  `<span class="badge crit-${esc(c)}"><span class="dot" aria-hidden="true"></span>${esc(label("criticality", c))}</span>`;
const envBadge = (e) =>
  `<span class="badge env-${esc(e)}">${esc(label("environment", e))}</span>`;
const statusBadge = (s) =>
  `<span class="badge status-${esc(s)}">${esc(label("status", s))}</span>`;
const shortId = (id) => id.slice(0, 8);

function confirmDialog(title, text, okLabel) {
  const dlg = document.getElementById("confirm-dialog");
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-text").textContent = text;
  document.getElementById("confirm-ok").textContent = okLabel;
  dlg.returnValue = "";
  dlg.showModal();
  return new Promise((resolve) => dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true }));
}

/* ---------- asset overview ---------- */

const FILTERS = ["q", "environment", "criticality", "asset_type", "status", "internet_facing"];

function readQuery() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  if (!params.has("status")) params.set("status", "active");
  return params;
}

function selectFilter(name, field, params, allLabel) {
  const current = params.get(name) || "";
  const opts = OPTIONS[field].map((o) =>
    `<option value="${esc(o.value)}" ${o.value === current ? "selected" : ""}>${esc(o.label)}</option>`).join("");
  return `<label class="field">${esc(allLabel)}
    <select name="${name}"><option value="">All</option>${opts}</select></label>`;
}

async function renderList() {
  const params = readQuery();
  view.innerHTML = `
    <div class="page-head">
      <div><h1>Assets</h1><div class="sub">Central inventory of IT assets</div></div>
      ${can("assets:write") ? '<a class="btn btn-primary" href="#/assets/new">+ Add Asset</a>' : ""}
    </div>
    <section class="panel">
      <form class="filters" id="filters" role="search">
        <label class="field search">Search
          <input type="search" name="q" value="${esc(params.get("q") || "")}"
                 placeholder="Name, IP address or hostname" maxlength="200" autocomplete="off">
        </label>
        ${selectFilter("environment", "environment", params, "Environment")}
        ${selectFilter("criticality", "criticality", params, "Criticality")}
        ${selectFilter("asset_type", "asset_type", params, "Asset type")}
        ${selectFilter("internet_facing", "internet_facing", params, "Internet-facing")}
        ${selectFilter("status", "status", params, "Status")}
      </form>
      <div id="results"><div class="empty">Loading…</div></div>
    </section>`;

  const form = document.getElementById("filters");
  // status="" means "All" - keep it explicit in the URL so the Active default does not come back.
  const sync = () => {
    const p = new URLSearchParams();
    for (const name of FILTERS) {
      const v = form.elements[name].value.trim();
      if (v || name === "status") p.set(name, v);
    }
    history.replaceState(null, "", `#/assets?${p}`);
    loadResults(p);
  };
  let timer;
  form.addEventListener("input", (e) => {
    clearTimeout(timer);
    timer = setTimeout(sync, e.target.name === "q" ? 250 : 0);
  });
  form.addEventListener("submit", (e) => { e.preventDefault(); sync(); });
  loadResults(params);
}

async function loadResults(params) {
  const box = document.getElementById("results");
  const query = new URLSearchParams();
  for (const name of FILTERS) if (params.get(name)) query.set(name, params.get(name));
  query.set("limit", "500");
  let data;
  let riskBy = null;                     // asset id -> risk summary (null: no findings:read)
  try {
    [data, riskBy] = await Promise.all([
      api(`/assets?${query}`),
      can("findings:read") ? api("/risk/assets").then((rows) => new Map(rows.map((r) => [r.asset_id, r])))
        .catch(() => null) : null,
    ]);
  } catch (err) {
    box.innerHTML = `<div class="empty">Could not load assets: ${esc(err.message)}</div>`;
    return;
  }
  if (!data.items.length) {
    const filtered = [...query.keys()].some((k) => k !== "limit" && k !== "status") || params.get("status") === "inactive";
    box.innerHTML = filtered
      ? `<div class="empty"><h2>No matching assets</h2>Adjust the search or filters.</div>`
      : `<div class="empty"><h2>No assets registered yet</h2>Start building the inventory.
           ${can("assets:write") ? '<p><a class="btn btn-primary" href="#/assets/new">+ Add Asset</a></p>' : ""}</div>`;
    return;
  }
  const rows = data.items.map((a) => `
    <tr data-id="${esc(a.id)}" class="${a.status === "inactive" ? "inactive" : ""}">
      <td class="name"><a href="#/assets/${esc(a.id)}">${esc(a.name)}</a>
        <div class="muted small mono" title="Asset ID">${esc(shortId(a.id))}</div></td>
      ${riskBy ? `<td>${riskCell(riskBy.get(a.id))}</td>` : ""}
      <td class="mono">${dash(a.ip_address)}</td>
      <td>${dash(a.hostname)}</td>
      <td>${esc(label("asset_type", a.asset_type))}</td>
      <td>${envBadge(a.environment)}</td>
      <td>${critBadge(a.criticality)}</td>
      <td>${esc(label("internet_facing", a.internet_facing))}</td>
      <td>${statusBadge(a.status)}</td>
      <td title="${esc(a.updated_at)}">${esc(fmtDate(a.updated_at))}</td>
    </tr>`).join("");
  box.innerHTML = `
    <div class="table-meta"><span>${data.total} asset${data.total === 1 ? "" : "s"}</span>
      ${data.total > data.items.length ? `<span>showing first ${data.items.length}</span>` : ""}</div>
    <div class="table-wrap"><table>
      <thead><tr><th>Asset name</th>${riskBy ? "<th>Risk</th>" : ""}<th>IP address</th><th>Hostname</th><th>Asset type</th>
        <th>Environment</th><th>Criticality</th><th>Internet-facing</th><th>Status</th><th>Last updated</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  box.querySelector("tbody").addEventListener("click", (e) => {
    if (e.target.closest("a")) return;
    const row = e.target.closest("tr[data-id]");
    if (row) location.hash = `#/assets/${row.dataset.id}`;
  });
}

/* ---------- asset detail ---------- */

const props = (pairs) => `<dl class="props">${pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const section = (title, body, extraClass = "") =>
  `<section class="panel section ${extraClass}"><h2>${esc(title)}</h2>${body}</section>`;

/* Detail sections. Future modules (monitoring, vulnerabilities, risk, remediation)
 * add their own renderer to this list instead of redesigning the page. */
const DETAIL_SECTIONS = [
  (a) => section("General Information", props([
    ["Asset name", esc(a.name)],
    ["Asset type", esc(label("asset_type", a.asset_type))],
    ["Asset ID", `<span class="mono">${esc(a.id)}</span>`],
    ["Tags", a.tags.length ? a.tags.map((t) => `<span class="tag">${esc(t)}</span>`).join("") : dash(null)],
  ])),
  (a) => section("Ownership", props([["Owner", dash(a.owner)]])),
  (a) => section("Business Context", a.description
    ? `<p class="description">${esc(a.description)}</p>` : `<p class="muted">No business description provided.</p>`),
  (a) => section("Environment and Criticality", props([
    ["Environment", envBadge(a.environment)],
    ["Criticality", critBadge(a.criticality)],
  ])),
  (a) => section("Network Identification", props([
    ["IP address", a.ip_address ? `<span class="mono">${esc(a.ip_address)}</span>` : dash(null)],
    ["Hostname", dash(a.hostname)],
    ["Internet-facing", esc(label("internet_facing", a.internet_facing))],
  ])),
  (a) => section("Lifecycle Information", props([
    ["Status", statusBadge(a.status)],
    ["Created", esc(fmtDate(a.created_at))],
    ["Last updated", esc(fmtDate(a.updated_at))],
    ...(a.deactivated_at ? [["Deactivated", esc(fmtDate(a.deactivated_at))]] : []),
  ])),
];

/* Monitoring results (ASSET-65). Scanner-derived strings (service, product, version,
 * banners, change detail) are attacker-controlled, so every value goes through esc()/dash(). */
function monitoringSection(a, m, err) {
  // Scan / schedule controls (ASSET-66) are filled in by setupMonitoringControls()
  // after render; shown only to users who may run scans.
  const controls = can("monitoring:run")
    ? `<div id="monitoring-controls" class="monitoring-controls"></div>` : "";
  const wrap = (body) => section("Monitoring", body + controls, "monitoring");
  if (err) return wrap(`<p class="muted">Could not load monitoring results: ${esc(err.message)}</p>`);
  if (!m || !m.scanned) {
    return wrap(`<p class="muted">${m && m.linked
      ? "Linked to a discovered host, but no scan results yet."
      : "Not scanned yet — this asset has not been seen by a monitoring scan."}</p>`);
  }
  const r = m.reachability || {};
  const ls = m.last_scan || {};
  const up = r.state === "up";
  const latency = r.latency_s != null
    ? ` <span class="muted small">${esc((r.latency_s * 1000).toFixed(0))} ms</span>` : "";
  const head = props([
    ["Last scan", ls.finished_at || ls.started_at
      ? `${esc(fmtDate(ls.finished_at || ls.started_at))} <span class="muted small">(${esc(ls.scan_type)})</span>`
      : dash(null)],
    ["Reachability", `<span class="badge status-${up ? "active" : "inactive"}">${up ? "Up" : "Down"}</span>${latency}`],
    ["Scanned address", r.ip ? `<span class="mono">${esc(r.ip)}</span>` : dash(null)],
  ]);
  const ports = m.ports.length
    ? `<table class="data ports"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>${
        m.ports.map((p) => `<tr><td class="mono">${esc(p.port)}/${esc(p.protocol)}</td>`
          + `<td>${dash(p.service)}</td><td>${dash(p.product)}</td>`
          + `<td>${p.version ? esc(p.version) : dash(null)}`
          + `${p.extrainfo ? ` <span class="muted small">${esc(p.extrainfo)}</span>` : ""}</td></tr>`).join("")
      }</tbody></table>`
    : `<p class="muted">No open ports found in the latest scan.</p>`;
  const changes = m.recent_changes.length
    ? `<ul class="changes">${m.recent_changes.map((c) => `<li>`
        + `<span class="muted small">${esc(fmtDate(c.detected_at))}</span> ${esc(c.change_type)}`
        + `${c.port != null ? ` <span class="mono">${esc(c.port)}${c.protocol ? "/" + esc(c.protocol) : ""}</span>` : ""}`
        + `${c.detail ? ` — ${esc(c.detail)}` : ""}</li>`).join("")}</ul>`
    : "";
  return wrap(`${head}<h3>Open ports</h3>${ports}${changes ? `<h3>Recent changes</h3>${changes}` : ""}`);
}

async function renderDetail(id) {
  view.innerHTML = `<div class="empty">Loading…</div>`;
  const [aRes, mRes] = await Promise.allSettled([
    api(`/assets/${encodeURIComponent(id)}`),
    api(`/monitoring/assets/${encodeURIComponent(id)}/summary`),
  ]);
  if (aRes.status === "rejected") {
    view.innerHTML = notFound(aRes.reason);
    return;
  }
  const a = aRes.value;
  const mon = mRes.status === "fulfilled" ? mRes.value : null;
  const monErr = mRes.status === "rejected" ? mRes.reason : null;
  const inactive = a.status === "inactive";
  view.innerHTML = `
    <div class="breadcrumb"><a href="#/assets">Assets</a> / ${esc(a.name)}</div>
    <div class="page-head">
      <div><h1>${esc(a.name)}</h1>
        <div class="sub">${esc(label("asset_type", a.asset_type))} · ${envBadge(a.environment)} ${critBadge(a.criticality)} ${statusBadge(a.status)}</div></div>
      ${can("assets:write") ? `<div class="actions">
        <a class="btn" href="#/assets/${esc(a.id)}/edit">Edit</a>
        <button class="btn ${inactive ? "" : "btn-danger"}" id="toggle-status">${inactive ? "Reactivate" : "Deactivate"}</button>
      </div>` : ""}
    </div>
    ${inactive ? `<div class="notice">This asset is inactive. It remains stored and identifiable.</div>` : ""}
    ${can("findings:read") ? '<div id="risk-panel" class="risk-area"><div class="panel empty">Loading risk…</div></div>' : ""}
    <div class="detail-grid">${DETAIL_SECTIONS.map((render) => render(a)).join("")}${monitoringSection(a, mon, monErr)}</div>
    ${can("audit:read") ? `<p class="small"><a href="#/audit?target_type=asset&target_id=${esc(a.id)}">View change history in the audit log</a></p>` : ""}`;

  if (can("findings:read")) loadRiskPanel(a);

  document.getElementById("toggle-status")?.addEventListener("click", async (e) => {
    const deactivate = !inactive;
    if (deactivate && !(await confirmDialog("Deactivate asset?",
      `"${a.name}" will be marked inactive. The record is kept and can be reactivated at any time.`, "Deactivate"))) return;
    e.target.disabled = true;
    try {
      await api(`/assets/${a.id}/${deactivate ? "deactivate" : "activate"}`, { method: "POST" });
      toast(deactivate ? "Asset deactivated" : "Asset reactivated");
      renderDetail(a.id);
    } catch (err) {
      toast(err.message);
      e.target.disabled = false;
    }
  });

  if (can("monitoring:run")) setupMonitoringControls(a);
}

/* Scan-now + per-asset schedules (ASSET-66). Rendered into #monitoring-controls after
 * the detail page loads; the server takes the scan target from the asset record. */
const SCAN_TYPE_OPTIONS = `
  <option value="discovery">Discovery (reachability)</option>
  <option value="port">Port scan</option>
  <option value="version" selected>Version scan</option>`;

function setupMonitoringControls(a) {
  const box = document.getElementById("monitoring-controls");
  if (!box) return;
  if (!a.ip_address && !a.hostname) {
    box.innerHTML = `<h3>Run a scan</h3>
      <p class="muted small">Add an IP address or hostname to this asset to scan it.</p>`;
    return;
  }
  box.innerHTML = `
    <h3>Run a scan</h3>
    <div class="scan-controls">
      <select id="scan-type" aria-label="Scan type">${SCAN_TYPE_OPTIONS}</select>
      <input id="scan-ports" class="mono" maxlength="200" placeholder="ports (optional, e.g. 22,80,443)">
      <button class="btn btn-primary" id="scan-now">Scan now</button>
      <span id="scan-status" class="muted small" role="status" aria-live="polite"></span>
    </div>
    <h3>Scheduled scans</h3>
    <div id="asset-schedules"><div class="muted small">Loading…</div></div>
    <form class="scan-controls" id="schedule-form">
      <select name="scan_type" aria-label="Scheduled scan type">${SCAN_TYPE_OPTIONS}</select>
      <label class="muted small">every
        <input name="interval_minutes" type="number" min="1" value="60"> min</label>
      <input name="ports" class="mono" maxlength="200" placeholder="ports (optional)">
      <button class="btn" type="submit">Add schedule</button>
    </form>`;

  const status = document.getElementById("scan-status");
  document.getElementById("scan-now").addEventListener("click", async (e) => {
    const body = { scan_type: document.getElementById("scan-type").value,
                   ports: document.getElementById("scan-ports").value.trim() || null };
    e.target.disabled = true;
    status.textContent = "Scanning… this can take a moment.";
    try {
      await api(`/monitoring/assets/${a.id}/scan`, { method: "POST", body });
      toast("Scan complete");
      renderDetail(a.id);                       // refresh to show the new results
    } catch (err) {
      e.target.disabled = false;
      status.textContent = err.message;         // e.g. "nmap binary not found", or out-of-scope target
    }
  });

  document.getElementById("schedule-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const minutes = parseInt(f.elements.interval_minutes.value, 10);
    const btn = f.querySelector("button");
    btn.disabled = true;
    try {
      await api(`/monitoring/assets/${a.id}/schedules`, { method: "POST", body: {
        scan_type: f.elements.scan_type.value,
        interval_seconds: (minutes > 0 ? minutes : 0) * 60,
        ports: f.elements.ports.value.trim() || null } });
      toast("Schedule created");
      f.reset();
      loadAssetSchedules(a);
    } catch (err) { toast(err.message); }
    btn.disabled = false;
  });

  loadAssetSchedules(a);
}

async function loadAssetSchedules(a) {
  const box = document.getElementById("asset-schedules");
  if (!box) return;
  let schedules;
  try { schedules = await api(`/monitoring/assets/${a.id}/schedules`); }
  catch (err) { box.innerHTML = `<p class="muted small">Could not load schedules: ${esc(err.message)}</p>`; return; }
  if (!schedules.length) { box.innerHTML = `<p class="muted small">No recurring scans scheduled.</p>`; return; }
  box.innerHTML = `<ul class="changes">${schedules.map((s) => `<li>`
    + `${esc(s.scan_type)} every ${esc(Math.round(s.interval_seconds / 60))} min`
    + `${s.ports ? ` <span class="mono">(${esc(s.ports)})</span>` : ""}`
    + `${s.last_error ? ` <span class="badge status-inactive" title="${esc(s.last_error)}">last run failed</span>`
        : s.last_run_at ? ` <span class="muted small">last run ${esc(fmtDate(s.last_run_at))}</span>` : ""}`
    + ` <button type="button" class="linkish" data-del-schedule="${esc(s.id)}">remove</button></li>`).join("")}</ul>`;
  box.querySelectorAll("button[data-del-schedule]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await api(`/monitoring/schedules/${b.dataset.delSchedule}`, { method: "DELETE" });
      toast("Schedule removed");
      loadAssetSchedules(a);
    } catch (err) { toast(err.message); b.disabled = false; }
  }));
}

function notFound(err) {
  const msg = err.status === 404 ? "This asset does not exist." : `Could not load the asset: ${esc(err.message)}`;
  return `<div class="panel empty"><h2>${err.status === 404 ? "Asset not found" : "Error"}</h2>${msg}
    <p><a class="btn" href="#/assets">Back to assets</a></p></div>`;
}

/* ---------- create / edit form ---------- */

function selectField(name, field, value, required) {
  const opts = OPTIONS[field].map((o) =>
    `<option value="${esc(o.value)}" ${o.value === value ? "selected" : ""}>${esc(o.label)}</option>`).join("");
  const placeholder = required && !value ? `<option value="" selected disabled>Select…</option>` : "";
  return `<select name="${name}" id="f-${name}" ${required ? "required" : ""}>${placeholder}${opts}</select>`;
}

function field(name, labelText, control, { required = false, hint = "", full = false } = {}) {
  return `<label class="field ${full ? "full" : ""}" for="f-${name}">
      <span>${esc(labelText)} ${required ? '<span class="req" aria-hidden="true">*</span>' : ""}
        ${hint ? `<span class="hint">${esc(hint)}</span>` : ""}</span>
      ${control}
      <span class="error" id="e-${name}" role="alert"></span>
    </label>`;
}

function forbidden() {
  return `<div class="panel empty"><h2>Not permitted</h2>Your role (${esc(ROLE_LABELS[ME?.role] ?? "")}) does not allow this action.
    <p><a class="btn" href="#/assets">Back to assets</a></p></div>`;
}

async function renderForm(id, fromHostId = null) {
  if (!can("assets:write")) { view.innerHTML = forbidden(); return; }
  let a = null;
  if (id) {
    try { a = await api(`/assets/${encodeURIComponent(id)}`); }
    catch (err) { view.innerHTML = notFound(err); return; }
  }
  let host = null;
  if (fromHostId != null) {                       // "create asset from host" (ASSET-96)
    try {
      const candidates = await api("/monitoring/candidates");
      host = candidates.find((c) => String(c.host_id) === String(fromHostId))
        || { host_id: fromHostId, ip: "", hostname: "" };
    } catch { host = { host_id: fromHostId, ip: "", hostname: "" }; }
  }
  const prefill = host ? { ip_address: host.ip || "", hostname: host.hostname || "" } : {};
  const v = (k) => esc(a?.[k] ?? prefill[k] ?? "");
  view.innerHTML = `
    <div class="breadcrumb">${host
      ? `<a href="#/candidates">Candidate hosts</a> / Create asset`
      : `<a href="#/assets">Assets</a> / ${a ? `<a href="#/assets/${esc(a.id)}">${esc(a.name)}</a> / Edit` : "New asset"}`}</div>
    <div class="page-head"><div><h1>${a ? "Edit asset" : host ? "Create asset from host" : "Add asset"}</h1>
      <div class="sub">${a
        ? `Asset ID <span class="mono">${esc(a.id)}</span> · created ${esc(fmtDate(a.created_at))}`
        : host
          ? `Discovered host <span class="mono">${esc(host.ip)}</span>${host.hostname ? ` · ${esc(host.hostname)}` : ""} — fields prefilled below.`
          : "Fields marked * are required."}</div></div></div>
    <form class="panel form" id="asset-form" novalidate>
      <div class="form-error" id="e-_form" role="alert" hidden></div>
      <fieldset><legend>General information</legend>
        ${field("name", "Asset name", `<input id="f-name" name="name" maxlength="200" required value="${v("name")}" autocomplete="off">`, { required: true })}
        ${field("asset_type", "Asset type", selectField("asset_type", "asset_type", a?.asset_type, true), { required: true })}
        <span class="hint full" id="name-hint" aria-live="polite"></span>
      </fieldset>
      <fieldset><legend>Environment and criticality</legend>
        ${field("environment", "Environment", selectField("environment", "environment", a?.environment, true), { required: true })}
        ${field("criticality", "Criticality", selectField("criticality", "criticality", a?.criticality, true), { required: true })}
      </fieldset>
      <fieldset><legend>Network identification</legend>
        ${field("ip_address", "IP address", `<input id="f-ip_address" name="ip_address" maxlength="45" value="${v("ip_address")}" placeholder="e.g. 10.0.4.12" class="mono">`, { hint: "IPv4 or IPv6" })}
        ${field("hostname", "Hostname", `<input id="f-hostname" name="hostname" maxlength="253" value="${v("hostname")}" placeholder="e.g. web01.corp.example">`)}
        ${field("internet_facing", "Internet-facing", selectField("internet_facing", "internet_facing", a?.internet_facing ?? "unknown", false))}
      </fieldset>
      <fieldset><legend>Ownership and business context</legend>
        ${field("owner", "Owner", `<input id="f-owner" name="owner" maxlength="200" value="${v("owner")}" placeholder="Team or person responsible">`)}
        ${field("tags", "Tags", `<input id="f-tags" name="tags" value="${esc((a?.tags || []).join(", "))}" placeholder="e.g. pci, dmz">`, { hint: "comma-separated" })}
        ${field("description", "Business description", `<textarea id="f-description" name="description" maxlength="5000" placeholder="What does this asset do for the business?">${v("description")}</textarea>`, { full: true })}
      </fieldset>
      ${a ? `<fieldset><legend>Lifecycle</legend>
        ${field("status", "Lifecycle status", selectField("status", "status", a.status, true))}</fieldset>` : ""}
      <div class="actions">
        <a class="btn" href="${a ? `#/assets/${esc(a.id)}` : host ? "#/candidates" : "#/assets"}">Cancel</a>
        <button class="btn btn-primary" type="submit">${a ? "Save changes" : "Create asset"}</button>
      </div>
    </form>`;

  const form = document.getElementById("asset-form");
  if (!a) form.elements.name.addEventListener("change", () => warnDuplicateName(form.elements.name.value));
  form.addEventListener("submit", (e) => { e.preventDefault(); submitForm(form, a, host); });
  form.elements.name.focus();
}

async function warnDuplicateName(name) {
  const hint = document.getElementById("name-hint");
  hint.textContent = "";
  name = name.trim();
  if (!name) return;
  try {
    const data = await api(`/assets?${new URLSearchParams({ q: name, limit: "50" })}`);
    const same = data.items.filter((x) => x.name.toLowerCase() === name.toLowerCase());
    if (same.length) {
      hint.textContent = `${same.length} existing asset(s) already use this name (${same
        .map((x) => [x.ip_address || x.hostname, shortId(x.id)].filter(Boolean).join(" / ")).join("; ")}). ` +
        "Names do not have to be unique — add an IP address or hostname to tell them apart.";
    }
  } catch { /* hint only */ }
}

function showErrors(form, errors) {
  for (const el of form.querySelectorAll(".error")) el.textContent = "";
  for (const el of form.querySelectorAll("[aria-invalid]")) el.removeAttribute("aria-invalid");
  const formErr = document.getElementById("e-_form");
  const general = [];
  let first = null;
  for (const [name, msg] of Object.entries(errors)) {
    const slot = document.getElementById(`e-${name}`);
    const input = form.elements[name];
    if (slot && input && name !== "_form") {
      slot.textContent = msg;
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", `e-${name}`);
      first ??= input;
    } else {
      general.push(msg);
    }
  }
  formErr.textContent = general.join(" ");
  formErr.hidden = general.length === 0;
  (first ?? formErr).focus?.();
}

async function submitForm(form, existing, fromHost = null) {
  const get = (n) => form.elements[n]?.value ?? "";
  const body = {
    name: get("name"),
    asset_type: get("asset_type") || null,
    environment: get("environment") || null,
    criticality: get("criticality") || null,
    internet_facing: get("internet_facing") || "unknown",
    ip_address: get("ip_address").trim() || null,
    hostname: get("hostname").trim() || null,
    owner: get("owner").trim() || null,
    description: get("description").trim() || null,
    tags: get("tags").split(",").map((t) => t.trim()).filter(Boolean),
  };
  if (existing) body.status = get("status");

  // Required-field check in the browser for fast feedback; the server validates everything again.
  const missing = {};
  if (!body.name.trim()) missing.name = "Asset name must not be empty.";
  for (const [k, text] of [["asset_type", "Select an asset type."], ["environment", "Select an environment."],
                           ["criticality", "Select a criticality."]]) {
    if (!body[k]) missing[k] = text;
  }
  if (Object.keys(missing).length) { showErrors(form, missing); return; }

  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    let saved;
    if (existing) saved = await api(`/assets/${existing.id}`, { method: "PATCH", body });
    else if (fromHost) saved = await api(`/monitoring/hosts/${fromHost.host_id}/create-asset`, { method: "POST", body });
    else saved = await api("/assets", { method: "POST", body });
    toast(existing ? "Asset updated" : "Asset created");
    location.hash = `#/assets/${existing ? saved.id : fromHost ? saved.asset_id : saved.id}`;
  } catch (err) {
    button.disabled = false;
    showErrors(form, err.status === 422 ? fieldErrors(err.detail) : { _form: err.message });
  }
}

/* ---------- header / session ---------- */

function renderHeader() {
  const nav = document.getElementById("mainnav");
  const menu = document.getElementById("usermenu");
  if (!ME) { nav.hidden = menu.hidden = true; nav.innerHTML = menu.innerHTML = ""; return; }
  const section = location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || (can("findings:read") ? "dashboard" : "assets");
  const links = [["dashboard", "Dashboard", can("findings:read")], ["assets", "Assets", true],
                 ["findings", "Findings", can("findings:read")],
                 ["assessments", "Assessments", can("findings:read")], ["candidates", "Candidates", can("assets:write")],
                 ["users", "Users", can("users:manage")], ["audit", "Audit log", can("audit:read")]];
  nav.innerHTML = links.filter(([, , ok]) => ok).map(([key, text]) =>
    `<a href="#/${key}" class="${section === key ? "active" : ""}">${esc(text)}</a>`).join("") +
    '<a href="/docs" target="_blank" rel="noopener">API docs</a>';
  menu.innerHTML = `
    <span class="who" title="${esc(ME.username)}">${esc(ME.display_name || ME.username)}
      <span class="role-badge">${esc(ROLE_LABELS[ME.role] ?? ME.role)}</span></span>
    <a href="#/account/password">Password</a>
    <button type="button" class="linkish" id="logout">Sign out</button>`;
  nav.hidden = menu.hidden = false;
  document.getElementById("logout").addEventListener("click", async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch { /* already gone */ }
    ME = null;
    toast("Signed out");
    renderLogin();
  });
}

async function renderLogin() {
  ME = null;
  renderHeader();
  let status = { setup_required: false };
  try { status = await api("/auth/status"); } catch { /* show the form anyway */ }
  view.innerHTML = `
    <div class="login-wrap">
      <form class="panel login" id="login-form" novalidate>
        <h1>Sign in</h1>
        <p class="muted">CyberAsset Guard</p>
        ${status.setup_required ? `<div class="notice">No user accounts exist yet. Create the first administrator on the server:
          <code class="mono">python -m app.maintenance create-user admin --role admin</code></div>` : ""}
        <label class="field" for="l-username">Username
          <input id="l-username" name="username" autocomplete="username" maxlength="64" required></label>
        <label class="field" for="l-password">Password
          <input id="l-password" name="password" type="password" autocomplete="current-password" maxlength="128" required></label>
        <div class="form-error" id="login-error" role="alert" hidden></div>
        <button class="btn btn-primary" type="submit">Sign in</button>
      </form>
    </div>`;
  const form = document.getElementById("login-form");
  form.elements.username.focus();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("login-error");
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      ME = await api("/auth/login", { method: "POST",
        body: { username: form.elements.username.value, password: form.elements.password.value } });
      OPTIONS = null;
      if (!location.hash || location.hash === "#/login") location.hash = "#/assets";
      route();
    } catch (ex) {
      err.textContent = ex.status === 401 ? "Invalid username or password." : ex.message;
      err.hidden = false;
      form.elements.password.value = "";
      form.elements.password.focus();
      button.disabled = false;
    }
  });
}

function promptPassword(title, text) {
  return promptValue(title, text, "New password (min. 12 characters)", "password");
}

/** Single-line prompt; type "password" or "text". Resolves to the value, or null when cancelled. */
function promptValue(title, text, labelText, type = "text") {
  const dlg = document.getElementById("prompt-dialog");
  const input = document.getElementById("prompt-input");
  input.type = type;
  input.maxLength = type === "password" ? 128 : 1000;
  input.autocomplete = type === "password" ? "new-password" : "off";
  document.getElementById("prompt-title").textContent = title;
  document.getElementById("prompt-text").textContent = text;
  document.getElementById("prompt-label").textContent = labelText;
  document.getElementById("prompt-error").textContent = "";
  input.value = "";
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); dlg.close("ok"); } };
  dlg.returnValue = "";
  dlg.showModal();
  return new Promise((resolve) => dlg.addEventListener("close",
    () => resolve(dlg.returnValue === "ok" ? input.value : null), { once: true }));
}

/* ---------- own password ---------- */

function renderPasswordChange() {
  view.innerHTML = `
    <div class="page-head"><div><h1>Change password</h1>
      <div class="sub">Signed in as ${esc(ME.username)}. Other sessions of your account will be signed out.</div></div></div>
    <form class="panel form narrow" id="pw-form" novalidate>
      <div class="form-error" id="e-_form" role="alert" hidden></div>
      ${field("current_password", "Current password", '<input id="f-current_password" name="current_password" type="password" autocomplete="current-password" maxlength="128">', { required: true })}
      ${field("new_password", "New password", '<input id="f-new_password" name="new_password" type="password" autocomplete="new-password" maxlength="128">', { required: true, hint: "min. 12 characters, must not contain your username" })}
      ${field("repeat", "Repeat new password", '<input id="f-repeat" name="repeat" type="password" autocomplete="new-password" maxlength="128">', { required: true })}
      <div class="actions"><a class="btn" href="#/assets">Cancel</a><button class="btn btn-primary" type="submit">Change password</button></div>
    </form>`;
  const form = document.getElementById("pw-form");
  form.elements.current_password.focus();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const get = (n) => form.elements[n].value;
    if (get("new_password") !== get("repeat")) { showErrors(form, { repeat: "The passwords do not match." }); return; }
    try {
      await api("/auth/password", { method: "POST",
        body: { current_password: get("current_password"), new_password: get("new_password") } });
      toast("Password changed");
      location.hash = "#/assets";
    } catch (err) {
      showErrors(form, err.status === 400 ? { current_password: "The current password is incorrect." }
        : err.status === 422 && typeof err.detail === "string" ? { new_password: err.detail }
        : err.status === 422 ? fieldErrors(err.detail) : { _form: err.message });
    }
  });
}

/* ---------- user management (admin) ---------- */

async function renderUsers() {
  if (!can("users:manage")) { view.innerHTML = forbidden(); return; }
  view.innerHTML = `
    <div class="page-head"><div><h1>Users</h1><div class="sub">Accounts and roles</div></div>
      <a class="btn btn-primary" href="#/users/new">+ Add user</a></div>
    <section class="panel" id="users-box"><div class="empty">Loading…</div></section>
    <section class="panel section roles"><h2>Roles</h2>${props([
      ["Viewer", "Read assets and monitoring results."],
      ["Analyst", "Viewer + create, edit and deactivate assets, run scans."],
      ["Administrator", "Analyst + manage users and read the audit log."],
    ].map(([k, v]) => [k, esc(v)]))}</section>`;
  const box = document.getElementById("users-box");
  let users;
  try { users = await api("/users"); }
  catch (err) { box.innerHTML = `<div class="empty">${esc(err.message)}</div>`; return; }
  if (!box.isConnected) return;                       // user navigated away while loading
  const roleSelect = (u) => `<select data-role="${esc(u.id)}" aria-label="Role of ${esc(u.username)}">${
    Object.entries(ROLE_LABELS).map(([v, l]) => `<option value="${v}" ${u.role === v ? "selected" : ""}>${l}</option>`).join("")}</select>`;
  const locked = (u) => u.locked_until && new Date(u.locked_until) > new Date();
  box.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>Username</th><th>Display name</th><th>Role</th><th>Status</th><th>Last login</th><th>Actions</th></tr></thead>
    <tbody>${users.map((u) => `<tr class="${u.is_active ? "" : "inactive"}">
      <td class="mono">${esc(u.username)}${u.id === ME.id ? ' <span class="muted small">(you)</span>' : ""}</td>
      <td>${dash(u.display_name)}</td>
      <td>${roleSelect(u)}</td>
      <td>${u.is_active ? (locked(u) ? '<span class="badge crit-high">Locked</span>' : '<span class="badge">Active</span>')
                        : '<span class="badge status-inactive">Disabled</span>'}</td>
      <td>${esc(fmtDate(u.last_login_at))}</td>
      <td class="row-actions">
        <button class="btn" data-reset="${esc(u.id)}" data-name="${esc(u.username)}">Reset password</button>
        <button class="btn ${u.is_active ? "btn-danger" : ""}" data-toggle="${esc(u.id)}" data-active="${u.is_active}"
          data-name="${esc(u.username)}">${u.is_active ? "Disable" : "Enable"}</button>
      </td></tr>`).join("")}</tbody></table></div>`;

  box.addEventListener("change", async (e) => {
    const sel = e.target.closest("select[data-role]");
    if (!sel) return;
    try {
      await api(`/users/${sel.dataset.role}`, { method: "PATCH", body: { role: sel.value } });
      toast("Role changed - the user has to sign in again");
      if (sel.dataset.role === ME.id) { ME = await api("/auth/me").catch(() => null); }
    } catch (err) { toast(err.message); }
    renderUsers();
  });
  box.addEventListener("click", async (e) => {
    const reset = e.target.closest("button[data-reset]");
    const toggle = e.target.closest("button[data-toggle]");
    try {
      if (reset) {
        const pw = await promptPassword(`Reset password for ${reset.dataset.name}`,
          "All sessions of this user are ended and a lockout is cleared. Share the new password through a secure channel.");
        if (pw === null) return;
        await api(`/users/${reset.dataset.reset}/password`, { method: "POST", body: { new_password: pw } });
        toast("Password reset");
      } else if (toggle) {
        const active = toggle.dataset.active === "true";
        if (active && !(await confirmDialog(`Disable ${toggle.dataset.name}?`,
          "The user is signed out immediately and cannot sign in until re-enabled. The account and its audit history are kept.", "Disable"))) return;
        await api(`/users/${toggle.dataset.toggle}`, { method: "PATCH", body: { is_active: !active } });
        toast(active ? "User disabled" : "User enabled");
        renderUsers();
      }
    } catch (err) { toast(err.message); }
  });
}

function renderUserForm() {
  if (!can("users:manage")) { view.innerHTML = forbidden(); return; }
  view.innerHTML = `
    <div class="breadcrumb"><a href="#/users">Users</a> / New user</div>
    <div class="page-head"><div><h1>Add user</h1><div class="sub">The user can change the initial password after signing in.</div></div></div>
    <form class="panel form narrow" id="user-form" novalidate>
      <div class="form-error" id="e-_form" role="alert" hidden></div>
      ${field("username", "Username", '<input id="f-username" name="username" maxlength="64" autocomplete="off" placeholder="e.g. jdoe">', { required: true, hint: "lower-case letters, digits, . _ -" })}
      ${field("display_name", "Display name", '<input id="f-display_name" name="display_name" maxlength="200" placeholder="e.g. Jane Doe">')}
      ${field("role", "Role", `<select id="f-role" name="role">${Object.entries(ROLE_LABELS).map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select>`, { required: true })}
      ${field("password", "Initial password", '<input id="f-password" name="password" type="password" autocomplete="new-password" maxlength="128">', { required: true, hint: "min. 12 characters" })}
      <div class="actions"><a class="btn" href="#/users">Cancel</a><button class="btn btn-primary" type="submit">Create user</button></div>
    </form>`;
  const form = document.getElementById("user-form");
  form.elements.username.focus();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const get = (n) => form.elements[n].value.trim();
    try {
      await api("/users", { method: "POST", body: { username: get("username"), display_name: get("display_name") || null,
        role: get("role"), password: form.elements.password.value } });
      toast("User created");
      location.hash = "#/users";
    } catch (err) {
      const msg = typeof err.detail === "string" ? err.detail : null;
      showErrors(form, err.status === 409 ? { username: msg }
        : msg && /password/i.test(msg) ? { password: msg }
        : msg && /username/i.test(msg) ? { username: msg }
        : err.status === 422 ? fieldErrors(err.detail) : { _form: err.message });
    }
  });
}

/* ---------- audit log (admin) ---------- */

const ACTION_GROUPS = [["", "All actions"], ["auth.*", "Sign-in & passwords"], ["asset.*", "Assets"],
  ["user.*", "User management"], ["access.*", "Denied access"], ["monitoring.*", "Monitoring"],
  ["finding.*", "Findings"], ["finding.auto_close", "Findings resolved by re-scan"]];

function describeDetails(e) {
  const d = e.details;
  if (!d) return "";
  if (d.changes) {
    return Object.entries(d.changes).map(([k, c]) =>
      `<div><span class="muted">${esc(k)}:</span> ${dash(Array.isArray(c.from) ? c.from.join(", ") : c.from)} → ${dash(Array.isArray(c.to) ? c.to.join(", ") : c.to)}</div>`).join("");
  }
  const flat = d.values ? { ...d.values } : d;
  return Object.entries(flat).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `<div><span class="muted">${esc(k)}:</span> ${esc(Array.isArray(v) ? v.join(", ") : v)}</div>`).join("");
}

async function renderAudit() {
  if (!can("audit:read")) { view.innerHTML = forbidden(); return; }
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const targetFilter = params.get("target_id");
  view.innerHTML = `
    <div class="page-head"><div><h1>Audit log</h1><div class="sub">Append-only record of security-relevant actions</div></div></div>
    <section class="panel">
      <form class="filters audit-filters" id="audit-filters">
        <label class="field">Action<select name="action">${ACTION_GROUPS.map(([v, l]) =>
          `<option value="${v}" ${params.get("action") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field">User<input name="actor" maxlength="64" value="${esc(params.get("actor") || "")}" placeholder="username"></label>
        <label class="field">Outcome<select name="outcome">${[["", "All"], ["success", "Success"], ["failure", "Failure"], ["denied", "Denied"]]
          .map(([v, l]) => `<option value="${v}" ${params.get("outcome") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        ${targetFilter ? `<div class="field">Target<span class="tag">${esc(params.get("target_type"))} ${esc(targetFilter.slice(0, 8))}
          <a href="#/audit" aria-label="Remove target filter">×</a></span></div>` : ""}
      </form>
      <div id="audit-results"><div class="empty">Loading…</div></div>
    </section>`;
  const form = document.getElementById("audit-filters");
  const sync = () => {
    const p = new URLSearchParams();
    for (const n of ["action", "actor", "outcome"]) if (form.elements[n].value.trim()) p.set(n, form.elements[n].value.trim());
    if (targetFilter) { p.set("target_type", params.get("target_type")); p.set("target_id", targetFilter); }
    history.replaceState(null, "", `#/audit?${p}`);
    loadAudit(p, 0);
  };
  let timer;
  form.addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(sync, e.target.name === "actor" ? 300 : 0); });
  form.addEventListener("submit", (e) => { e.preventDefault(); sync(); });
  loadAudit(params, 0);
}

async function loadAudit(params, offset) {
  const box = document.getElementById("audit-results");
  const q = new URLSearchParams(params);
  q.set("limit", "100");
  q.set("offset", String(offset));
  let data;
  try { data = await api(`/audit?${q}`); }
  catch (err) { box.innerHTML = `<div class="empty">${esc(err.message)}</div>`; return; }
  if (!box.isConnected) return;                       // user navigated away while loading
  const rows = data.items.map((e) => `<tr>
      <td title="${esc(e.occurred_at)}">${esc(fmtDate(e.occurred_at))}</td>
      <td class="mono">${dash(e.actor_username)}</td>
      <td class="mono">${esc(e.action)}</td>
      <td><span class="badge outcome-${esc(e.outcome)}">${esc(e.outcome)}</span></td>
      <td>${e.target_type ? `${esc(e.target_type)}: ${e.target_type === "asset" && e.target_id
        ? `<a href="#/assets/${esc(e.target_id)}">${esc(e.target_label || e.target_id)}</a>` : esc(e.target_label || e.target_id)}` : '<span class="muted">—</span>'}</td>
      <td class="mono">${dash(e.ip_address)}</td>
      <td class="details">${describeDetails(e)}</td></tr>`).join("");
  const table = offset === 0 ? null : box.querySelector("tbody");
  if (table) {
    table.insertAdjacentHTML("beforeend", rows);
  } else if (!data.items.length) {
    box.innerHTML = '<div class="empty"><h2>No matching events</h2></div>';
    return;
  } else {
    box.innerHTML = `<div class="table-meta"><span>${data.total} event${data.total === 1 ? "" : "s"}</span></div>
      <div class="table-wrap"><table class="audit"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Outcome</th>
      <th>Target</th><th>IP</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div><div id="audit-more"></div>`;
  }
  const more = box.querySelector("#audit-more");
  const shown = offset + data.items.length;
  more.innerHTML = shown < data.total ? `<div class="actions pad"><button class="btn" id="audit-more-btn">Load more (${data.total - shown} left)</button></div>` : "";
  document.getElementById("audit-more-btn")?.addEventListener("click", () => loadAudit(params, shown));
}

/* ---------- risk, findings and assessments ---------- */

const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const FINDING_STATUS_LABELS = { open: "Open", in_remediation: "In remediation", accepted_risk: "Accepted risk",
                                resolved: "Resolved", verified_fixed: "Verified fixed" };
const CLOSED = new Set(["resolved", "verified_fixed"]);
const TRIGGER_LABELS = { correlation: "Assessment run", kev_refresh: "KEV update", finding_status: "Finding status",
                         asset_change: "Asset change", rescore: "Rescore", manual: "Manual", scan: "After scan",
                         scheduled: "Scheduled" };

const riskBadge = (score, level) => (score === null || score === undefined)
  ? '<span class="muted">—</span>'
  : `<span class="badge crit-${esc(String(level).toLowerCase())}" title="Risk ${esc(score)} of 100">
       <span class="dot" aria-hidden="true"></span>${esc(score)} · ${esc(level)}</span>`;

/** Asset-level risk: never confuse "not assessed" or "nothing could be checked" with "no risk". */
function riskCell(r) {
  if (!r) return '<span class="muted small" title="No assessment has run for this asset yet">not assessed</span>';
  const inactive = r.asset_status && r.asset_status !== "active"
    ? ' <span class="muted small" title="Inactive assets are no longer reassessed">(inactive, last known)</span>' : "";
  const warnings = esc(r.correlation_warnings.join("\n"));
  if (r.max_score === null) {
    return (r.correlation_warnings.length
      ? `<span class="badge warn" title="${warnings}">incomplete</span><span class="sr-only">${warnings}</span>`
      : '<span class="muted small">no open findings</span>') + inactive;
  }
  const warn = r.correlation_warnings.length
    ? ` <span class="badge warn" title="${warnings}">!</span><span class="sr-only">${warnings}</span>` : "";
  return riskBadge(r.max_score, r.max_level) + warn + inactive;
}

const findingStatusBadge = (s) => `<span class="badge fstatus-${esc(s)}">${esc(FINDING_STATUS_LABELS[s] ?? s)}</span>`;

function whyBlock(risk) {
  if (!risk) return '<p class="muted">Not assessed yet.</p>';
  const factors = risk.factors.map((f) => `<tr><td>${esc(f.label)}</td><td>${esc(f.value)}</td>
      <td class="num">${esc(f.points)} / ${esc(f.max_points)}</td><td>${esc(f.reason)}</td></tr>`).join("");
  return `<p class="why">${esc(risk.why)}</p>
    ${risk.unknown_factors.length ? `<p class="small muted">Unknown, scored conservatively: ${esc(risk.unknown_factors.join(", "))}</p>` : ""}
    <div class="table-wrap"><table class="factors"><thead><tr><th>Factor</th><th>Value</th><th>Points</th><th>Reason</th></tr></thead>
    <tbody>${factors}</tbody></table></div>
    <p class="small muted">Model version ${esc(risk.model_version)} · scored ${esc(fmtDate(risk.assessed_at))}</p>`;
}

/** Jira integration status for the findings tables; never throws (null = unknown). */
async function loadJira() {
  if (JIRA && Date.now() - JIRA_AT < 30000) return JIRA;
  try { JIRA = await api("/integrations/jira"); JIRA_AT = Date.now(); }
  catch { JIRA = null; }
  return JIRA;
}

const JIRA_STATE_LABELS = { pending: "Pending", sending: "Pending", failed: "Retrying", error: "Failed",
                            skipped: "Not created", created: "Created" };

/** Jira cell: task link / delivery state / why not eligible, plus Create or Retry for writers. */
function jiraCell(f, editable) {
  const t = f.ticket;
  const enabled = JIRA?.state === "enabled";
  const el = f.jira_eligibility;
  const button = (text) => editable && enabled
    ? ` <button type="button" class="btn btn-small" data-jira="${esc(f.id)}">${esc(text)}</button>` : "";
  if (t?.issue_key) {
    const link = /^https:\/\//.test(t.issue_url || "")
      ? `<a href="${esc(t.issue_url)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(t.issue_key)}</a>`
      : `<span class="mono">${esc(t.issue_key)}</span>`;
    return link + (t.jira_status ? `<div class="small muted">${esc(t.jira_status)}</div>` : "");
  }
  if (t) {
    const title = t.last_error ? `${t.error_category ? `[${t.error_category}] ` : ""}${t.last_error}` : "";
    const cls = t.state === "error" ? "badge crit-high" : t.state === "failed" || t.state === "skipped" ? "badge warn" : "badge";
    const retry = t.state === "error" ? button("Retry") : t.state === "skipped" && el?.manual ? button("Create Jira Task") : "";
    return `<span class="${cls}" title="${esc(title)}">${esc(JIRA_STATE_LABELS[t.state] ?? t.state)}</span>`
      + (title ? `<span class="sr-only">${esc(title)}</span>` : "") + retry;
  }
  if (!enabled) return '<span class="muted small" title="Jira integration is not enabled">—</span>';
  if (el?.automatic) return '<span class="badge" title="Qualifies; the task is created shortly">Pending</span>';
  return `<span class="muted small" title="${esc(el?.reason ?? "")}">Not eligible</span>`
    + `<span class="sr-only">${esc(el?.reason ?? "")}</span>` + (el?.manual ? button("Create Jira Task") : "");
}

/** After a task was requested: check its delivery every second (at most 30 s) and put the
 *  Jira link into the finding's cell as soon as it exists. Falls back to a reload. */
async function waitForTicket(findingId, cell, reload) {
  const finding = { id: findingId, ticket: null, jira_eligibility: null };
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    if (!cell || !cell.isConnected) return;               // the user moved on
    let t;
    try { t = await api(`/findings/${encodeURIComponent(findingId)}/ticket`); } catch { continue; }
    finding.ticket = t;
    cell.innerHTML = jiraCell(finding, false);
    if (t.state === "pending" || t.state === "sending") continue;
    if (t.issue_key) toast(`Jira task ${t.issue_key} created`);
    else toast(`Jira task: ${JIRA_STATE_LABELS[t.state] ?? t.state}${t.last_error ? ` - ${t.last_error}` : ""}`);
    reload();                                              // refresh buttons, details and counts
    return;
  }
  reload();
}

function findingRows(items, { showAsset = true, actions = true } = {}) {
  const editable = actions && can("findings:write");
  return items.map((f) => `
    <tr data-finding="${esc(f.id)}">
      <td>${riskBadge(f.risk?.score, f.risk?.level)}</td>
      <td><a href="${esc(f.cve.nvd_url)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(f.cve.id)}</a>
        ${f.cve.known_exploited ? '<span class="badge crit-critical" title="Listed in CISA KEV">KEV</span>' : ""}
        <div class="small muted">CVSS ${dash(f.cve.cvss_score)}</div></td>
      ${showAsset ? `<td><a href="#/assets/${esc(f.asset_id)}">${esc(f.asset_name)}</a></td>` : ""}
      <td>${esc(f.software)} <span class="mono small">${dash(f.version)}</span></td>
      <td class="mono">${f.port ? `${esc(f.port)}/${esc(f.protocol ?? "")}` : dash(null)}</td>
      <td>${f.confidence === "low" ? '<span class="badge warn" title="Version unknown or platform-specific CVE">low</span>' : "high"}</td>
      <td>${findingStatusBadge(f.status)}</td>
      <td class="jira-cell">${jiraCell(f, editable)}</td>
      <td><div class="row-actions">
        <button type="button" class="btn btn-small" data-why="${esc(f.id)}" aria-expanded="false"
          aria-controls="why-${esc(f.id)}">Why?</button>
        ${editable && !CLOSED.has(f.status) ? `<select class="status-select" data-status="${esc(f.id)}"
          aria-label="Change status of ${esc(f.cve.id)} on ${esc(f.asset_name)}">
          ${["open", "in_remediation", "accepted_risk"].map((s) =>
            `<option value="${s}" ${s === f.status ? "selected" : ""}>${esc(FINDING_STATUS_LABELS[s])}</option>`).join("")}
        </select>` : ""}
      </div></td>
    </tr>
    <tr class="why-row" id="why-${esc(f.id)}" data-why-row="${esc(f.id)}" hidden><td colspan="${showAsset ? 9 : 8}">${whyBlock(f.risk)}
      ${f.status_reason ? `<p class="small"><strong>Status reason:</strong> ${esc(f.status_reason)}</p>` : ""}
      ${f.ticket?.issue_key ? `<p class="small"><strong>Jira task:</strong> ${jiraCell(f, false)}</p>` : ""}</td></tr>`).join("");
}

function findingTable(items, opts = {}) {
  const showAsset = opts.showAsset ?? true;
  return `<div class="table-wrap"><table class="findings"><thead><tr><th>Risk</th><th>CVE</th>
    ${showAsset ? "<th>Asset</th>" : ""}<th>Software</th><th>Port</th><th>Confidence</th><th>Status</th><th>Jira</th><th></th></tr></thead>
    <tbody>${findingRows(items, opts)}</tbody></table></div>`;
}

/** Wire "Why?" toggles and status selects inside `box`; `reload` re-renders after a change. */
function wireFindings(box, reload) {
  box.addEventListener("click", async (e) => {
    const jiraBtn = e.target.closest("[data-jira]");
    if (jiraBtn) {
      const id = jiraBtn.dataset.jira;
      const cell = jiraBtn.closest(".jira-cell");
      jiraBtn.disabled = true;
      try {
        const r = await api(`/findings/${encodeURIComponent(id)}/ticket`, { method: "POST" });
        toast(r.queued ? "Jira task requested - creating it…" : "The Jira task already exists");
      } catch (err) { toast(err.message); reload(); return; }
      JIRA = null;
      await waitForTicket(id, cell, reload);            // delivery runs in the background
      return;
    }
    const btn = e.target.closest("[data-why]");
    if (!btn) return;
    const row = box.querySelector(`[data-why-row="${CSS.escape(btn.dataset.why)}"]`);
    row.hidden = !row.hidden;
    btn.setAttribute("aria-expanded", String(!row.hidden));
  });
  box.addEventListener("change", async (e) => {
    const sel = e.target.closest("[data-status]");
    if (!sel) return;
    const status = sel.value;
    let reason = null;
    if (status === "accepted_risk") {
      reason = await promptValue("Accept risk", "Why is this risk accepted? The reason is stored and audit-logged.",
                                 "Reason (required)");
      if (reason === null) { reload(); return; }                       // cancelled
      if (!reason.trim()) { toast("A reason is required to accept a risk"); reload(); return; }
    }
    sel.disabled = true;
    try {
      await api(`/findings/${encodeURIComponent(sel.dataset.status)}`, { method: "PATCH", body: { status, reason } });
      toast(`Status set to "${FINDING_STATUS_LABELS[status]}"`);
    } catch (err) {
      toast(err.message);
    }
    reload();
  });
}

async function renderFindings() {
  if (!can("findings:read")) { view.innerHTML = forbidden(); return; }
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const drill = DRILL_FILTERS.filter((k) => params.get(k));
  if (!params.has("status") && !drill.length) params.set("status", "open");
  const assetId = params.get("asset_id");
  view.innerHTML = `
    <div class="page-head">
      <div><h1>Findings</h1><div class="sub">Vulnerabilities ranked by contextual risk, not by CVSS alone</div></div>
    </div>
    ${assetId ? `<div class="notice">Showing one asset only. <a href="#/findings">Show all assets</a></div>` : ""}
    ${drill.length ? `<div class="notice">Filtered from the dashboard: ${esc(describeDrill(params))}.
      <a href="#/findings">Clear</a></div>` : ""}
    <section class="panel">
      <form class="filters filters-4" id="ffilters" role="search">
        <label class="field">Search
          <input type="search" name="q" value="${esc(params.get("q") || "")}"
                 placeholder="CVE, software or asset" maxlength="100" autocomplete="off"></label>
        <label class="field">Status<select name="status"><option value="">All</option>
          ${Object.entries(FINDING_STATUS_LABELS).map(([v, t]) =>
            `<option value="${v}" ${params.get("status") === v ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>
        <label class="field">CVSS severity<select name="severity"><option value="">All</option>
          ${["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((v) =>
            `<option value="${v}" ${params.get("severity") === v ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
        <label class="field checkbox"><input type="checkbox" name="kev" ${params.get("kev") === "true" ? "checked" : ""}>
          Only CISA KEV (actively exploited)</label>
      </form>
      <div id="fresults"><div class="empty">Loading…</div></div>
    </section>`;
  const form = document.getElementById("ffilters");
  form.addEventListener("submit", (e) => e.preventDefault());
  let searchTimer;
  form.addEventListener("input", (e) => {                 // search as you type (debounced)
    if (e.target.name !== "q") return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => form.dispatchEvent(new Event("change")), 300);
  });
  form.addEventListener("change", () => {
    const p = new URLSearchParams();
    if (form.elements.q.value.trim()) p.set("q", form.elements.q.value.trim());
    p.set("status", form.elements.status.value);
    if (form.elements.severity.value) p.set("severity", form.elements.severity.value);
    if (form.elements.kev.checked) p.set("kev", "true");
    if (assetId) p.set("asset_id", assetId);
    for (const k of drill) p.set(k, params.get(k));
    history.replaceState(null, "", `#/findings?${p}`);
    loadFindings(p);
  });
  wireFindings(document.getElementById("fresults"), () => loadFindings(currentFindingParams()));
  loadFindings(params);
}

function currentFindingParams() {
  const p = new URLSearchParams(location.hash.split("?")[1] || "");
  if (!p.has("status") && !DRILL_FILTERS.some((k) => p.get(k))) p.set("status", "open");
  return p;
}

/* Filters a dashboard link can set (all supported by GET /findings). */
const DRILL_FILTERS = ["unresolved", "active_assets", "risk_level", "min_risk", "first_seen_from", "first_seen_to", "cve"];

function describeDrill(p) {
  const parts = [];
  if (p.get("unresolved")) parts.push("unresolved (open or in remediation)");
  if (p.get("active_assets")) parts.push("active assets only");
  if (p.get("risk_level")) parts.push(`risk level ${p.get("risk_level")}`);
  if (p.get("min_risk")) parts.push(`risk score ≥ ${p.get("min_risk")}`);
  if (p.get("first_seen_from") || p.get("first_seen_to")) {
    parts.push(`first detected ${p.get("first_seen_from") || "…"} to before ${p.get("first_seen_to") || "…"} (UTC)`);
  }
  if (p.get("cve")) parts.push(p.get("cve"));
  return parts.join(" · ");
}

async function loadFindings(params) {
  const box = document.getElementById("fresults");
  if (!box) return;
  const q = new URLSearchParams({ sort: "risk", limit: "200" });
  for (const name of ["q", "status", "severity", "kev", "asset_id", ...DRILL_FILTERS]) {
    if (params.get(name)) q.set(name, params.get(name));
  }
  let data;
  try { [data] = await Promise.all([api(`/findings?${q}`), loadJira()]); }
  catch (err) { box.innerHTML = `<div class="empty">Could not load findings: ${esc(err.message)}</div>`; return; }
  if (!data.items.length) {
    box.innerHTML = `<div class="empty"><h2>No matching findings</h2>
      Findings appear after an assessment. See <a href="#/assessments">Assessments</a> for when the last one ran.</div>`;
    return;
  }
  box.innerHTML = `<div class="table-meta"><span>${data.total} finding${data.total === 1 ? "" : "s"}</span>
      ${data.total > data.items.length ? `<span>showing the ${data.items.length} highest-risk</span>` : ""}</div>
    ${findingTable(data.items)}`;
}

/* Asset detail: risk panel */
async function loadRiskPanel(a) {
  const box = document.getElementById("risk-panel");
  if (!box) return;
  let risk, top, hist;
  try {
    [risk, top, hist] = await Promise.all([
      api(`/assets/${a.id}/risk`),
      api(`/assets/${a.id}/findings?status=open&sort=risk&limit=5`),
      api(`/assets/${a.id}/risk/history?limit=10`),
      loadJira(),
    ]);
  } catch (err) {
    box.innerHTML = `<div class="panel empty">Could not load the risk: ${esc(err.message)}</div>`;
    return;
  }
  const canRun = can("findings:write") && a.status === "active";
  const summary = !risk.assessed
    ? '<p class="muted">This asset has not been assessed yet.</p>'
    : props([
        ["Risk", riskCell(risk)],
        ["Open findings", esc(risk.open_findings)],
        ["Accepted risks", esc(risk.accepted_findings)],
        ["With unknown inputs", esc(risk.findings_with_unknowns)],
        ["Last assessed", esc(fmtDate(risk.assessed_at))],
      ]);
  const warnings = risk.correlation_warnings?.length
    ? `<div class="notice warn-notice"><strong>Not everything could be checked:</strong>
         <ul>${risk.correlation_warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "";
  const histRows = hist.map((h) => `<tr><td>${esc(fmtDate(h.recorded_at))}</td>
      <td>${esc(TRIGGER_LABELS[h.trigger] ?? h.trigger)}${h.run_id ? ` <span class="muted small">#${esc(h.run_id)}</span>` : ""}</td>
      <td>${riskBadge(h.max_score, h.max_level)}</td><td class="num">${esc(h.open_findings)}</td>
      <td class="num">${esc(h.accepted_findings)}</td></tr>`).join("");
  box.innerHTML = `<section class="panel section risk-panel">
      <div class="section-head"><h2>Risk</h2>
        ${canRun ? '<button type="button" class="btn btn-primary" id="assess-now">Assess now</button>' : ""}</div>
      <div id="assess-status" role="status" aria-live="polite"></div>
      ${summary}${warnings}
      ${top.items.length ? `<h3>Highest-risk open findings</h3>${findingTable(top.items, { showAsset: false, actions: false })}
        <p class="small"><a href="#/findings?status=open&asset_id=${esc(a.id)}">All findings of this asset (${esc(top.total)})</a></p>` : ""}
      ${hist.length ? `<h3>Risk history</h3><div class="table-wrap"><table><thead><tr><th>When</th><th>Trigger</th>
        <th>Risk</th><th>Open</th><th>Accepted</th></tr></thead><tbody>${histRows}</tbody></table></div>` : ""}
    </section>`;
  if (!box.dataset.wired) {                // the panel is re-rendered in place: add listeners once
    box.dataset.wired = "1";
    wireFindings(box, () => loadRiskPanel(a));
  }
  document.getElementById("assess-now")?.addEventListener("click", (e) =>
    startAssessment(e.target, [a.id], document.getElementById("assess-status"), () => loadRiskPanel(a)));
}

/* Start a run and follow it until it finishes. `onProgress` runs after every status poll. */
async function startAssessment(button, assetIds, statusBox, onDone, onProgress) {
  button.disabled = true;
  let run;
  try {
    run = await api("/correlation/run", { method: "POST", body: assetIds ? { asset_ids: assetIds } : undefined });
  } catch (err) {
    toast(err.status === 409 ? "An assessment is already running - please wait for it to finish." : err.message);
    button.disabled = false;
    return;
  }
  const started = Date.now();
  const show = (r) => {
    if (statusBox) statusBox.innerHTML = `<div class="notice">Assessment #${esc(r.id)}: <strong>${esc(r.status)}</strong>
      ${r.assets_processed ? ` · ${esc(r.assets_processed)} asset(s) processed` : ""}</div>`;
  };
  show(run);
  let failures = 0;
  while (["queued", "running"].includes(run.status) && Date.now() - started < 15 * 60 * 1000) {
    await new Promise((r) => setTimeout(r, 2000));
    if (!document.body.contains(button)) return;            // user navigated away
    try {
      run = await api(`/correlation/runs/${run.id}`);
      failures = 0;
    } catch {
      if (++failures >= 3) break;                            // keep polling through short outages
      continue;
    }
    show(run);
    onProgress?.();
  }
  button.disabled = false;
  if (["queued", "running"].includes(run.status)) {
    toast("Assessment status unknown - see the Assessments page");
  } else {
    toast(run.status === "success" ? "Assessment finished"
      : run.status === "partial" ? "Assessment finished with warnings" : `Assessment ${run.status}`);
  }
  onDone?.();
}

/* Assessments page: schedule, status, history of runs */
async function renderAssessments() {
  if (!can("findings:read")) { view.innerHTML = forbidden(); return; }
  view.innerHTML = `
    <div class="page-head">
      <div><h1>Assessments</h1><div class="sub">When assets are checked against current vulnerability data</div></div>
      ${can("findings:write") ? `<div class="actions">
        <button type="button" class="btn" id="kev-refresh">Update CISA KEV now</button>
        <button type="button" class="btn btn-primary" id="run-all">Assess all assets now</button></div>` : ""}
    </div>
    <div id="run-status" role="status" aria-live="polite"></div>
    <div id="schedule"><div class="panel empty">Loading…</div></div>
    <div id="jira-panel"></div>
    <section class="panel section"><h2>Recent assessment runs</h2><div id="runs"><div class="empty">Loading…</div></div></section>`;
  document.getElementById("run-all")?.addEventListener("click", (e) =>
    startAssessment(e.target, null, document.getElementById("run-status"), loadAssessments, loadAssessments));
  document.getElementById("kev-refresh")?.addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const r = await api("/correlation/kev/refresh", { method: "POST" });
      toast(`CISA KEV updated: ${r.kev_entries} entries`);
    } catch (err) { toast(err.message); }
    e.target.disabled = false;
    loadAssessments();
  });
  loadAssessments();
  loadJiraPanel();
}

async function loadJiraPanel() {
  const box = document.getElementById("jira-panel");
  if (!box) return;
  JIRA = null;
  const j = await loadJira();
  if (!box.isConnected || !j) return;
  const counts = Object.entries(j.tickets).filter(([, n]) => n).map(([k, n]) => `${esc(JIRA_STATE_LABELS[k] ?? k)}: ${esc(n)}`);
  const state = { enabled: "Enabled", disabled: "Disabled", misconfigured: "Misconfigured" }[j.state] ?? j.state;
  box.innerHTML = section("Jira tasks", props([
    ["Integration", `<span class="badge ${j.state === "misconfigured" ? "crit-high" : ""}">${esc(state)}</span>`
      + (j.problem ? ` <span class="small">${esc(j.problem)}</span>` : "")],
    ...(j.state === "disabled" ? [] : [
      ["Project", `<span class="mono">${esc(j.project_key ?? "—")}</span> · ${esc(j.issue_type)} · label <span class="mono">${esc(j.label)}</span>`],
      ["Automatic tasks", j.policy.auto_create
        ? `risk level ${esc(j.policy.levels.join(", "))}${j.policy.include_low_confidence ? " (incl. potential findings)" : " (confirmed version matches only)"}`
        : "off - manual tasks only"],
      ["Tasks", counts.length ? counts.join(" · ") : "none yet"],
      ...(j.last_error ? [["Last error", `<span class="small">${esc(j.last_error)}</span>`]] : []),
    ]),
  ]));
}

async function loadAssessments() {
  const box = document.getElementById("schedule");
  const runsBox = document.getElementById("runs");
  if (!box || !runsBox) return;
  let s, runs;
  try { [s, runs] = await Promise.all([api("/correlation/schedule"), api("/correlation/runs?limit=20")]); }
  catch (err) { box.innerHTML = `<div class="panel empty">Could not load the schedule: ${esc(err.message)}</div>`; return; }
  const yesNo = (v) => (v ? "Yes" : "No");
  box.innerHTML = section("Schedule and data", props([
    ["Periodic assessment", s.periodic_enabled ? `Every ${esc(s.interval_hours)} h` : '<span class="muted">Off</span>'],
    ["Next periodic run", s.next_run_at ? esc(fmtDate(s.next_run_at)) : '<span class="muted">not scheduled in this process</span>'],
    ["After each version scan", yesNo(s.after_scan)],
    ["CISA KEV catalogue", s.kev_last_synced
      ? `${esc(s.kev_entries)} entries, updated ${esc(fmtDate(s.kev_last_synced))}
         ${s.kev_current ? "" : ' <span class="badge warn" title="Older than 48 h: KEV status counts as unknown">outdated</span>'}`
      : '<span class="badge warn">never downloaded - KEV status counts as unknown</span>'],
    ["NVD API key", s.nvd_api_key_configured ? "configured" : '<span class="muted">not set (slower NVD lookups)</span>'],
    ["Running now", s.active_run ? `#${esc(s.active_run.id)} (${esc(s.active_run.status)})` : '<span class="muted">—</span>'],
  ]));
  runsBox.innerHTML = runs.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Started</th><th>Trigger</th>
      <th>Status</th><th class="num">Assets</th><th class="num">New</th><th class="num">Reopened</th><th class="num">Closed</th>
      <th>Duration</th><th>Warnings</th></tr></thead><tbody>${runs.map((r) => `<tr>
        <td class="mono">${esc(r.id)}</td><td>${esc(fmtDate(r.started_at))}</td>
        <td>${esc(TRIGGER_LABELS[r.trigger] ?? r.trigger)}</td>
        <td><span class="badge run-${esc(r.status)}">${esc(r.status)}</span></td>
        <td class="num">${esc(r.assets_processed)}</td><td class="num">${esc(r.findings_opened)}</td>
        <td class="num">${esc(r.findings_reopened)}</td><td class="num">${esc(r.findings_closed)}</td>
        <td>${r.duration_seconds !== null ? `${esc(r.duration_seconds.toFixed(1))} s` : dash(null)}</td>
        <td class="details">${r.warnings ? `<details><summary>${esc(r.warnings.split("\n").length)} warning(s)</summary>
          <pre>${esc(r.warnings)}</pre></details>` : dash(null)}</td></tr>`).join("")}</tbody></table></div>`
    : '<div class="empty">No assessment has run yet.</div>';
}

/* ---------- candidate hosts (discovered, not yet linked) — ASSET-96 ---------- */

async function renderCandidates() {
  if (!can("assets:write")) { view.innerHTML = forbidden(); return; }
  view.innerHTML = `
    <div class="page-head"><div><h1>Candidate hosts</h1>
      <div class="sub">Discovered hosts not yet linked to a managed asset. Link them to an existing asset or create one.</div></div></div>
    <section class="panel" id="candidates-box"><div class="empty">Loading…</div></section>`;
  loadCandidates();
}

async function loadCandidates() {
  const box = document.getElementById("candidates-box");
  let hosts;
  try { hosts = await api("/monitoring/candidates"); }
  catch (err) { box.innerHTML = `<div class="empty">Could not load candidates: ${esc(err.message)}</div>`; return; }
  if (!hosts.length) {
    box.innerHTML = `<div class="empty"><h2>No candidate hosts</h2>
      <p class="muted">Every discovered host is already linked to a managed asset.</p></div>`;
    return;
  }
  const match = (h) => h.ambiguous
    ? `<span class="muted">Several assets match — link manually or create one</span>`
    : h.suggested_asset_id
      ? `Suggested: <a href="#/assets/${esc(h.suggested_asset_id)}" class="mono">${esc(shortId(h.suggested_asset_id))}</a>`
      : `<span class="muted">No match</span>`;
  const rows = hosts.map((h) => `<tr>
      <td class="mono">${esc(h.ip)}</td>
      <td>${dash(h.hostname)}</td>
      <td>${match(h)}</td>
      <td class="actions pad">
        ${!h.ambiguous && h.suggested_asset_id
          ? `<button class="btn" data-link="${esc(h.host_id)}" data-asset="${esc(h.suggested_asset_id)}">Link to suggested</button>` : ""}
        <a class="btn btn-primary" href="#/candidates/${esc(h.host_id)}/new-asset">Create asset</a>
      </td></tr>`).join("");
  box.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>IP address</th><th>Hostname</th><th>Suggested match</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
  box.querySelectorAll("button[data-link]").forEach((btn) => btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await api(`/monitoring/hosts/${btn.dataset.link}/link`, { method: "POST", body: { asset_id: btn.dataset.asset } });
      toast("Host linked to asset");
      loadCandidates();
    } catch (err) { toast(err.message); btn.disabled = false; }
  }));
}

/* ---------- executive dashboard ---------- */

const LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const fmtDay = (iso) => iso ? new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined,
  { dateStyle: "medium", timeZone: "UTC" }) : "—";
const monthLabel = (ym) => new Date(`${ym}-01T00:00:00Z`).toLocaleDateString(undefined,
  { month: "short", year: "numeric", timeZone: "UTC" });
const nextMonth = (ym) => {
  const [y, m] = ym.split("-").map(Number);
  return m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, "0")}`;
};
const findingsLink = (params) => `#/findings?${new URLSearchParams(params)}`;

function kpiCard({ label, value, unit = "", sub = "", href = "", unavailable = "", extra = "" }) {
  const body = unavailable
    ? `<div class="kpi-value unavailable">Unavailable</div><p class="kpi-note">${esc(unavailable)}</p>`
    : `<div class="kpi-value">${esc(value)}<span class="kpi-unit">${esc(unit)}</span></div>
       ${sub ? `<p class="kpi-note">${sub}</p>` : ""}`;
  return `<article class="panel kpi">
      <h2 class="kpi-label">${esc(label)}</h2>${body}${extra}
      ${href && !unavailable ? `<a class="kpi-link" href="${esc(href)}">View details</a>` : ""}
    </article>`;
}

function changeText(delta, { better = "up", unit = "" } = {}) {
  if (delta === null || delta === undefined) return "";
  if (delta === 0) return '<span class="delta flat">no change</span>';
  const good = better === "up" ? delta > 0 : delta < 0;
  return `<span class="delta ${good ? "good" : "bad"}">${delta > 0 ? "▲" : "▼"} ${esc(Math.abs(delta))}${esc(unit)}</span>`;
}

/* Small, accessible SVG charts (no library). Values are numbers from the API, labels escaped. */
function lineChart(points, { max = null, label, series }) {
  const W = 640, H = 200, L = 36, R = 12, T = 12, B = 28;
  const all = series.flatMap((s) => points.map((p) => p[s.key])).filter((v) => v !== null && v !== undefined);
  const top = max ?? Math.max(4, ...all);
  const x = (i) => L + (points.length === 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (points.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const ticks = [0, Math.round(top / 2), top];
  const grid = ticks.map((t) => `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" class="grid"/>
      <text x="${L - 6}" y="${y(t) + 4}" class="axis" text-anchor="end">${t}</text>`).join("");
  const lines = series.map((s) => {
    const pts = points.map((p, i) => (p[s.key] === null || p[s.key] === undefined ? null : [x(i), y(p[s.key])]));
    const segs = [];
    let cur = [];
    for (const pt of pts) { if (pt) cur.push(pt); else if (cur.length) { segs.push(cur); cur = []; } }
    if (cur.length) segs.push(cur);
    return segs.map((seg) => `<polyline class="line ${s.cls}" points="${seg.map((p) => p.join(",")).join(" ")}"/>`).join("")
      + pts.filter(Boolean).map((p) => `<circle class="dot ${s.cls}" cx="${p[0]}" cy="${p[1]}" r="2.5"/>`).join("");
  }).join("");
  const first = points[0], last = points[points.length - 1];
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="${esc(label)}">
      ${grid}${lines}
      <text x="${L}" y="${H - 8}" class="axis">${esc(fmtDay(first.day))}</text>
      <text x="${W - R}" y="${H - 8}" class="axis" text-anchor="end">${esc(fmtDay(last.day))}</text></svg>
    <div class="legend">${series.map((s) => `<span><i class="sw ${s.cls}"></i>${esc(s.name)}</span>`).join("")}</div>`;
}

function barChart(months) {
  const W = 640, H = 200, L = 36, R = 12, T = 12, B = 28;
  const top = Math.max(4, ...months.flatMap((m) => [m.new, m.resolved]));
  const slot = (W - L - R) / months.length, bw = Math.min(14, slot / 3);
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const ticks = [0, Math.round(top / 2), top];
  const bars = months.map((m, i) => {
    const cx = L + slot * i + slot / 2;
    return `<rect class="bar new" x="${cx - bw - 1}" y="${y(m.new)}" width="${bw}" height="${y(0) - y(m.new)}"><title>${esc(monthLabel(m.month))}: ${m.new} new</title></rect>
      <rect class="bar resolved" x="${cx + 1}" y="${y(m.resolved)}" width="${bw}" height="${y(0) - y(m.resolved)}"><title>${esc(monthLabel(m.month))}: ${m.resolved} resolved</title></rect>
      ${i % 2 === months.length % 2 ? "" : `<text x="${cx}" y="${H - 8}" class="axis" text-anchor="middle">${esc(monthLabel(m.month))}</text>`}`;
  }).join("");
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="New and resolved findings per month">
      ${ticks.map((t) => `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" class="grid"/>
        <text x="${L - 6}" y="${y(t) + 4}" class="axis" text-anchor="end">${t}</text>`).join("")}${bars}</svg>
    <div class="legend"><span><i class="sw new"></i>New</span><span><i class="sw resolved"></i>Resolved</span></div>`;
}

function distribution(byLevel, unscored) {
  const total = LEVEL_ORDER.reduce((n, l) => n + byLevel[l], 0) + unscored;
  if (!total) return '<p class="muted">No unresolved findings on active assets.</p>';
  // bar widths as SVG attributes: the CSP forbids inline style attributes
  const row = (name, count, cls, href) => `<div class="dist-row">
      <span class="dist-label">${href ? `<a href="${esc(href)}">${esc(name)}</a>` : esc(name)}</span>
      <svg class="dist-bar" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">
        <rect class="track" x="0" y="0" width="100" height="10"/>
        <rect class="${cls}" x="0" y="0" width="${Math.max(count ? 2 : 0, (100 * count) / total)}" height="10"/></svg>
      <span class="dist-count">${esc(count)}</span></div>`;
  return LEVEL_ORDER.map((l) => row(l[0] + l.slice(1).toLowerCase(), byLevel[l], `fill crit-${l.toLowerCase()}`,
      findingsLink({ unresolved: 1, active_assets: 1, risk_level: l }))).join("")
    + (unscored ? row("Not yet scored", unscored, "fill unscored", "") : "");
}

function runStatus(run) {
  if (!run) return '<span class="muted">none yet</span>';
  const label = { success: "completed", partial: "completed with warnings", failed: "failed" }[run.status] ?? run.status;
  return `<span class="badge run-${esc(run.status)}">${esc(label)}</span> ${esc(fmtDate(run.finished_at || run.started_at))}
    <span class="muted small">#${esc(run.id)} · ${esc(run.scope === "all" ? "all active assets" : run.scope === "selected" ? "selected assets" : "scope not recorded")}</span>`;
}

async function renderDashboard() {
  if (!can("findings:read")) { view.innerHTML = forbidden(); return; }
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const month = params.get("month") || "";
  view.innerHTML = `<div class="page-head"><div><h1>Security overview</h1>
      <div class="sub">Organisation-wide posture from assessed assets</div></div></div>
    <div class="panel empty">Loading…</div>`;
  const loading = view.querySelector(".panel");
  let d;
  try { d = await api(`/dashboard${month ? `?month=${encodeURIComponent(month)}` : ""}`); }
  catch (err) { loading.innerHTML = `Could not load the dashboard: ${esc(err.message)}`; return; }
  if (!loading.isConnected) return;                   // user navigated away while loading

  const p = d.posture, s = d.security_score, m = d.month_figures, prev = d.previous_month_figures, h = d.health;
  const thisMonth = d.month, monthEnd = nextMonth(thisMonth);
  const firstSeen = { first_seen_from: `${thisMonth}-01`, first_seen_to: `${monthEnd}-01` };
  const coverage = `Based on ${p.assets_assessed} of ${p.assets_active} active assets`
    + (p.assets_no_data ? ` · ${p.assets_no_data} without software data` : "")
    + (p.assets_never_assessed ? ` · ${p.assets_never_assessed} never assessed` : "")
    + (p.open_outside_score ? ` · ${p.open_outside_score} open findings on assets without current data are not in the score` : "");
  const scoreSub = s.value === null ? "" : [
    s.change !== null ? `${changeText(s.change)} vs. ${esc(fmtDay(s.baseline_day))}` : '<span class="muted">no earlier snapshot to compare</span>',
    esc(coverage)].join("<br>");
  const auditLink = can("audit:read") ? "#/audit?action=finding.auto_close" : "";
  const newDelta = m.new_findings - prev.new_findings;

  view.innerHTML = `
    <div class="page-head">
      <div><h1>Security overview</h1>
        <div class="sub">Organisation-wide posture from assessed assets · all periods in UTC</div></div>
      <form class="actions" id="month-form">
        <label class="field inline">Month <input type="month" name="month" value="${esc(thisMonth)}"
          max="${esc(d.generated_at.slice(0, 7))}" min="2000-01"></label>
      </form>
    </div>

    <section class="kpi-grid" aria-label="Security posture">
      ${kpiCard({ label: "Security Score", value: s.value, unit: "/100", sub: scoreSub,
        unavailable: s.value === null ? s.unavailable_reason : "",
        extra: `<details class="method"><summary>How is this calculated?</summary>
          <p>100 − (½ × W + ½ × B), method version ${esc(s.method_version)}.</p>
          <p><strong>W</strong> is the highest contextual risk (Risk Engine, 0–100) of any unresolved finding on an
          assessed active asset, so one severe risk is never averaged away. <strong>B</strong> is the share of assessed
          active assets with an unresolved finding of risk ≥ 65 (HIGH or CRITICAL). Accepted risks and assets without
          software data are excluded; coverage is shown below the score. Higher is better.</p></details>` })}
      ${kpiCard({ label: "Open critical findings", value: d.open_critical_now,
        sub: "Unresolved, risk level CRITICAL, active assets", href: findingsLink({ unresolved: 1, active_assets: 1, risk_level: "CRITICAL" }) })}
      ${kpiCard({ label: `New findings · ${monthLabel(thisMonth)}`, value: m.new_findings,
        sub: `${changeText(newDelta, { better: "down" })} vs. ${esc(monthLabel(prev.month))} (${esc(prev.new_findings)})`,
        href: findingsLink({ ...firstSeen, status: "" }) })}
      ${kpiCard({ label: `Remediation rate · ${monthLabel(thisMonth)}`,
        value: m.remediation_rate, unit: "%",
        unavailable: m.remediation_rate === null ? m.remediation_rate_reason : "",
        sub: m.remediation_rate === null ? "" : `${esc(m.resolved_findings)} resolved of ${esc(m.remediation_workload)}
          (unresolved at month start + new + reopened)` })}
      ${kpiCard({ label: "Assets at risk", value: p.assets_at_risk,
        sub: `Active assets with an unresolved finding of risk ≥ 65 · of ${esc(p.assets_assessed)} assessed`,
        href: findingsLink({ unresolved: 1, active_assets: 1, min_risk: 65 }) })}
    </section>

    <div class="dash-grid">
      <section class="panel section">
        <h2>Monthly highlights · ${esc(monthLabel(thisMonth))}</h2>
        <table class="highlights"><tbody>
          <tr><th scope="row">First detected this month <span class="muted small">(incl. assets deactivated since)</span></th><td class="num"><a href="${esc(findingsLink({ ...firstSeen, status: "" }))}">${esc(m.new_findings)}</a></td>
            <td class="muted small">${esc(monthLabel(prev.month))}: ${esc(prev.new_findings)}</td></tr>
          <tr><th scope="row">… of which critical / high (current risk level)</th>
            <td class="num"><a href="${esc(findingsLink({ ...firstSeen, status: "", risk_level: "CRITICAL" }))}">${esc(m.new_by_level.CRITICAL)}</a> /
              <a href="${esc(findingsLink({ ...firstSeen, status: "", risk_level: "HIGH" }))}">${esc(m.new_by_level.HIGH)}</a></td><td></td></tr>
          <tr><th scope="row">Resolved this month (verified by re-scan)</th>
            <td class="num">${auditLink ? `<a href="${esc(auditLink)}">${esc(m.resolved_findings)}</a>` : esc(m.resolved_findings)}</td>
            <td class="muted small">${esc(monthLabel(prev.month))}: ${esc(prev.resolved_findings)}</td></tr>
          <tr><th scope="row">Reopened this month</th><td class="num">${esc(m.reopened_findings)}</td><td></td></tr>
          <tr><th scope="row">Risks accepted this month</th><td class="num">${esc(m.risk_accepted)}</td><td></td></tr>
          <tr><th scope="row">Open critical findings now</th><td class="num"><a href="${esc(findingsLink({ unresolved: 1, active_assets: 1, risk_level: "CRITICAL" }))}">${esc(d.open_critical_now)}</a></td><td></td></tr>
          <tr><th scope="row">Overdue remediation actions</th><td class="num muted">n/a</td>
            <td class="muted small">${esc(d.unavailable.overdue_actions)}</td></tr>
          <tr><th scope="row">Security Score change</th><td class="num">${s.change !== null ? changeText(s.change) : '<span class="muted">n/a</span>'}</td>
            <td class="muted small">${s.change !== null ? `since ${esc(fmtDay(s.baseline_day))}` : "needs a snapshot from before this month"}</td></tr>
        </tbody></table>
      </section>

      <section class="panel section">
        <h2>Assessment health</h2>
        ${props([
          ["Last full assessment", runStatus(h.last_full_assessment)],
          ["Last assessment run", runStatus(h.last_run)],
          ["Coverage", `${esc(p.assets_assessed)} assessed · ${esc(p.assets_no_data)} without data · ${esc(p.assets_never_assessed)} never assessed
            <span class="muted small">(${esc(p.assets_active)} active)</span>`],
          ["Next scheduled", h.periodic_enabled ? (h.next_run_at ? esc(fmtDate(h.next_run_at)) : '<span class="muted">not scheduled in this process</span>') : '<span class="muted">periodic assessment off</span>'],
          ["CISA KEV data", h.freshness.kev_last_synced ? `${esc(fmtDate(h.freshness.kev_last_synced))} ${h.freshness.kev_current ? "" : '<span class="badge warn">outdated</span>'}` : '<span class="badge warn">never downloaded</span>'],
          ["NVD product data", h.freshness.nvd_newest_product_sync ? `${esc(fmtDate(h.freshness.nvd_oldest_product_sync))} – ${esc(fmtDate(h.freshness.nvd_newest_product_sync))}` : '<span class="muted">none yet</span>'],
          ["Last version scan", h.freshness.last_version_scan_at ? esc(fmtDate(h.freshness.last_version_scan_at)) : '<span class="muted">none yet</span>'],
        ])}
        ${h.recent_problem_runs.length ? `<h3>Runs with problems (30 days)</h3><ul class="problems">${h.recent_problem_runs.map((r) =>
          `<li>${runStatus(r)}${r.first_warnings.length ? `<div class="small muted">${r.first_warnings.map(esc).join("<br>")}</div>` : ""}</li>`).join("")}</ul>` : ""}
        <p class="small"><a href="#/assessments">Assessments and schedule</a></p>
      </section>
    </div>

    <section class="panel section">
      <h2>Top risks</h2>
      ${d.top_risks.length ? `<div class="table-wrap"><table class="top-risks"><thead><tr><th>Risk</th><th>Asset</th><th>Finding</th>
        <th>Context</th><th>Recommended action</th></tr></thead><tbody>${d.top_risks.map((t) => `<tr>
          <td>${riskBadge(t.risk_score, t.risk_level)}</td>
          <td><a href="#/assets/${esc(t.asset_id)}">${esc(t.asset_name)}</a></td>
          <td><a href="${esc(t.nvd_url)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(t.cve_id)}</a>
            ${t.known_exploited ? '<span class="badge crit-critical" title="Listed in CISA KEV">KEV</span>' : ""}
            <div class="small">${esc(t.software)} ${esc(t.version ?? "")}${t.port ? ` · ${esc(t.port)}/${esc(t.protocol ?? "")}` : ""}</div>
            <div class="small muted">${esc(t.why)}</div>
            <a class="small" href="${esc(findingsLink({ asset_id: t.asset_id, cve: t.cve_id, status: "" }))}">Finding details</a></td>
          <td>${critBadge(t.criticality)} ${envBadge(t.environment)}
            <div class="small">Internet-facing: ${esc(label("internet_facing", t.internet_facing))}</div></td>
          <td class="muted small">${t.recommended_action ? esc(t.recommended_action) : esc(d.unavailable.recommended_action)}</td>
        </tr>`).join("")}</tbody></table></div>` : '<p class="muted">No scored unresolved findings on active assets.</p>'}
    </section>

    <div class="dash-grid">
      <section class="panel section">
        <h2>Security Score over time</h2>
        ${d.trend.length >= 2 ? lineChart(d.trend, { max: 100, label: "Security Score per day", series: [{ key: "security_score", name: "Security Score", cls: "score" }] })
          : `<p class="muted">${d.trend.length ? `History starts ${esc(fmtDay(d.trend[0].day))}.` : "No history yet."}
             Daily snapshots are recorded after each assessment, KEV update, status or asset change;
             the chart appears once two days are recorded. Earlier values are not reconstructed.</p>`}
      </section>
      <section class="panel section">
        <h2>Open critical and high findings</h2>
        ${d.trend.length >= 2 ? lineChart(d.trend, { label: "Open critical and high findings per day",
            series: [{ key: "open_critical", name: "Critical", cls: "critical" }, { key: "open_high", name: "High", cls: "high" }] })
          : '<p class="muted">Appears once two days of snapshots are recorded.</p>'}
      </section>
      <section class="panel section">
        <h2>New vs. resolved findings</h2>
        ${barChart(d.series)}
        <p class="small muted">New = first detected in the month; resolved = closed by a re-scan in the month (audit log).</p>
      </section>
      <section class="panel section">
        <h2>Unresolved findings by risk level</h2>
        ${distribution(p.open_by_level, p.open_unscored)}
      </section>
    </div>
    <p class="small muted">Generated ${esc(fmtDate(d.generated_at))}. Figures come from stored assessment results;
      metrics without reliable data are shown as unavailable.</p>`;

  document.getElementById("month-form").addEventListener("submit", (e) => e.preventDefault());
  document.getElementById("month-form").addEventListener("change", (e) => {
    const value = e.target.value;
    if (/^\d{4}-\d{2}$/.test(value)) location.hash = `#/dashboard?month=${value}`;
  });
}

/* ---------- router ---------- */

async function route() {
  if (!ME) {
    try { ME = await api("/auth/me"); }
    catch (err) {
      if (err.status === 401) return renderLogin();
      view.innerHTML = `<div class="empty">The API is not reachable: ${esc(err.message)}</div>`;
      return;
    }
  }
  if (!OPTIONS) {
    try { OPTIONS = await api("/assets/options"); }
    catch (err) { if (ME) view.innerHTML = `<div class="empty">The API is not reachable: ${esc(err.message)}</div>`; return; }
  }
  const home = can("findings:read") ? "/dashboard" : "/assets";
  const path = location.hash.replace(/^#/, "").split("?")[0] || home;
  const parts = path.split("/").filter(Boolean);           // ["assets", id?, "edit"?]
  window.scrollTo(0, 0);
  renderHeader();
  if (parts[0] === "users") return parts[1] === "new" ? renderUserForm() : renderUsers();
  if (parts[0] === "audit") return renderAudit();
  if (parts[0] === "dashboard") return renderDashboard();
  if (parts[0] === "findings") return renderFindings();
  if (parts[0] === "assessments") return renderAssessments();
  if (parts[0] === "account" && parts[1] === "password") return renderPasswordChange();
  if (parts[0] === "candidates") {
    if (parts[2] === "new-asset") return renderForm(null, parts[1]);
    return renderCandidates();
  }
  if (parts[0] !== "assets") { location.hash = `#${home}`; return; }
  if (parts.length === 1) return renderList();
  if (parts[1] === "new") return renderForm(null);
  if (parts[2] === "edit") return renderForm(parts[1]);
  return renderDetail(parts[1]);
}

window.addEventListener("hashchange", route);
route();
