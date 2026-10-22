/* CrowdSec self-hosted console – no build step, no external dependencies. */

const state = {
  user: null,
  csrf: null,
  session: null,
  route: 'dashboard',
  range: '24h',
  cache: {},
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function fmtDate(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function relTime(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

/* ---------------- api ---------------- */

async function api(path, options = {}) {
  const init = { credentials: 'same-origin', headers: { Accept: 'application/json' }, ...options };

  if (init.body !== undefined && typeof init.body !== 'string') {
    init.body = JSON.stringify(init.body);
    init.headers['Content-Type'] = 'application/json';
  }

  if (init.method && init.method !== 'GET') {
    init.headers['X-CSRF-Token'] = state.csrf || '';
  }

  const response = await fetch(path, init);
  const text = await response.text();
  let payload = null;

  if (text) {
    try { payload = JSON.parse(text); } catch { payload = text; }
  }

  if (response.status === 401) {
    showLogin();
    throw new Error('Authentication required');
  }

  if (!response.ok) {
    const message = (payload && payload.message) || response.statusText;
    throw new Error(message);
  }

  return payload;
}

/* ---------------- ui helpers ---------------- */

function toast(message, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function openModal(title, bodyHtml, onMount) {
  const root = $('#modal-root');
  root.innerHTML = `
    <div class="overlay" id="overlay">
      <div class="modal" role="dialog" aria-modal="true">
        <div class="modal-head">
          <h3>${esc(title)}</h3>
          <button class="close" id="modal-close" aria-label="Close">×</button>
        </div>
        <div class="modal-body">${bodyHtml}</div>
      </div>
    </div>`;

  $('#modal-close').addEventListener('click', closeModal);
  $('#overlay').addEventListener('click', (event) => {
    if (event.target.id === 'overlay') closeModal();
  });

  const onKey = (event) => {
    if (event.key === 'Escape') { closeModal(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);

  if (onMount) onMount(root);
}

function closeModal() {
  $('#modal-root').innerHTML = '';
}

function fmtDuration(value) {
  if (!value) return '—';

  if (value === '0s' || value === '0') return 'permanent';

  const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(value);
  if (!match) return value;

  const [, hours, minutes, seconds] = match;
  const parts = [];

  if (hours && Number(hours) > 0) parts.push(`${hours}h`);
  if (minutes && Number(minutes) > 0) parts.push(`${minutes}m`);
  if (parts.length === 0 && seconds) parts.push(`${Math.round(Number(seconds))}s`);

  return parts.join('') || value;
}

function badge(value, cls = '') {
  return `<span class="badge ${cls}">${esc(value)}</span>`;
}

function typeBadge(type) {
  return badge(type || 'ban', type === 'ban' ? 'ban' : type === 'captcha' ? 'captcha' : '');
}

function spinner() {
  return '<div class="empty"><span class="spinner"></span></div>';
}

function errorBox(message) {
  return `<div class="panel"><div class="panel-body"><p style="color:var(--danger);margin:0">${esc(message)}</p></div></div>`;
}

/* ---------------- session ---------------- */

function showLogin() {
  state.user = null;
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
}

function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#current-user').textContent = state.user || '';
  $('#version').textContent = `cswebui ${state.session?.version || ''}`;

  if (state.session && !state.session.features?.blocklist) {
    $('#nav-blocklist').classList.add('hidden');
  }
}

async function boot() {
  try {
    const session = await api('/api/session');
    state.user = session.user;
    state.csrf = session.csrf;
    state.session = session;
    showApp();
    window.addEventListener('hashchange', route);
    route();
  } catch {
    showLogin();
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#login-submit');
  button.disabled = true;
  $('#login-error').textContent = '';

  try {
    const result = await api('/api/login', {
      method: 'POST',
      body: { username: $('#username').value, password: $('#password').value },
    });
    state.user = result.user;
    state.csrf = result.csrf;
    const session = await api('/api/session');
    state.session = session;
    $('#password').value = '';
    showApp();
    window.addEventListener('hashchange', route);
    if (!location.hash) location.hash = '#/dashboard';
    route();
  } catch (error) {
    $('#login-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
  showLogin();
});

/* ---------------- router ---------------- */

const routes = {
  dashboard: renderDashboard,
  alerts: renderAlerts,
  decisions: renderDecisions,
  geo: renderGeo,
  infrastructure: renderInfrastructure,
  metrics: renderMetrics,
  allowlists: renderAllowlists,
  blocklist: renderBlocklist,
  config: renderConfig,
};

function route() {
  const name = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('?')[0];
  state.route = routes[name] ? name : 'dashboard';

  $$('#nav a').forEach((link) => {
    link.classList.toggle('active', link.dataset.route === state.route);
  });

  routes[state.route]().catch((error) => {
    $('#view').innerHTML = errorBox(error.message);
  });
}

/* ---------------- dashboard ---------------- */

async function renderDashboard() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div>
        <h2>Dashboard</h2>
        <p>Everything your Security Engine knows right now.</p>
      </div>
      <div class="toolbar">
        <span class="pill" id="lapi-pill"><span class="dot off"></span> Local API</span>
        <select id="range">
          ${['1h', '6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>last ${r}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="dashboard-body">${spinner()}</div>`;

  $('#range').addEventListener('change', (event) => {
    state.range = event.target.value;
    renderDashboard();
  });

  const data = await api(`/api/overview?since=${encodeURIComponent(state.range)}`);
  state.cache.overview = data;

  const metrics = data.metrics;
  const db = data.data_sources.db;

  $('#lapi-pill').innerHTML = data.lapi_reachable
    ? '<span class="dot"></span> Local API'
    : '<span class="dot off"></span> Local API unreachable';

  const ko = metrics && metrics.parser_hits > 0
    ? ((metrics.parser_ko / metrics.parser_hits) * 100).toFixed(1) + '% KO'
    : '';

  const cards = [
    statCard(`Alerts (${state.range})`, fmtNum(data.alerts.total), `${fmtNum(data.alerts.events)} events`),
    statCard('Unique sources', fmtNum(data.alerts.unique_sources), 'distinct source IPs'),
    statCard('Active decisions', fmtNum(data.decisions.total), `${fmtNum(data.decisions.simulated)} simulated`),
    statCard('Machines', `${data.machines.online}/${data.machines.total}`, 'online (< 5 min)'),
    statCard('Bouncers', `${data.bouncers.active}/${data.bouncers.total}`, 'active (< 5 min)'),
    data.blocklist
      ? statCard('Shared blocklist', fmtNum(data.blocklist.active_decisions), `${data.blocklist.machines} engine(s)`)
      : '',
    metrics
      ? statCard('Parsed lines', fmtNum(metrics.parser_hits), ko || 'parser hits')
      : '',
  ].filter(Boolean).join('');

  const metricsPanels = metrics
    ? `
      <div class="grid-2">
        <div class="panel">
          <div class="panel-head"><h3>Top parsers</h3><span class="hint">hits</span></div>
          <div class="panel-body">${renderBarList(metrics.top_nodes)}</div>
        </div>
        <div class="panel">
          <div class="panel-head"><h3>Top buckets</h3><span class="hint">active buckets</span></div>
          <div class="panel-body">${renderBarList(metrics.top_buckets)}</div>
        </div>
      </div>`
    : `<div class="panel" style="margin-bottom:14px"><div class="panel-body">
         <span class="hint">Prometheus metrics are not reachable. Enable <code>prometheus</code> in <code>config.yaml</code> and set <code>data.metrics_url</code> in the cswebui config.</span>
       </div></div>`;

  $('#dashboard-body').innerHTML = `
    <div class="cards">${cards}</div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Alerts over time</h3><span class="hint">${esc(state.range)}</span></div>
        <div class="panel-body">
          ${renderChart(data.alerts.timeline)}
          <div class="chart-legend"><span>${data.alerts.timeline.length ? fmtDate(data.alerts.timeline[0].time) : ''}</span><span>${data.alerts.timeline.length ? fmtDate(data.alerts.timeline[data.alerts.timeline.length - 1].time) : ''}</span></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top countries</h3><span class="hint">source geo</span></div>
        <div class="panel-body">${renderCountryList(data.alerts.by_country)}</div>
      </div>
    </div>

    <div class="panel map-panel" style="margin-bottom:18px">
      <div class="panel-head"><h3>Where the attacks come from</h3><span class="hint">GeoIP, last ${esc(state.range)}</span></div>
      <div class="panel-body">${renderWorldMap(data.alerts.geo, data.alerts.by_country)}</div>
    </div>

    <div class="grid-3">
      <div class="panel">
        <div class="panel-head"><h3>Top scenarios</h3></div>
        <div class="panel-body">${renderBarList(data.alerts.by_scenario)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Decisions by origin</h3></div>
        <div class="panel-body">${renderBarList(data.decisions.by_origin)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top AS</h3></div>
        <div class="panel-body">${renderBarList(data.alerts.by_as)}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Machines</h3><a href="#/infrastructure">details</a></div>
        ${renderMachinesTable(data.machines.items.slice(0, 6))}
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Bouncers</h3><a href="#/infrastructure">details</a></div>
        ${renderBouncersTable(data.bouncers.items.slice(0, 6))}
      </div>
    </div>

    ${metricsPanels}

    <div class="panel">
      <div class="panel-head"><h3>Recent alerts</h3><a href="#/alerts">show all</a></div>
      <div class="table-wrap">${renderAlertsTable(data.recent_alerts, true)}</div>
    </div>

    ${!db ? '<p class="hint" style="margin-top:12px">LAPI database not readable: machine/bouncer and geo aggregates are limited. Set <code>data.db_path</code>.</p>' : ''}`;

  $$('#dashboard-body tbody tr[data-alert-id]').forEach((row) => {
    row.addEventListener('click', () => showAlert(Number(row.dataset.alertId)));
  });
}

function statCard(label, value, hint) {
  return `<div class="card">
    <div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div>
    <div class="hint">${esc(hint)}</div>
  </div>`;
}

function fmtNum(value) {
  const number = Number(value || 0);
  return number.toLocaleString();
}

function flag(country) {
  if (!country || country.length !== 2) return '';
  return String.fromCodePoint(...[...country.toUpperCase()].map((ch) => 0x1F1E6 + ch.charCodeAt(0) - 65));
}

function renderCountryList(items) {
  if (!items || items.length === 0) {
    return '<div class="empty">No geo data (enable GeoIP in the engine)</div>';
  }

  return `<div class="bar-list">${items.map((item) => `
    <div class="bar-row">
      <span class="name"><span class="flag">${flag(item.name)}</span> ${esc(item.name)}</span>
      <span class="count">${fmtNum(item.count)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, (item.count / items[0].count) * 100)}%"></div></div>
    </div>`).join('')}</div>`;
}

function statusBadge(active, activeText = 'online', inactiveText = 'offline') {
  return active
    ? `<span class="badge ok">${esc(activeText)}</span>`
    : `<span class="badge">${esc(inactiveText)}</span>`;
}

function renderMachinesTable(machines) {
  if (!machines || machines.length === 0) {
    return '<div class="empty">No machines registered</div>';
  }

  const cutoff = Date.now() - 5 * 60 * 1000;

  return `<div class="table-wrap"><table>
    <thead><tr><th>Machine</th><th>Version</th><th>OS</th><th>Last seen</th><th>Status</th></tr></thead>
    <tbody>${machines.map((machine) => `
      <tr>
        <td class="mono" title="${esc(machine.machine_id)}">${esc(shortID(machine.machine_id))}</td>
        <td class="mono">${esc(machine.version || '—')}</td>
        <td>${esc([machine.osname, machine.osversion].filter(Boolean).join(' ') || '—')}</td>
        <td title="${esc(machine.last_heartbeat || '')}">${machine.last_heartbeat ? relTime(machine.last_heartbeat) : 'never'}</td>
        <td>${statusBadge(machine.last_heartbeat && new Date(machine.last_heartbeat).getTime() > cutoff, 'online', 'idle')}</td>
      </tr>`).join('')}</tbody></table></div>`;
}

function renderBouncersTable(bouncers) {
  if (!bouncers || bouncers.length === 0) {
    return '<div class="empty">No bouncers registered</div>';
  }

  return `<div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Type</th><th>Version</th><th>Last pull</th></tr></thead>
    <tbody>${bouncers.map((bouncer) => `
      <tr>
        <td class="mono">${esc(bouncer.name)}</td>
        <td>${esc(bouncer.type || '—')}</td>
        <td class="mono">${esc(bouncer.version || '—')}</td>
        <td>${bouncer.last_pull ? relTime(bouncer.last_pull) : 'never'}</td>
      </tr>`).join('')}</tbody></table></div>`;
}

function shortID(value) {
  if (!value) return '—';
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function renderChart(points) {
  if (!points || points.length === 0) return '<div class="empty">No data</div>';

  const width = 800;
  const height = 150;
  const pad = 6;
  const max = Math.max(1, ...points.map((p) => p.count));
  const step = points.length > 1 ? (width - pad * 2) / (points.length - 1) : 0;

  const coords = points.map((point, index) => {
    const x = pad + index * step;
    const y = height - pad - (point.count / max) * (height - pad * 2);
    return [x, y];
  });

  const line = coords.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const area = `${line} L${coords[coords.length - 1][0].toFixed(1)},${height - pad} L${coords[0][0].toFixed(1)},${height - pad} Z`;

  return `
    <svg class="chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Alerts over time">
      <defs>
        <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.35"/>
          <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.02"/>
        </linearGradient>
      </defs>
      <path d="${area}" fill="url(#chart-fill)"/>
      <path d="${line}" fill="none" stroke="#38bdf8" stroke-width="1.6" vector-effect="non-scaling-stroke"/>
    </svg>`;
}

function renderBarList(items) {
  if (!items || items.length === 0) return '<div class="empty">No data</div>';

  const max = Math.max(1, ...items.map((item) => item.count));

  return `<div class="bar-list">${items.map((item) => `
    <div class="bar-row">
      <span class="name" title="${esc(item.name)}">${esc(item.name)}</span>
      <span class="count">${item.count}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, (item.count / max) * 100)}%"></div></div>
    </div>`).join('')}</div>`;
}

function renderAlertsTable(alerts, compact = false) {
  if (!alerts || alerts.length === 0) {
    return '<div class="empty">No alerts</div>';
  }

  const rows = alerts.map((alert) => `
    <tr class="clickable" data-alert-id="${alert.id}">
      <td title="${esc(fmtDate(alert.created_at))}">${esc(relTime(alert.created_at))}</td>
      <td class="mono">${esc(alert.scenario)}</td>
      <td class="mono">${esc(alert.source_ip || alert.source_value)}</td>
      <td>${alert.source_country ? `<span class="flag">${flag(alert.source_country)}</span> ${esc(alert.source_country)}` : '—'}</td>
      ${compact ? '' : `<td>${esc(alert.source_scope)}</td>`}
      <td>${alert.decisions}</td>
      <td>${alert.events}</td>
      <td>${esc(alert.kind || '—')}</td>
    </tr>`).join('');

  return `<table>
    <thead><tr>
      <th>When</th><th>Scenario</th><th>Source</th><th>Country</th>${compact ? '' : '<th>Scope</th>'}<th>Decisions</th><th>Events</th><th>Kind</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

/* ---------------- alerts ---------------- */

async function renderAlerts() {
  const view = $('#view');
  view.innerHTML = `
    <div class="page-header">
      <div><h2>Alerts</h2><p>Everything your scenarios detected.</p></div>
    </div>
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-body">
        <form class="form-grid" id="alert-filters">
          <div class="field"><label for="f-scenario">Scenario</label><input id="f-scenario" type="text" placeholder="crowdsecurity/ssh-bf"></div>
          <div class="field"><label for="f-ip">Source IP</label><input id="f-ip" type="text" placeholder="1.2.3.4"></div>
          <div class="field"><label for="f-limit">Limit</label>
            <select id="f-limit"><option>50</option><option selected>100</option><option>250</option><option>500</option></select>
          </div>
          <div class="field" style="display:flex;align-items:flex-end"><button class="btn" type="submit">Filter</button></div>
        </form>
      </div>
    </div>
    <div class="panel"><div id="alerts-body">${spinner()}</div></div>`;

  const load = async () => {
    const params = new URLSearchParams();
    const scenario = $('#f-scenario').value.trim();
    const ip = $('#f-ip').value.trim();
    if (scenario) params.set('scenario', scenario);
    if (ip) params.set('ip', ip);
    params.set('limit', $('#f-limit').value);

    $('#alerts-body').innerHTML = spinner();

    const data = await api(`/api/alerts?${params}`);
    state.cache.alerts = data.alerts;

    $('#alerts-body').innerHTML = data.alerts.length
      ? `<div class="table-wrap">${renderAlertsTable(data.alerts)}</div>`
      : '<div class="empty">No alerts match the filter</div>';

    $$('#alerts-body tbody tr[data-alert-id]').forEach((row) => {
      row.addEventListener('click', () => showAlert(Number(row.dataset.alertId)));
    });
  };

  $('#alert-filters').addEventListener('submit', (event) => {
    event.preventDefault();
    load().catch((error) => toast(error.message, 'error'));
  });

  await load();
}

async function showAlert(id) {
  openModal('Alert', spinner());

  try {
    const alert = await api(`/api/alerts/${id}`);
    const decisions = (alert.decisions || []).map((decision) => `
      <tr>
        <td class="mono">${esc(decision.value)}</td>
        <td>${esc(decision.scope)}</td>
        <td>${typeBadge(decision.type)}</td>
        <td class="mono">${esc(decision.duration)}</td>
        <td class="mono">${esc(decision.origin)}</td>
      </tr>`).join('');

    const source = alert.source || {};
    const labels = (alert.labels || []).join(', ');

    openModal(`Alert #${alert.id}`, `
      <dl class="kv">
        <dt>Created</dt><dd>${esc(fmtDate(alert.created_at))}</dd>
        <dt>Scenario</dt><dd class="mono">${esc(alert.scenario)}</dd>
        <dt>Message</dt><dd>${esc(alert.message)}</dd>
        <dt>Source</dt><dd class="mono">${esc(source.ip || source.value)}${source.cn ? ` (${esc(source.cn)})` : ''}</dd>
        <dt>Country</dt><dd>${alert.source_country ? `<span class="flag">${flag(alert.source_country)}</span> ${esc(alert.source_country)}` : '—'}</dd>
        <dt>AS</dt><dd>${esc(alert.source_as_name || '—')}</dd>
        <dt>Coordinates</dt><dd class="mono">${alert.latitude || alert.longitude ? `${alert.latitude.toFixed(2)}, ${alert.longitude.toFixed(2)}` : '—'}</dd>
        <dt>Kind</dt><dd>${esc(alert.kind || '—')}</dd>
        <dt>Events</dt><dd>${esc(alert.events_count)}</dd>
        <dt>Labels</dt><dd>${esc(labels || '—')}</dd>
      </dl>
      ${decisions ? `<h4 style="margin:18px 0 8px">Decisions</h4><div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Scope</th><th>Type</th><th>Duration</th><th>Origin</th></tr></thead>
        <tbody>${decisions}</tbody></table></div>` : ''}
      <h4 style="margin:18px 0 8px">Events</h4>
      <pre class="json">${esc(JSON.stringify(alert.events || [], null, 2))}</pre>
      <div class="form-actions" style="justify-content:flex-end">
        <button class="btn secondary" id="alert-close">Close</button>
        <button class="btn danger" id="alert-delete">Delete alert</button>
      </div>`);

    $('#alert-close').addEventListener('click', closeModal);

    $('#alert-delete').addEventListener('click', async () => {
      if (!confirm(`Delete alert #${id}?`)) return;

      try {
        await api(`/api/alerts/${id}`, { method: 'DELETE' });
        closeModal();
        toast('Alert deleted', 'ok');
        route();
      } catch (error) {
        toast(error.message, 'error');
      }
    });
  } catch (error) {
    openModal('Alert', errorBox(error.message));
  }
}

/* ---------------- decisions ---------------- */

async function renderDecisions() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Decisions</h2><p>What your remediators enforce.</p></div>
      <div class="toolbar"><button class="btn" id="add-decision">Add decision</button></div>
    </div>
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-body">
        <form class="form-grid" id="decision-filters">
          <div class="field"><label for="d-ip">IP</label><input id="d-ip" type="text" placeholder="1.2.3.4"></div>
          <div class="field"><label for="d-range">Range</label><input id="d-range" type="text" placeholder="1.2.3.0/24"></div>
          <div class="field"><label for="d-value">Value</label><input id="d-value" type="text" placeholder="exact value"></div>
          <div class="field"><label for="d-type">Type</label>
            <select id="d-type"><option value="">any</option><option>ban</option><option>captcha</option></select>
          </div>
          <div class="field" style="display:flex;align-items:flex-end"><button class="btn" type="submit">Filter</button></div>
        </form>
      </div>
    </div>
    <div class="panel"><div id="decisions-body">${spinner()}</div></div>`;

  const load = async () => {
    const params = new URLSearchParams();
    [['ip', '#d-ip'], ['range', '#d-range'], ['value', '#d-value'], ['type', '#d-type']].forEach(([key, sel]) => {
      const value = $(sel).value.trim();
      if (value) params.set(key, value);
    });

    $('#decisions-body').innerHTML = spinner();

    const data = await api(`/api/decisions?${params}`);
    $('#decisions-body').innerHTML = renderDecisionsTable(data.decisions);

    $$('#decisions-body tr[data-decision-id]').forEach((row) => {
      const button = $('button[data-delete]', row);
      if (button) {
        button.addEventListener('click', async (event) => {
          event.stopPropagation();
          await deleteDecision(Number(row.dataset.decisionId), row.dataset.origin);
        });
      }
    });
  };

  $('#decision-filters').addEventListener('submit', (event) => {
    event.preventDefault();
    load().catch((error) => toast(error.message, 'error'));
  });

  $('#add-decision').addEventListener('click', () => showDecisionForm('local', load));

  await load();
}

function renderDecisionsTable(decisions) {
  if (!decisions || decisions.length === 0) return '<div class="empty">No decisions</div>';

  const rows = decisions.map((decision) => `
    <tr data-decision-id="${decision.id}" data-origin="${esc(decision.origin)}">
      <td class="mono">${esc(decision.value)}</td>
      <td>${esc(decision.scope)}</td>
      <td>${decision.country ? `<span class="flag">${flag(decision.country)}</span> ${esc(decision.country)}` : '—'}</td>
      <td class="mono" title="${esc(decision.as_name || '')}">${esc(decision.as_name || '—')}</td>
      <td>${typeBadge(decision.type)}${decision.simulated ? ' ' + badge('simulated', 'sim') : ''}</td>
      <td class="mono">${esc(fmtDuration(decision.duration))}</td>
      <td class="mono">${esc(decision.scenario)}</td>
      <td class="mono">${esc(decision.origin)}</td>
      <td><button class="btn danger" data-delete style="padding:4px 9px;font-size:12px">Unban</button></td>
    </tr>`).join('');

  return `<div class="table-wrap"><table>
    <thead><tr><th>Value</th><th>Scope</th><th>Country</th><th>AS</th><th>Type</th><th>Remaining</th><th>Scenario</th><th>Origin</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function deleteDecision(id, origin) {
  const message = origin === 'CAPI' || origin === 'lists'
    ? 'Delete this shared blocklist entry? It is re-added on the next pull unless it is removed on the blocklist server.'
    : 'Delete this decision?';

  if (!confirm(message)) return;

  try {
    await api(`/api/decisions/${id}`, { method: 'DELETE' });
    toast('Decision deleted', 'ok');
    route();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function showDecisionForm(target, onDone) {
  const title = target === 'local' ? 'Add decision' : 'Share decision via blocklist server';

  openModal(title, `
    <form id="decision-form">
      <div class="form-grid">
        <div class="field"><label for="n-value">IP or range</label><input id="n-value" type="text" placeholder="1.2.3.4" required></div>
        <div class="field"><label for="n-scope">Scope</label>
          <select id="n-scope"><option value="ip">ip</option><option value="range">range</option></select>
        </div>
        <div class="field"><label for="n-type">Type</label>
          <select id="n-type"><option value="ban">ban</option><option value="captcha">captcha</option></select>
        </div>
        <div class="field"><label for="n-duration">Duration</label><input id="n-duration" type="text" value="4h" required></div>
      </div>
      <div class="field" style="margin-top:12px"><label for="n-reason">Reason</label><input id="n-reason" type="text" placeholder="manual ban from cswebui"></div>
      <div class="form-actions" style="justify-content:flex-end">
        <button class="btn secondary" type="button" id="n-cancel">Cancel</button>
        <button class="btn" type="submit">Apply</button>
      </div>
    </form>`, () => {
    $('#n-cancel').addEventListener('click', closeModal);

    $('#decision-form').addEventListener('submit', async (event) => {
      event.preventDefault();

      const body = {
        value: $('#n-value').value.trim(),
        scope: $('#n-scope').value,
        type: $('#n-type').value,
        duration: $('#n-duration').value.trim() || '4h',
        reason: $('#n-reason').value.trim(),
      };

      const path = target === 'local' ? '/api/decisions' : '/api/blocklist/decisions';

      try {
        await api(path, { method: 'POST', body });
        closeModal();
        toast(target === 'local' ? 'Decision created' : 'Decision shared', 'ok');
        if (onDone) onDone();
      } catch (error) {
        toast(error.message, 'error');
      }
    });
  });
}

/* ---------------- allowlists ---------------- */

async function renderAllowlists() {
  const view = $('#view');

  view.innerHTML =
    `<div class="page-header"><div><h2>Allowlists</h2><p>Never ban these values.</p></div></div>
     <div class="panel"><div id="allowlists-body">${spinner()}</div></div>`;

  const data = await api('/api/allowlists');

  if (!data.allowlists.length) {
    $('#allowlists-body').innerHTML = '<div class="empty">No allowlists configured</div>';
    return;
  }

  $('#allowlists-body').innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Description</th><th>Items</th><th>Managed by console</th></tr></thead>
      <tbody>${data.allowlists.map((list) => `
        <tr class="clickable" data-allowlist="${esc(list.name)}">
          <td class="mono">${esc(list.name)}</td>
          <td class="wrap">${esc(list.description)}</td>
          <td>${(list.items || []).length}</td>
          <td>${list.console_managed ? 'yes' : 'no'}</td>
        </tr>`).join('')}</tbody>
    </table></div>`;

  $$('tr[data-allowlist]').forEach((row) => {
    row.addEventListener('click', () => showAllowlist(row.dataset.allowlist));
  });
}

async function showAllowlist(name) {
  openModal(`Allowlist ${name}`, spinner());

  try {
    const allowlist = await api(`/api/allowlists/${encodeURIComponent(name)}`);

    const items = (allowlist.items || []).map((item) => `
      <tr>
        <td class="mono">${esc(item.value)}</td>
        <td class="wrap">${esc(item.description)}</td>
        <td class="mono">${esc(item.expiration)}</td>
      </tr>`).join('');

    openModal(`Allowlist ${name}`, `
      <dl class="kv">
        <dt>Description</dt><dd>${esc(allowlist.description)}</dd>
        <dt>Created</dt><dd>${esc(fmtDate(allowlist.created_at))}</dd>
        <dt>Items</dt><dd>${(allowlist.items || []).length}</dd>
      </dl>
      ${items ? `<div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Description</th><th>Expiration</th></tr></thead>
        <tbody>${items}</tbody></table></div>` : '<div class="empty">No items</div>'}`);
  } catch (error) {
    openModal(`Allowlist ${name}`, errorBox(error.message));
  }
}

/* ---------------- shared blocklist ---------------- */

async function renderBlocklist() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Shared blocklist</h2><p>Decisions exchanged through your own blocklist server.</p></div>
      <div class="toolbar"><button class="btn" id="share-decision">Share decision</button></div>
    </div>
    <div id="blocklist-stats" class="cards"></div>
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Entries</h3><span class="hint" id="blocklist-count"></span></div>
      <div id="blocklist-decisions">${spinner()}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Registered engines</h3></div>
      <div id="blocklist-machines">${spinner()}</div>
    </div>`;

  $('#share-decision').addEventListener('click', () => showDecisionForm('blocklist', renderBlocklist));

  const [stats, decisions, machines] = await Promise.all([
    api('/api/blocklist/stats').catch((error) => ({ error: error.message })),
    api('/api/blocklist/decisions').catch((error) => ({ error: error.message })),
    api('/api/blocklist/machines').catch((error) => ({ error: error.message })),
  ]);

  if (stats.error) {
    $('#blocklist-stats').innerHTML = errorBox(stats.error);
  } else {
    $('#blocklist-stats').innerHTML = `
      <div class="card"><div class="label">Entries</div><div class="value">${stats.active_decisions}</div></div>
      <div class="card"><div class="label">Engines</div><div class="value">${stats.machines}</div></div>
      <div class="card"><div class="label">Revision</div><div class="value">${stats.revision}</div></div>`;
  }

  const entries = (decisions.decisions || []).map((decision) => `
    <tr>
      <td class="mono">${esc(decision.value)}</td>
      <td>${esc(decision.scope)}</td>
      <td class="mono">${esc(decision.scenario)}</td>
      <td class="mono">${esc(fmtDuration(decision.duration))}</td>
      <td class="mono">${esc(fmtDate(decision.until))}</td>
      <td>${esc(decision.source)}</td>
      <td><button class="btn danger" data-blocklist-id="${decision.id}" style="padding:4px 9px;font-size:12px">Remove</button></td>
    </tr>`).join('');

  $('#blocklist-decisions').innerHTML = entries
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Scope</th><th>Scenario</th><th>Duration</th><th>Until</th><th>Source</th><th></th></tr></thead>
        <tbody>${entries}</tbody></table></div>`
    : '<div class="empty">No shared decisions</div>';

  $('#blocklist-count').textContent = `${(decisions.decisions || []).length} shown`;

  $$('button[data-blocklist-id]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!confirm('Remove this entry from the shared blocklist?')) return;

      try {
        await api(`/api/blocklist/decisions/${button.dataset.blocklistId}`, { method: 'DELETE' });
        toast('Entry removed', 'ok');
        renderBlocklist();
      } catch (error) {
        toast(error.message, 'error');
      }
    });
  });

  const engineRows = (machines.machines || []).map((machine) => `
    <tr>
      <td class="mono">${esc(machine.machine_id)}</td>
      <td>${esc(machine.last_ip)}</td>
      <td>${esc(machine.last_seen && !machine.last_seen.startsWith('0001') ? relTime(machine.last_seen) : 'never')}</td>
    </tr>`).join('');

  $('#blocklist-machines').innerHTML = engineRows
    ? `<div class="table-wrap"><table><thead><tr><th>Machine</th><th>Last IP</th><th>Last seen</th></tr></thead><tbody>${engineRows}</tbody></table></div>`
    : '<div class="empty">No engine registered yet</div>';
}

/* ---------------- configuration ---------------- */

let currentConfig = { name: null, content: '' };

async function renderConfig() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Configuration</h2><p>Edit the engine configuration and reload it.</p></div>
      <div class="toolbar">
        <button class="btn secondary" id="config-reload">Reload engine</button>
      </div>
    </div>
    <div class="split">
      <div class="panel">
        <div class="panel-head"><h3>Files</h3></div>
        <div class="panel-body"><div class="file-list" id="config-files">${spinner()}</div></div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <h3 id="config-title">Select a file</h3>
          <span class="hint" id="config-meta"></span>
        </div>
        <div class="panel-body">
          <textarea class="editor" id="config-editor" spellcheck="false" placeholder="Choose a file on the left"></textarea>
          <div class="editor-actions">
            <span class="hint" id="config-status"></span>
            <button class="btn" id="config-save" disabled>Save</button>
          </div>
        </div>
      </div>
    </div>`;

  const data = await api('/api/config');

  $('#config-files').innerHTML = data.files.map((file) => `
    <button data-file="${esc(file.name)}" class="${file.name === currentConfig.name ? 'active' : ''}">
      <span>${esc(file.name)}</span>
      ${file.exists ? '' : '<span class="missing">missing</span>'}
    </button>`).join('');

  $$('#config-files button').forEach((button) => {
    button.addEventListener('click', () => {
      loadConfigFile(button.dataset.file).catch((error) => toast(error.message, 'error'));
    });
  });

  $('#config-save').addEventListener('click', saveConfigFile);

  $('#config-reload').addEventListener('click', async () => {
    try {
      const result = await api('/api/reload', { method: 'POST' });
      toast(result.output || result.message, 'ok');
    } catch (error) {
      toast(error.message, 'error');
    }
  });

  if (!currentConfig.name && data.files.length > 0) {
    const first = data.files.find((file) => file.exists) || data.files[0];
    await loadConfigFile(first.name);
  } else if (currentConfig.name) {
    await loadConfigFile(currentConfig.name);
  }
}

async function loadConfigFile(name) {
  if (currentConfig.name !== name && isDirty() && !confirm('Discard unsaved changes?')) return;

  const file = await api(`/api/config/${encodeURIComponent(name).replace(/%2F/g, '/')}`);

  currentConfig = { name, content: file.content || '' };

  $('#config-editor').value = currentConfig.content;
  $('#config-title').textContent = name;
  $('#config-meta').textContent = `${file.size} bytes · ${fmtDate(file.modified)}`;
  $('#config-save').disabled = true;
  $('#config-status').textContent = '';

  $$('#config-files button').forEach((button) => {
    button.classList.toggle('active', button.dataset.file === name);
  });

  $('#config-editor').addEventListener('input', () => {
    $('#config-save').disabled = !isDirty();
    $('#config-status').textContent = isDirty() ? 'unsaved changes' : '';
  }, { once: false });
}

function isDirty() {
  const editor = $('#config-editor');
  return editor ? editor.value !== currentConfig.content : false;
}

async function saveConfigFile() {
  if (!currentConfig.name) return;

  const button = $('#config-save');
  button.disabled = true;

  try {
    await api(`/api/config/${encodeURIComponent(currentConfig.name).replace(/%2F/g, '/')}`, {
      method: 'PUT',
      body: { content: $('#config-editor').value },
    });
    currentConfig.content = $('#config-editor').value;
    $('#config-status').textContent = 'saved';
    toast('Configuration saved. Reload the engine to apply it.', 'ok');
  } catch (error) {
    toast(error.message, 'error');
    button.disabled = false;
  }
}



/* ---------------- geo map ---------------- */

function projectGeo(lat, lon) {
  return [lon + 180, 90 - lat];
}

function renderWorldMap(geoPoints, byCountry, options = {}) {
  const points = [];

  if (geoPoints && geoPoints.length > 0) {
    geoPoints.forEach((point) => points.push(point));
  } else if (byCountry && byCountry.length > 0 && typeof COUNTRY_CENTROIDS !== 'undefined') {
    byCountry.forEach((country) => {
      const centroid = COUNTRY_CENTROIDS[country.name];
      if (centroid) {
        points.push({ lat: centroid[0], lon: centroid[1], count: country.count, country: country.name });
      }
    });
  }

  if (points.length === 0) {
    return '<div class="empty">No GeoIP data yet. Enable the geoip-enrich parser and provide GeoLite2 data.</div>';
  }

  const max = Math.max(1, ...points.map((point) => point.count));
  const bubbles = points.map((point) => {
    const [x, y] = projectGeo(point.lat, point.lon);
    const radius = 1.6 + 6 * Math.sqrt(point.count / max);
    const label = point.country ? `${point.country}: ${point.count} alert(s)` : `${point.count} alert(s)`;
    return `<circle class="map-bubble" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${radius.toFixed(1)}"><title>${esc(label)}</title></circle>`;
  }).join('');

  const graticule = [];

  for (let lon = -150; lon < 180; lon += 30) {
    const x = lon + 180;
    graticule.push(`<line x1="${x}" y1="0" x2="${x}" y2="180"/>`);
  }

  for (let lat = -60; lat <= 60; lat += 30) {
    const y = 90 - lat;
    graticule.push(`<line x1="0" y1="${y}" x2="360" y2="${y}"/>`);
  }

  return `
    <svg class="worldmap" viewBox="0 0 360 180" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Origin of the detected attacks">
      <g class="map-graticule">${graticule.join('')}</g>
      <path class="map-land" d="${WORLD_MAP_PATH}"/>
      <g>${bubbles}</g>
    </svg>
    <div class="map-legend">
      <span><span class="dot" style="width:6px;height:6px"></span>few</span>
      <span><span class="dot" style="width:11px;height:11px"></span>many</span>
      <span>${points.length} location(s), bubble size = alerts</span>
    </div>`;
}

async function renderGeo() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Geo</h2><p>Where the detected sources are located.</p></div>
      <div class="toolbar">
        <select id="geo-range">
          ${['6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>last ${r}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="geo-body">${spinner()}</div>`;

  $('#geo-range').addEventListener('change', (event) => {
    state.range = event.target.value;
    renderGeo();
  });

  const data = await api(`/api/overview?since=${encodeURIComponent(state.range)}`);
  const alerts = data.alerts;
  const countries = alerts.by_country || [];
  const topCountry = countries[0] ? `${flag(countries[0].name)} ${countries[0].name}` : '—';

  $('#geo-body').innerHTML = `
    <div class="cards">
      ${statCard(`Alerts (${state.range})`, fmtNum(alerts.total), `${fmtNum(alerts.events)} events`)}
      ${statCard('Countries', fmtNum(countries.length), 'distinct source countries')}
      ${statCard('Top country', topCountry, countries[0] ? `${fmtNum(countries[0].count)} alert(s)` : 'no geo data')}
      ${statCard('Locations', fmtNum((alerts.geo || []).length), 'map clusters')}
    </div>

    <div class="panel map-panel map-large" style="margin-bottom:14px">
      <div class="panel-head"><h3>Origin map</h3><span class="hint">GeoLite2 via the geoip-enrich parser</span></div>
      <div class="panel-body">${renderWorldMap(alerts.geo, countries)}</div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Top countries</h3></div>
        <div class="panel-body">${renderCountryList(countries)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top networks (AS)</h3></div>
        <div class="panel-body">${renderBarList(alerts.by_as)}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Recent alerts with geo</h3><a href="#/alerts">all alerts</a></div>
      <div class="table-wrap">${renderAlertsTable(data.recent_alerts, false)}</div>
    </div>`;
}

/* ---------------- infrastructure ---------------- */

async function renderInfrastructure() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Infrastructure</h2><p>Engines, bouncers and how they talk to the API.</p></div>
    </div>
    <div id="infra-body">${spinner()}</div>`;

  const infra = await api('/api/infra');
  let metrics = null;

  try {
    metrics = (await api('/api/metrics')).summary;
  } catch {
    metrics = null;
  }

  const cutoff = Date.now() - 5 * 60 * 1000;
  const machinesOnline = infra.machines.filter((m) => m.last_heartbeat && new Date(m.last_heartbeat).getTime() > cutoff).length;
  const bouncersActive = infra.bouncers.filter((b) => b.last_pull && new Date(b.last_pull).getTime() > cutoff).length;

  const machineRows = infra.machines.map((machine) => `
    <tr>
      <td class="mono" style="max-width:340px;overflow:hidden;text-overflow:ellipsis" title="${esc(machine.machine_id)}">${esc(machine.machine_id)}</td>
      <td class="mono">${esc(machine.version || '—')}</td>
      <td>${esc([machine.osname, machine.osversion].filter(Boolean).join(' ') || '—')}</td>
      <td title="${esc(machine.scenarios || '')}">${(machine.scenarios || '').split(',').filter(Boolean).length}</td>
      <td>${machine.last_heartbeat ? relTime(machine.last_heartbeat) : 'never'}</td>
      <td class="mono">${esc(machine.ip_address || '—')}</td>
      <td>${machine.validated ? '<span class="badge ok">valid</span>' : '<span class="badge">pending</span>'}</td>
    </tr>`).join('');

  const bouncerRows = infra.bouncers.map((bouncer) => `
    <tr>
      <td class="mono">${esc(bouncer.name)}</td>
      <td>${esc(bouncer.type || '—')}</td>
      <td class="mono">${esc(bouncer.version || '—')}</td>
      <td>${esc([bouncer.osname, bouncer.osversion].filter(Boolean).join(' ') || '—')}</td>
      <td class="mono">${esc(bouncer.ip_address || '—')}</td>
      <td>${bouncer.last_pull ? relTime(bouncer.last_pull) : 'never'}</td>
      <td>${bouncer.revoked ? '<span class="badge ban">revoked</span>' : statusBadge(bouncer.last_pull && new Date(bouncer.last_pull).getTime() > cutoff, 'active', 'idle')}</td>
    </tr>`).join('');

  const features = metrics && metrics.features && metrics.features.length
    ? metrics.features.map((feature) => `<span class="badge">${esc(feature)}</span>`).join(' ')
    : '<span class="hint">no metric data</span>';

  $('#infra-body').innerHTML = `
    <div class="cards">
      ${statCard('Machines', `${machinesOnline}/${infra.machines.length}`, 'online (< 5 min)')}
      ${statCard('Bouncers', `${bouncersActive}/${infra.bouncers.length}`, 'active (< 5 min)')}
      ${metrics ? statCard('LAPI requests', fmtNum(metrics.lapi_requests), 'total since start') : ''}
      ${metrics ? statCard('Bouncer requests', fmtNum(metrics.bouncer_requests), 'total since start') : ''}
    </div>

    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Machines</h3><span class="hint">${infra.db ? 'from the LAPI database' : 'database not readable'}</span></div>
      ${infra.machines.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Machine</th><th>Version</th><th>OS</th><th>Scenarios</th><th>Last seen</th><th>IP</th><th>State</th></tr></thead>
        <tbody>${machineRows}</tbody></table></div>` : '<div class="empty">No machines registered</div>'}
    </div>

    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Bouncers</h3></div>
      ${infra.bouncers.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Type</th><th>Version</th><th>OS</th><th>IP</th><th>Last pull</th><th>State</th></tr></thead>
        <tbody>${bouncerRows}</tbody></table></div>` : '<div class="empty">No bouncers registered</div>'}
    </div>

    <div class="grid-3">
      <div class="panel">
        <div class="panel-head"><h3>LAPI routes</h3></div>
        <div class="panel-body">${renderBarList(metrics ? metrics.top_routes : [])}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Chattiest machines</h3></div>
        <div class="panel-body">${renderBarList(metrics ? metrics.top_machines : [])}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Chattiest bouncers</h3></div>
        <div class="panel-body">${renderBarList(metrics ? metrics.top_bouncers : [])}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Enabled features</h3></div>
      <div class="panel-body">${features}</div>
    </div>`;
}

/* ---------------- metrics ---------------- */

async function renderMetrics() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Metrics</h2><p>Prometheus counters exported by the engine.</p></div>
      <div class="toolbar"><span class="hint" id="metrics-fetched"></span></div>
    </div>
    <div id="metrics-body">${spinner()}</div>`;

  let data;

  try {
    data = await api('/api/metrics');
  } catch (error) {
    $('#metrics-body').innerHTML = errorBox(`Could not scrape metrics: ${error.message}. Enable prometheus in config.yaml and check data.metrics_url.`);
    return;
  }

  const m = data.summary;
  $('#metrics-fetched').textContent = `${data.samples} series · ${relTime(data.fetched_at)}`;

  const koRate = m.parser_hits > 0 ? ((m.parser_ko / m.parser_hits) * 100).toFixed(1) : '0.0';
  const avgParse = m.avg_parse_ms != null ? `${m.avg_parse_ms.toFixed(2)} ms` : '—';
  const lastPull = m.capi_last_pull ? relTime(m.capi_last_pull) : 'never';

  $('#metrics-body').innerHTML = `
    <div class="cards">
      ${statCard('Parser hits', fmtNum(m.parser_hits), 'lines entering parsing')}
      ${statCard('Parsed OK', fmtNum(m.parser_ok), 'successfully parsed')}
      ${statCard('Parse errors', fmtNum(m.parser_ko), `${koRate}% of hits`)}
      ${statCard('Avg parse time', avgParse, 'per line')}
      ${statCard('Active buckets', fmtNum(m.buckets_current), `${fmtNum(m.bucket_overflows)} overflows total`)}
      ${statCard('Acquisition lines', fmtNum(m.acquisition_lines), 'read from sources')}
      ${statCard('LAPI requests', fmtNum(m.lapi_requests), 'all routes')}
      ${statCard('CAPI last pull', lastPull, `${fmtNum(m.capi_errors)} errors`)}
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Top parsers by hits</h3></div>
        <div class="panel-body">${renderBarList(m.top_nodes)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top parsers by errors</h3></div>
        <div class="panel-body">${renderBarList(m.top_nodes_ko)}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Active buckets</h3></div>
        <div class="panel-body">${renderBarList(m.top_buckets)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Bucket overflows</h3></div>
        <div class="panel-body">${renderBarList(m.top_overflows)}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Acquisition sources</h3><span class="hint">lines read</span></div>
        <div class="panel-body">${renderBarList(m.top_sources)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Pipeline health</h3></div>
        <div class="panel-body">
          <dl class="kv" style="margin:0">
            <dt>Postoverflow queue</dt><dd>${fmtNum(m.postoverflow_queue)} waiting</dd>
            <dt>Postoverflow dropped</dt><dd>${fmtNum(m.postoverflow_dropped)}</dd>
            <dt>Bucket pours</dt><dd>${fmtNum(m.bucket_poured)}</dd>
            <dt>CAPI errors</dt><dd>${fmtNum(m.capi_errors)}</dd>
            <dt>Version</dt><dd class="mono">${esc(m.version || '—')}</dd>
          </dl>
        </div>
      </div>
    </div>`;
}

boot();
