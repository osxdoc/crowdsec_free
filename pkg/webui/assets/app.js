/* CrowdSec self-hosted console – no build step, no external dependencies. */

const state = {
  user: null,
  csrf: null,
  session: null,
  route: 'dashboard',
  range: '24h',
  cache: {},
  hash: '',
  filters: { alerts: {}, decisions: {}, blocklist: {} },
};

let viewController = new AbortController();

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
  const init = { credentials: 'same-origin', headers: { Accept: 'application/json' },
    signal: !options.method || options.method === 'GET' ? viewController.signal : undefined, ...options };

  if (init.body !== undefined && typeof init.body !== 'string') {
    init.body = JSON.stringify(init.body);
    init.headers['Content-Type'] = 'application/json';
  }

  if (init.method && init.method !== 'GET') {
    init.headers['X-CSRF-Token'] = state.csrf || '';
  }

  const response = await fetch(path, init);
  const text = await response.text();
  init.signal?.throwIfAborted();
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

function toast(message, kind = '', action = null) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  const modal = $('#modal-root dialog[open] .modal-body');
  if (modal) el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  const region = modal || $('#toasts');
  const existing = $$('.toast', region);
  if (existing.length >= 3) existing[0].remove();
  const dismiss = document.createElement('button');
  dismiss.className = 'close';
  dismiss.type = 'button';
  dismiss.setAttribute('aria-label', 'Dismiss notification');
  dismiss.textContent = '×';
  el.appendChild(dismiss);
  region.appendChild(el);

  const remove = () => {
    if (el.isConnected === false) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (!el.animate || reduce) { el.remove(); return; }
    el.animate(
      [{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'translateY(6px) scale(0.98)' }],
      { duration: 160, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
    ).onfinish = () => el.remove();
  };
  if (action) {
    el.classList.add('has-action');
    const button = document.createElement('button');
    button.className = 'toast-action';
    button.type = 'button';
    button.textContent = action.label;
    button.addEventListener('click', () => { action.onClick(); remove(); });
    el.appendChild(button);
  }

  let timer = setTimeout(remove, action ? 10000 : 5000);
  dismiss.addEventListener('click', remove);
  // Keep a toast on screen while it is being read or dismissed.
  el.addEventListener('mouseenter', () => { clearTimeout(timer); });
  el.addEventListener('mouseleave', () => { timer = setTimeout(remove, 2500); });
}

let modalReturnFocus = null;

function openModal(title, bodyHtml, onMount) {
  const root = $('#modal-root');
  if (!$('dialog', root)) modalReturnFocus = document.activeElement;
  $('dialog', root)?.close();
  root.innerHTML = `
      <dialog class="modal" aria-labelledby="modal-title">
        <div class="modal-head">
          <h3 id="modal-title">${esc(title)}</h3>
          <button class="close" id="modal-close" aria-label="Close">×</button>
        </div>
        <div class="modal-body">${bodyHtml}</div>
      </dialog>`;

  $('#modal-close').addEventListener('click', closeModal);
  const dialog = $('dialog', root);
  dialog.addEventListener('click', (event) => {
    const rect = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right ||
        event.clientY < rect.top || event.clientY > rect.bottom)) closeModal();
  });
  dialog.addEventListener('cancel', (event) => { event.preventDefault(); closeModal(); });

  if (onMount) onMount(root);
  dialog.showModal();
  document.body?.classList.add('modal-open');
  enhanceTables(root);
}

function closeModal() {
  $('#modal-root dialog')?.close();
  $('#modal-root').innerHTML = '';
  document.body?.classList.remove('modal-open');
  if (modalReturnFocus?.isConnected) modalReturnFocus.focus();
  modalReturnFocus = null;
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
  return '<div class="empty" role="status"><span class="spinner" aria-hidden="true"></span><span class="sr-only">Loading…</span></div>';
}

function errorBox(message, retry = false) {
  return `<div class="panel"><div class="panel-body"><p role="alert" style="color:var(--danger);margin:0">${esc(message)}</p>${retry ? '<button class="btn secondary" data-retry style="margin-top:12px">Try again</button>' : ''}</div></div>`;
}

/* ---------------- session ---------------- */

function showLogin() {
  clearTimeout(refreshTimer);
  clearTimeout(freshnessTimer);
  closeModal();
  state.user = null;
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#username').focus();
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
    if (!location.hash) history.replaceState(null, '', '#/dashboard');
    route();
  } catch (error) {
    $('#login-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#logout').addEventListener('click', async () => {
  if (!discardConfigChanges()) return;
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
  viewController.abort();
  viewController = new AbortController();
  $('#view').innerHTML = '';
  state.filters = { alerts: {}, decisions: {}, blocklist: {} };
  showLogin();
});

/* ---------------- router ---------------- */

const routes = {
  dashboard: renderDashboard,
  alerts: renderAlerts,
  decisions: renderDecisions,
  inspect: renderInspect,
  geo: renderGeo,
  infrastructure: renderInfrastructure,
  metrics: renderMetrics,
  allowlists: renderAllowlists,
  blocklist: renderBlocklist,
  hub: renderHub,
  config: renderConfig,
};

function discardConfigChanges() {
  return !isDirty() || confirm('Discard unsaved changes?');
}

document.addEventListener('click', handleConsoleAction);

window.addEventListener('beforeunload', (event) => {
  if (isDirty()) { event.preventDefault(); event.returnValue = ''; }
});
window.addEventListener('hashchange', () => { if (state.user) route(); });

function setNavOpen(open) {
  $('.sidebar').classList.toggle('nav-open', open);
  $('#nav-toggle').setAttribute('aria-expanded', String(open));
  const scrim = $('#nav-scrim');
  if (scrim) {
    scrim.hidden = !open;
    scrim.classList.toggle('visible', open);
  }
  document.body?.classList.toggle('nav-locked', open);
}

async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    toast('Copied to clipboard', 'ok');
  } catch {
    toast('Could not copy', 'error');
  }
}

$('#nav-toggle').addEventListener('click', () => setNavOpen($('#nav-toggle').getAttribute('aria-expanded') !== 'true'));
$('.sidebar').addEventListener('keydown', (event) => {
  if (event.key === 'Escape') { setNavOpen(false); $('#nav-toggle').focus(); }
});
$('.skip-link').addEventListener('click', (event) => { event.preventDefault(); $('#view').focus(); });
$('#nav-scrim')?.addEventListener('click', () => setNavOpen(false));

$('#view').addEventListener('click', (event) => {
  if (event.target.closest('[data-retry]')) { route(); return; }
  const copy = event.target.closest('[data-copy]');
  if (copy) { copyText(copy.dataset.copy); return; }
  const alert = event.target.closest('[data-alert-id]');
  if (alert) showAlert(Number(alert.dataset.alertId));
  const allowlist = event.target.closest('[data-allowlist]');
  if (allowlist) showAllowlist(allowlist.dataset.allowlist);
});

function route() {
  if (!discardConfigChanges()) {
    history.replaceState(null, '', state.hash || '#/config');
    return;
  }
  clearTimeout(refreshTimer);
  clearTimeout(freshnessTimer);
  viewController.abort();
  viewController = new AbortController();
  const signal = viewController.signal;
  closeModal();
  state.hash = location.hash || '#/dashboard';
  const name = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('?')[0];
  state.route = routes[name] ? name : 'dashboard';
  state.cache.updatedAt = null;
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  if (filterFields[state.route] && params.size) {
    state.filters[state.route] = Object.fromEntries([...params].filter(([key]) => filterFields[state.route].includes(key)));
  }
  const navWasOpen = $('#nav-toggle').getAttribute('aria-expanded') === 'true';
  setNavOpen(false);
  if (navWasOpen) $('#nav-toggle').focus();

  $$('#nav a').forEach((link) => {
    link.classList.toggle('active', link.dataset.route === state.route);
    if (link.dataset.route === state.route) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  document.title = `${$('#nav a.active')?.textContent || 'Dashboard'} · CrowdSec`;

  routes[state.route]().then(() => {
    if (signal.aborted) return;
    enhanceTables();
    mountRefresh(state.cache.updatedAt || new Date().toISOString());
  }).catch((error) => {
    if (signal.aborted) return;
    $('#view').innerHTML = errorBox(error.message, true);
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
        <select id="range" aria-label="Time range">
          ${['1h', '6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>last ${r}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="dashboard-body">${spinner()}</div>`;

  $('#range').addEventListener('change', (event) => {
    state.range = event.target.value;
    route();
  });

  const data = await api(`/api/overview?since=${encodeURIComponent(state.range)}`);
  state.cache.overview = data;
  state.cache.updatedAt = data.generated_at;

  const metrics = data.metrics;
  const db = data.data_sources.db;

  $('#lapi-pill').innerHTML = data.lapi_reachable
    ? '<span class="dot"></span> Local API'
    : '<span class="dot off"></span> Local API unreachable';

  const ko = metrics && metrics.parser_hits > 0 && (!metrics.present || metrics.present.cs_parser_hits_ko_total)
    ? ((metrics.parser_ko / metrics.parser_hits) * 100).toFixed(1) + '% unparsed'
    : '';

  const alertsOk = data.data_sources.alerts !== false;
  const decisionsOk = data.data_sources.decisions !== false;
  const previous = data.previous_alerts;
  const delta = (current, before) => {
    if (!before) return current > 0 ? '<span class="delta up">new</span>' : '';
    const change = ((current - before) / before) * 100;
    if (!Number.isFinite(change)) return '';
    if (Math.abs(change) < 1) return '<span class="delta flat">±0%</span>';
    const up = change > 0;
    return `<span class="delta ${up ? 'up' : 'down'}">${up ? '▲' : '▼'} ${Math.abs(change).toFixed(0)}%</span>`;
  };

  const situation = `
    <div class="situation">
      <div class="card primary">
        <div class="label">Alerts · last ${esc(state.range)}</div>
        <div class="value">${alertsOk ? fmtNum(data.alerts.total) : '—'}</div>
        <div class="hint">${alertsOk ? `${fmtNum(data.alerts.events)} events ${delta(data.alerts.total, previous?.Total)}` : 'unavailable'}</div>
      </div>
      <div class="card primary">
        <div class="label">Unique sources</div>
        <div class="value">${alertsOk ? fmtNum(data.alerts.unique_sources) : '—'}</div>
        <div class="hint">${alertsOk ? `distinct IPs ${delta(data.alerts.unique_sources, previous?.UniqueSources)}` : 'unavailable'}</div>
      </div>
      <div class="card primary">
        <div class="label">Active decisions</div>
        <div class="value">${decisionsOk ? fmtNum(data.decisions.total) : '—'}</div>
        <div class="hint">${decisionsOk ? `${fmtNum(data.decisions.simulated)} simulated` : 'unavailable'}</div>
      </div>
    </div>`;

  const strip = `
    <div class="stat-strip">
      ${statPill('Machines', data.data_sources.machines === false ? '—' : `${data.machines.online}/${data.machines.total}`, data.machines.online > 0 ? 'ok' : 'off')}
      ${statPill('Bouncers', data.data_sources.bouncers === false ? '—' : `${data.bouncers.active}/${data.bouncers.total}`, data.bouncers.active > 0 ? 'ok' : 'off')}
      ${data.blocklist ? statPill('Blocklist', fmtNum(data.blocklist.active_decisions), 'ok') : ''}
      ${metrics ? statPill('Parser input', metricNumber(metrics, 'parser_hits', 'cs_parser_hits_total'), ko ? 'warn' : 'ok') : ''}
    </div>`;

  const onboarding = renderOnboarding(data);

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
    ${onboarding}
    ${renderHealth(data)}
    ${situation}
    ${strip}

    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h3>Alerts over time</h3><span class="hint">${esc(state.range)}</span></div>
      <div class="panel-body">
        ${alertsOk ? renderChart(data.alerts.timeline) : '<div class="empty">Alert data unavailable</div>'}
        <div class="chart-legend"><span>${data.alerts.timeline.length ? fmtDate(data.alerts.timeline[0].time) : ''}</span><span>${data.alerts.timeline.length ? fmtDate(data.alerts.timeline[data.alerts.timeline.length - 1].time) : ''}</span></div>
      </div>
    </div>

    <div class="panel map-panel" style="margin-bottom:18px">
      <div class="panel-head"><h3>Where the attacks come from</h3><span class="hint">GeoIP, last ${esc(state.range)}</span></div>
      <div class="panel-body map-split">
        <div class="map-canvas">${alertsOk ? renderWorldMap(data.alerts.geo, data.alerts.by_country) : '<div class="empty">Alert data unavailable</div>'}</div>
        <div class="map-side">${alertsOk ? renderCountryList(data.alerts.by_country) : ''}</div>
      </div>
    </div>

    <div class="grid-3">
      <div class="panel">
        <div class="panel-head"><h3>Top scenarios</h3></div>
        <div class="panel-body">${renderBarList(data.alerts.by_scenario, ['alerts', 'scenario'])}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Decisions by origin</h3></div>
        <div class="panel-body">${renderBarList(data.decisions.by_origin, ['decisions', 'origin'])}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top AS</h3></div>
        <div class="panel-body">${renderBarList(data.alerts.by_as)}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Machines</h3><a href="#/infrastructure">details</a></div>
        ${data.data_sources.machines === false ? '<div class="empty">Machine data unavailable</div>' : renderMachinesTable(data.machines.items.slice(0, 6))}
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Bouncers</h3><a href="#/infrastructure">details</a></div>
        ${data.data_sources.bouncers === false ? '<div class="empty">Bouncer data unavailable</div>' : renderBouncersTable(data.bouncers.items.slice(0, 6))}
      </div>
    </div>

    ${metricsPanels}

    <div class="panel">
      <div class="panel-head"><h3>Recent alerts</h3><a href="#/alerts">show all</a></div>
      <div class="table-wrap">${data.data_sources.recent_alerts === false ? '<div class="empty">Recent alerts unavailable</div>' : renderAlertsTable(data.recent_alerts, true)}</div>
    </div>

    ${!db ? '<p class="hint" style="margin-top:12px">LAPI database not readable: machine/bouncer and geo aggregates are limited. Set <code>data.db_path</code>.</p>' : ''}`;

  $('#onboarding-dismiss')?.addEventListener('click', () => {
    localStorage.setItem('cswebui.onboarding.dismissed', '1');
    $('#onboarding')?.remove();
  });


}


// Filters stay collapsed until something is set: they were the largest block on
// every list page, and most visits never touch them.
const filterNoise = { alerts: ['limit', 'include_capi'], decisions: ['limit'], blocklist: ['limit'] };

function activeFilterCount(kind) {
  const noise = filterNoise[kind] || [];
  return Object.keys(state.filters[kind] || {}).filter((key) => !noise.includes(key)).length;
}

function filterPanelOpen(kind) {
  const count = activeFilterCount(kind);
  return `<details class="panel filters" data-filters="${kind}"${count ? ' open' : ''}>
    <summary><span>Filters</span><span class="filter-count">${count ? `${count} active` : ''}</span></summary>
    <div class="panel-body">`;
}

function filterPanelClose() {
  return '</div></details>';
}

function updateFilterBadge(kind) {
  const box = $(`[data-filters="${kind}"]`);
  if (!box) return;
  const count = activeFilterCount(kind);
  const badge = $('.filter-count', box);
  if (badge) badge.textContent = count ? `${count} active` : '';
  box.toggleAttribute('open', count > 0);
}

function statPill(label, value, state = '') {
  return `<span class="stat-pill"><span class="dot ${state}"></span><span class="stat-label">${esc(label)}</span><strong>${esc(value)}</strong></span>`;
}

// The checklist disappears once every step is done, or when dismissed.
function renderOnboarding(data) {
  const dismissed = localStorage.getItem('cswebui.onboarding.dismissed') === '1';
  const steps = [
    { done: data.lapi_reachable, text: 'Engine reachable', hint: 'Local API answers' },
    { done: (data.machines?.total || 0) > 0, text: 'Engine registered', hint: 'cscli machines add' },
    { done: (data.bouncers?.total || 0) > 0, text: 'Bouncer connected', hint: 'cscli bouncers add <name>' },
    { done: (data.alerts?.by_country?.length || 0) > 0, text: 'GeoIP enrichment active', hint: 'install crowdsecurity/geoip-enrich' },
  ];
  const open = steps.filter((step) => !step.done);
  if (dismissed || open.length === 0) return '';
  return `<div class="panel onboarding" id="onboarding">
    <div class="panel-head"><h3>Finish the setup</h3><button class="close" type="button" id="onboarding-dismiss" aria-label="Dismiss checklist">×</button></div>
    <div class="panel-body">
      <ul>${steps.map((step) => `<li class="${step.done ? 'done' : ''}"><span class="tick">${step.done ? '✓' : '○'}</span><span>${esc(step.text)}</span>${step.done ? '' : `<code>${esc(step.hint)}</code>`}</li>`).join('')}</ul>
    </div>
  </div>`;
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
    return `<div class="empty"><p>No machines registered yet.</p>
      <button class="btn secondary" type="button" data-copy="cscli machines add my-engine --auto">Copy: cscli machines add …</button></div>`;
  }

  const cutoff = Date.now() - 5 * 60 * 1000;

  return `<div class="table-wrap"><table>
    <thead><tr><th>Machine</th><th>Version</th><th>OS</th><th>Last seen</th><th>Status</th></tr></thead>
    <tbody>${machines.map((machine) => `
      <tr>
        <td class="mono" title="${esc(machine.machine_id)}">${esc(shortID(machine.machine_id))}</td>
        <td class="mono">${esc(machine.version || '—')}</td>
        <td>${esc([machine.osname, machine.osversion].filter(Boolean).join(' ') || '—')}</td>
        <td data-sort="${sortDate(machine.last_heartbeat)}" title="${esc(machine.last_heartbeat || '')}">${machine.last_heartbeat ? relTime(machine.last_heartbeat) : 'never'}</td>
        <td>${statusBadge(machine.last_heartbeat && new Date(machine.last_heartbeat).getTime() > cutoff, 'online', 'idle')}</td>
      </tr>`).join('')}</tbody></table></div>`;
}

function renderBouncersTable(bouncers) {
  if (!bouncers || bouncers.length === 0) {
    return `<div class="empty"><p>No bouncer connected yet.</p>
      <button class="btn secondary" type="button" data-copy="cscli bouncers add my-bouncer">Copy: cscli bouncers add …</button></div>`;
  }

  return `<div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Type</th><th>Version</th><th>Last pull</th></tr></thead>
    <tbody>${bouncers.map((bouncer) => `
      <tr>
        <td class="mono">${esc(bouncer.name)}</td>
        <td>${esc(bouncer.type || '—')}</td>
        <td class="mono">${esc(bouncer.version || '—')}</td>
        <td data-sort="${sortDate(bouncer.last_pull)}">${bouncer.last_pull ? relTime(bouncer.last_pull) : 'never'}</td>
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

function renderBarList(items, drilldown = null) {
  if (!items || items.length === 0) return '<div class="empty">No data</div>';

  const max = Math.max(1, ...items.map((item) => item.count));

  return `<div class="bar-list">${items.map((item) => `
    <div class="bar-row">
      ${drilldown ? `<a class="name" href="${esc(filteredLink(drilldown[0], drilldown[1], item.name))}">${esc(item.name)}</a>` : `<span class="name" title="${esc(item.name)}">${esc(item.name)}</span>`}
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
      <td data-sort="${sortDate(alert.created_at)}" title="${esc(fmtDate(alert.created_at))}">${esc(relTime(alert.created_at))}</td>
      <td class="mono">${esc(alert.scenario)}</td>
      <td class="mono"><button class="table-link" aria-label="Open alert #${alert.id}: ${esc(alert.source_ip || alert.source_value || 'Details')}">${esc(alert.source_ip || alert.source_value || 'Details')}</button></td>
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
    ${filterPanelOpen('alerts')}
        <form class="form-grid" id="alert-filters">
          <div class="field"><label for="f-scenario">Scenario</label><input id="f-scenario" type="text" placeholder="crowdsecurity/ssh-bf"></div>
          <div class="field"><label for="f-ip">Source IP</label><input id="f-ip" type="text" placeholder="1.2.3.4"></div>
          <div class="field"><label for="f-limit">Limit</label>
            <select id="f-limit"><option>50</option><option selected>100</option><option>250</option><option>500</option></select>
          </div>
          <div class="field"><label for="f-since">Period</label><select id="f-since"><option value="">All retained alerts</option><option value="1h">Last hour</option><option value="6h">Last 6 hours</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></div>
          <div class="field"><label for="f-origin">Decision origin</label><input id="f-origin" type="text" placeholder="cscli, crowdsec, CAPI…"></div>
          <div class="field"><label for="f-kind">Kind</label><select id="f-kind"><option value="">Any</option><option value="overflow">Overflow</option><option value="appsec">AppSec</option></select></div>
          <div class="field"><label for="f-include_capi">Shared alerts</label><select id="f-include_capi"><option value="false">Exclude CAPI</option><option value="true">Include CAPI</option></select></div>
          <div class="field" style="display:flex;align-items:flex-end"><button class="btn" type="submit">Filter</button></div>
        </form>
      ${filterPanelClose()}
    <div class="panel"><div id="alerts-body">${spinner()}</div></div>`;

  let loadID = 0;
  const load = async () => {
    const id = ++loadID;
    const body = $('#alerts-body');
    const params = new URLSearchParams();
    const scenario = $('#f-scenario').value.trim();
    const ip = $('#f-ip').value.trim();
    if (scenario) params.set('scenario', scenario);
    if (ip) params.set('ip', ip);
    params.set('limit', $('#f-limit').value);
    ['since', 'origin', 'kind', 'include_capi'].forEach((key) => {
      const value = $(`#f-${key}`)?.value;
      if (value) params.set(key, value);
    });
    rememberFilters('alerts', params);
    updateFilterBadge('alerts');

    $('#alerts-body').innerHTML = spinner();

    try {
      const data = await api(`/api/alerts?${params}`);
      if (id !== loadID || !body.isConnected) return;
      state.cache.alerts = data.alerts;
      body.innerHTML = resultCount(data.alerts.length, Number(params.get('limit'))) + (data.alerts.length
        ? `<div class="table-wrap">${renderAlertsTable(data.alerts)}</div>`
        : '<div class="empty">No alerts match the filter</div>');
      enhanceTables(body);
      mountRefresh(data.generated_at || new Date().toISOString());
    } catch (error) {
      if (id === loadID && body.isConnected && error.name !== 'AbortError') body.innerHTML = errorBox(error.message, true);
    }
  };

  $('#alert-filters').addEventListener('submit', (event) => {
    event.preventDefault();
    load();
  });

  Object.entries(state.filters.alerts).forEach(([key, value]) => { const input = $(`#f-${key}`); if (input) input.value = value; });
  await load();
}

async function showAlert(id) {
  openModal('Alert', spinner());
  const modal = $('#modal-root dialog');

  try {
    const alert = await api(`/api/alerts/${id}`);
    if (!modal.isConnected) return;
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
        ${source.ip ? `<button class="btn secondary" data-inspect-ip="${esc(source.ip)}">Inspect IP</button>` : ''}
        <button class="btn secondary" id="alert-close">Close</button>
        <button class="btn danger" id="alert-delete">Delete alert</button>
      </div>`);

    $('#alert-close').addEventListener('click', closeModal);

    $('#alert-delete').addEventListener('click', async (event) => {
      if (!confirm(`Delete alert #${id}?`)) return;
      const button = event.currentTarget;
      const dialog = button.closest('dialog');
      button.disabled = true;

      try {
        await api(`/api/alerts/${id}`, { method: 'DELETE' });
        if (dialog.isConnected) { closeModal(); route(); }
        toast('Alert deleted', 'ok');
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });
  } catch (error) {
    if (!modal.isConnected || error.name === 'AbortError') return;
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
    ${filterPanelOpen('decisions')}
        <form class="form-grid" id="decision-filters">
          <div class="field"><label for="d-ip">IP</label><input id="d-ip" type="text" placeholder="1.2.3.4"></div>
          <div class="field"><label for="d-range">Range</label><input id="d-range" type="text" placeholder="1.2.3.0/24"></div>
          <div class="field"><label for="d-value">Value</label><input id="d-value" type="text" placeholder="exact value"></div>
          <div class="field"><label for="d-type">Type</label>
            <select id="d-type"><option value="">any</option><option>ban</option><option>captcha</option></select>
          </div>
          <div class="field"><label for="d-origin">Origin</label><input id="d-origin" type="text" placeholder="cscli, crowdsec, CAPI…"></div>
          <div class="field"><label for="d-scenario">Scenario</label><input id="d-scenario" type="text"></div>
          <div class="field"><label for="d-scope">Scope</label><select id="d-scope"><option value="">Any</option><option>ip</option><option>range</option></select></div>
          <div class="field"><label for="d-limit">Alert retrieval limit</label><select id="d-limit"><option>100</option><option selected>500</option><option>1000</option><option>5000</option></select></div>
          <div class="field" style="display:flex;align-items:flex-end"><button class="btn" type="submit">Filter</button></div>
        </form>
      ${filterPanelClose()}
    <div class="panel"><div id="decisions-body">${spinner()}</div></div>`;

  let loadID = 0;
  const load = async () => {
    const id = ++loadID;
    const body = $('#decisions-body');
    const params = new URLSearchParams();
    filterFields.decisions.map((key) => [key, `#d-${key}`]).forEach(([key, sel]) => {
      const value = $(sel)?.value.trim();
      if (value) params.set(key, value);
    });
    rememberFilters('decisions', params);
    updateFilterBadge('decisions');

    $('#decisions-body').innerHTML = spinner();

    try {
      const data = await api(`/api/decisions?${params}`);
      if (id !== loadID || !body.isConnected) return;
      body.innerHTML = renderDecisionsTable(data.decisions) + resultCount(data.decisions.length, data.alert_limit || Number(params.get('limit')) || 500, data.limited || false);
      enhanceTables(body);
      mountRefresh(data.generated_at || new Date().toISOString());

      const decisionsById = new Map((data.decisions || []).map((item) => [item.id, item]));
      $$('#decisions-body tr[data-decision-id]').forEach((row) => {
        const button = $('button[data-delete]', row);
        if (button) {
          button.addEventListener('click', async (event) => {
            event.stopPropagation();
            await deleteDecision(decisionsById.get(Number(row.dataset.decisionId)), load, button);
          });
        }
      });
    } catch (error) {
      if (id === loadID && body.isConnected && error.name !== 'AbortError') body.innerHTML = errorBox(error.message, true);
    }
  };

  $('#decision-filters').addEventListener('submit', (event) => {
    event.preventDefault();
    load();
  });

  $('#add-decision').addEventListener('click', () => showDecisionForm('local', load));

  Object.entries(state.filters.decisions).forEach(([key, value]) => { const input = $(`#d-${key}`); if (input) input.value = value; });
  await load();
}

function renderDecisionsTable(decisions, actionable = true) {
  if (!decisions || decisions.length === 0) return '<div class="empty">No decisions</div>';

  const rows = decisions.map((decision) => `
    <tr data-decision-id="${decision.id}" data-origin="${esc(decision.origin)}">
      <td class="mono">${decision.scope === 'ip' ? `<button class="table-link" data-inspect-ip="${esc(decision.value)}">${esc(decision.value)}</button>` : `<span data-copy="${esc(decision.value)}" title="Click to copy">${esc(decision.value)}</span>`}</td>
      <td>${esc(decision.scope)}</td>
      <td>${decision.country ? `<span class="flag">${flag(decision.country)}</span> ${esc(decision.country)}` : '—'}</td>
      <td class="mono" title="${esc(decision.as_name || '')}">${esc(decision.as_name || '—')}</td>
      <td>${typeBadge(decision.type)}${decision.simulated ? ' ' + badge('simulated', 'sim') : ''}</td>
      <td class="mono" data-sort="${sortDate(decision.until)}">${esc(fmtDuration(decision.duration))}</td><td class="mono" data-sort="${sortDate(decision.until)}">${esc(fmtDate(decision.until))}</td>
      <td class="mono">${esc(decision.scenario)}</td>
      <td class="mono">${esc(decision.origin)}</td>
      <td>${decision.alert_id ? `<button class="table-link" data-alert-id="${decision.alert_id}">Alert #${decision.alert_id}</button>` : '—'}</td>${actionable ? '<td><button class="btn danger" data-delete style="padding:4px 9px;font-size:12px">Unban</button></td>' : ''}
    </tr>`).join('');

  return `<div class="table-wrap"><table>
    <thead><tr><th>Value</th><th>Scope</th><th>Country</th><th>AS</th><th>Type</th><th>Remaining</th><th>Until</th><th>Scenario</th><th>Origin</th><th>Alert</th>${actionable ? '<th></th>' : ''}</tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function deleteDecision(decision, onDone, button) {
  button.disabled = true;

  try {
    await api(`/api/decisions/${decision.id}`, { method: 'DELETE' });
    await onDone();
    toast(`Decision for ${decision.value} removed`, 'ok', {
      label: 'Undo',
      onClick: async () => {
        try {
          await api('/api/decisions', {
            method: 'POST',
            body: {
              value: decision.value,
              scope: decision.scope,
              type: decision.type,
              duration: decision.duration || '4h',
              reason: 'undo delete from cswebui',
            },
          });
          toast('Decision restored', 'ok');
          await onDone();
        } catch (error) {
          if (error.name !== 'AbortError') toast(error.message, 'error');
        }
      },
    });
  } catch (error) {
    if (error.name !== 'AbortError') toast(error.message, 'error');
  } finally {
    button.disabled = false;
  }
}


function showDecisionForm(target, onDone) {
  const title = target === 'local' ? 'Add decision' : 'Share decision via blocklist server';

  openModal(title, `
    <form id="decision-form">
      <div class="form-grid">
        <div class="field"><label for="n-value">IP or range</label><input id="n-value" type="text" placeholder="1.2.3.4" required autofocus></div>
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
      const button = $('button[type="submit"]', event.currentTarget);
      const dialog = event.currentTarget.closest('dialog');
      if (button.disabled) return;
      button.disabled = true;

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
        if (dialog.isConnected) closeModal();
        toast(target === 'local' ? 'Decision created' : 'Decision shared', 'ok');
        if (onDone && state.route === (target === 'local' ? 'decisions' : 'blocklist')) await onDone();
      } catch (error) {
        if (error.name !== 'AbortError') toast(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });
  });
}

/* ---------------- allowlists ---------------- */

async function renderAllowlists() {
  const view = $('#view');

  view.innerHTML =
    `<div class="page-header"><div><h2>Allowlists</h2><p>Never ban these values.</p></div><div class="toolbar"><button class="btn" data-allowlist-create>Create allowlist</button></div></div>
     <div class="panel"><div id="allowlists-body">${spinner()}</div></div>`;

  const data = await api('/api/allowlists');
  state.cache.updatedAt = data.generated_at;

  if (!data.allowlists.length) {
    $('#allowlists-body').innerHTML = '<div class="empty">No allowlists configured</div>';
    return;
  }

  $('#allowlists-body').innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Description</th><th>Items</th><th>Managed by console</th></tr></thead>
      <tbody>${data.allowlists.map((list) => `
        <tr class="clickable" data-allowlist="${esc(list.name)}">
          <td class="mono"><button class="table-link">${esc(list.name)}</button></td>
          <td class="wrap">${esc(list.description)}</td>
          <td>${(list.items || []).length}</td>
          <td>${list.console_managed ? 'yes' : 'no'}</td>
        </tr>`).join('')}</tbody>
    </table></div>`;

}

async function showAllowlist(name) {
  openModal(`Allowlist ${name}`, spinner());
  const modal = $('#modal-root dialog');

  try {
    const allowlist = await api(`/api/allowlists/${encodeURIComponent(name)}`);
    if (!modal.isConnected) return;

    const items = (allowlist.items || []).map((item) => `
      <tr>
        <td class="mono">${esc(item.value)}</td>
        <td class="wrap">${esc(item.description)}</td>
        <td class="mono" data-sort="${sortDate(item.expiration)}">${!item.expiration || item.expiration.startsWith('0001') ? 'permanent' : esc(fmtDate(item.expiration))}</td>${allowlist.console_managed ? '' : `<td><button class="btn danger" data-allowlist-remove data-allowlist-name="${esc(name)}" data-allowlist-value="${esc(item.value)}">Remove</button></td>`}
      </tr>`).join('');

    openModal(`Allowlist ${name}`, `
      <dl class="kv">
        <dt>Description</dt><dd>${esc(allowlist.description)}</dd>
        <dt>Created</dt><dd>${esc(fmtDate(allowlist.created_at))}</dd>
        <dt>Items</dt><dd>${(allowlist.items || []).length}</dd>
      </dl>
      ${items ? `<div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Description</th><th>Expiration</th>${allowlist.console_managed ? '' : '<th></th>'}</tr></thead>
        <tbody>${items}</tbody></table></div>` : '<div class="empty">No items</div>'}
      ${allowlist.console_managed ? '<p class="hint">Managed by the CrowdSec Console; local editing is disabled.</p>' : `<div class="form-actions"><button class="btn" data-allowlist-add="${esc(name)}">Add entry</button><button class="btn danger" data-allowlist-remove data-allowlist-name="${esc(name)}">Delete allowlist</button></div>`}`);
  } catch (error) {
    if (!modal.isConnected || error.name === 'AbortError') return;
    openModal(`Allowlist ${name}`, errorBox(error.message));
  }
}

/* ---------------- shared blocklist ---------------- */

async function renderBlocklist() {
  const view = $('#view');
  const signal = viewController.signal;

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Shared blocklist</h2><p>Decisions exchanged through your own blocklist server.</p></div>
      <div class="toolbar"><button class="btn" id="share-decision">Share decision</button></div>
    </div>
    ${filterPanelOpen('blocklist')}<form id="blocklist-filters" class="form-grid">
      <div class="field"><label for="bl-value">Value</label><input id="bl-value" type="text"></div>
      <div class="field"><label for="bl-scenario">Scenario</label><input id="bl-scenario" type="text"></div>
      <div class="field"><label for="bl-limit">Limit</label><select id="bl-limit"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select></div>
      <button class="btn" type="submit">Filter</button></form>${filterPanelClose()}
    <div id="blocklist-stats" class="cards"></div>
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Entries</h3><span class="hint" id="blocklist-count"></span></div>
      <div id="blocklist-decisions">${spinner()}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Registered engines</h3></div>
      <div id="blocklist-machines">${spinner()}</div>
    </div>`;

  $('#share-decision').addEventListener('click', () => showDecisionForm('blocklist', async () => route()));
  Object.entries(state.filters.blocklist || {}).forEach(([key, value]) => { const input = $(`#bl-${key}`); if (input) input.value = value; });
  const filters = new URLSearchParams(state.filters.blocklist || {});
  $('#blocklist-filters')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const params = new URLSearchParams();
    filterFields.blocklist.forEach((key) => { const value = $(`#bl-${key}`).value.trim(); if (value) params.set(key, value); });
    rememberFilters('blocklist', params); updateFilterBadge('blocklist'); route();
  });

  const [stats, decisions, machines] = await Promise.all([
    api('/api/blocklist/stats').catch((error) => ({ error: error.message })),
    api(`/api/blocklist/decisions?${filters}`).catch((error) => ({ error: error.message })),
    api('/api/blocklist/machines').catch((error) => ({ error: error.message })),
  ]);
  signal.throwIfAborted();

  if (stats.error) {
    $('#blocklist-stats').innerHTML = errorBox(stats.error, true);
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
      <td class="mono" data-sort="${sortDate(decision.until)}">${esc(fmtDate(decision.until))}</td>
      <td>${esc(decision.source)}</td>
      <td><button class="btn danger" data-blocklist-id="${decision.id}" style="padding:4px 9px;font-size:12px">Remove</button></td>
    </tr>`).join('');

  $('#blocklist-decisions').innerHTML = decisions.error ? errorBox(decisions.error, true) : entries
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Scope</th><th>Scenario</th><th>Duration</th><th>Until</th><th>Source</th><th></th></tr></thead>
        <tbody>${entries}</tbody></table></div>`
    : '<div class="empty">No shared decisions</div>';

  $('#blocklist-count').textContent = decisions.error ? 'Unavailable' : `${(decisions.decisions || []).length} shown · limit ${filters.get('limit') || 200}${(decisions.decisions || []).length >= Number(filters.get('limit') || 200) ? ' · limit reached' : ''}`;

  $$('button[data-blocklist-id]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!confirm('Remove this entry from the shared blocklist?')) return;
      button.disabled = true;

      try {
        await api(`/api/blocklist/decisions/${button.dataset.blocklistId}`, { method: 'DELETE' });
        toast('Entry removed', 'ok');
        if (!signal.aborted) route();
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });
  });

  const engineRows = (machines.machines || []).map((machine) => `
    <tr>
      <td class="mono">${esc(machine.machine_id)}</td>
      <td>${esc(machine.last_ip)}</td>
      <td data-sort="${sortDate(machine.last_seen)}">${esc(machine.last_seen && !machine.last_seen.startsWith('0001') ? relTime(machine.last_seen) : 'never')}</td>
    </tr>`).join('');

  $('#blocklist-machines').innerHTML = machines.error ? errorBox(machines.error, true) : engineRows
    ? `<div class="table-wrap"><table><thead><tr><th>Machine</th><th>Last IP</th><th>Last seen</th></tr></thead><tbody>${engineRows}</tbody></table></div>`
    : '<div class="empty">No engine registered yet</div>';
}

/* ---------------- configuration ---------------- */

let currentConfig = { name: null, content: '' };

async function renderConfig() {
  const view = $('#view');
  const selectedName = currentConfig.name;
  currentConfig = { name: null, content: '' };

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Configuration</h2><p>Edit the engine configuration and reload it.</p></div>
      <div class="toolbar">
        <button class="btn secondary" id="config-check">Check saved config</button><button class="btn secondary" id="config-reload">Reload engine</button>
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
          <textarea class="editor" id="config-editor" aria-labelledby="config-title" spellcheck="false" placeholder="Choose a file on the left" disabled></textarea>
          <div class="editor-actions">
            <span class="hint" id="config-status" role="status"></span>
            <button class="btn secondary" data-config-preview>Review changes</button><button class="btn" id="config-save" disabled>Save</button>
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
      loadConfigFile(button.dataset.file).catch((error) => { if (error.name !== 'AbortError') toast(error.message, 'error'); });
    });
  });

  $('#config-save').addEventListener('click', saveConfigFile);
  $('#config-check').addEventListener('click', checkSavedConfig);
  $('#config-editor').addEventListener('input', () => {
    $('#config-save').disabled = !isDirty();
    $('#config-reload').disabled = isDirty();
    $('#config-check').disabled = isDirty();
    $('#config-status').textContent = isDirty() ? 'Unsaved changes · save before reloading' : '';
  });

  $('#config-reload').addEventListener('click', async () => {
    const button = $('#config-reload');
    button.disabled = true;
    try {
      const result = await api('/api/reload', { method: 'POST' });
      toast(result.output || result.message, 'ok');
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      button.disabled = isDirty();
    }
  });

  if (selectedName && data.files.some((file) => file.name === selectedName)) {
    await loadConfigFile(selectedName);
  } else if (data.files.length > 0) {
    const first = data.files.find((file) => file.exists) || data.files[0];
    await loadConfigFile(first.name);
  }
}

async function loadConfigFile(name) {
  if (!discardConfigChanges()) return;

  const editor = $('#config-editor');
  const buttons = $$('#config-files button');
  editor.disabled = true;
  $('#config-save').disabled = true;
  buttons.forEach((button) => { button.disabled = true; });

  try {
    const file = await api(`/api/config/${encodeURIComponent(name).replace(/%2F/g, '/')}`);
    currentConfig = { name, content: file.content || '' };

    editor.value = currentConfig.content;
    $('#config-title').textContent = name;
    $('#config-meta').textContent = `${file.size} bytes · ${fmtDate(file.modified)}`;
    $('#config-status').textContent = '';
    $('#config-reload').disabled = false;
    if ($('#config-check')) $('#config-check').disabled = false;

    buttons.forEach((button) => { button.classList.toggle('active', button.dataset.file === name); });
  } finally {
    editor.disabled = !currentConfig.name;
    buttons.forEach((button) => { button.disabled = false; });
    if (editor.isConnected) $('#config-save').disabled = !isDirty();
  }
}

function isDirty() {
  const editor = $('#config-editor');
  return editor ? editor.value !== currentConfig.content : false;
}

async function saveConfigFile() {
  if (!currentConfig.name) return;

  const button = $('#config-save');
  const editor = $('#config-editor');
  const name = currentConfig.name;
  const content = editor.value;
  const fileButtons = $$('#config-files button');
  button.disabled = true;
  editor.disabled = true;
  fileButtons.forEach((item) => { item.disabled = true; });
  $('#config-reload').disabled = true;

  try {
    await api(`/api/config/${encodeURIComponent(name).replace(/%2F/g, '/')}`, {
      method: 'PUT',
      body: { content },
    });
    if (!editor.isConnected) return;
    currentConfig.content = content;
    $('#config-status').textContent = 'Saved · reload the engine to apply';
    toast('Configuration saved. Reload the engine to apply it.', 'ok');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    editor.disabled = false;
    fileButtons.forEach((item) => { item.disabled = false; });
    if (editor.isConnected) {
      button.disabled = !isDirty();
      $('#config-reload').disabled = isDirty();
      if ($('#config-check')) $('#config-check').disabled = isDirty();
    }
  }
}



/* ---------------- geo map ---------------- */

function projectGeo(lat, lon) {
  return [lon + 180, 90 - lat];
}

function mapIntensity(count, max) {
  if (!count || count <= 0) {
    return 'rgba(21, 34, 47, 0.85)';
  }

  // Any country with data is clearly visible; the busiest one is near opaque.
  const ratio = count / Math.max(1, max);
  return `rgba(56, 189, 248, ${(0.55 + 0.4 * ratio).toFixed(3)})`;
}

function renderWorldMap(geoPoints, byCountry) {
  const counts = {};
  (byCountry || []).forEach((country) => { counts[country.name] = country.count; });

  const values = Object.values(counts);
  const max = Math.max(1, ...values);
  const countriesWithData = values.length;

  if (countriesWithData === 0 && (geoPoints || []).length === 0) {
    return '<div class="empty">No GeoIP data yet. Enable the geoip-enrich parser and provide GeoLite2 data.</div>';
  }

  let countryLayer = '';

  if (typeof COUNTRY_PATHS !== 'undefined' && Object.keys(COUNTRY_PATHS).length > 0) {
    countryLayer = Object.entries(COUNTRY_PATHS).map(([iso, path]) => {
      const count = counts[iso] || 0;
      const name = (COUNTRY_CENTROIDS[iso] || [0, 0, iso])[2];
      const title = count > 0 ? `${name}: ${count} alert(s)` : name;
      const className = count > 0 ? 'map-country has-data' : 'map-country';
      return `<path class="${className}" d="${path}" fill="${mapIntensity(count, max)}"><title>${esc(title)}</title></path>`;
    }).join('');
  }

  // Small dots keep the exact cluster visible on top of the country shading.
  const dots = (geoPoints || []).map((point) => {
    const [x, y] = projectGeo(point.lat, point.lon);
    const label = point.country ? `${point.country}: ${point.count} alert(s)` : `${point.count} alert(s)`;
    return `<circle class="map-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="1.1"><title>${esc(label)}</title></circle>`;
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
      <g>${countryLayer}</g>
      <g class="map-dots">${dots}</g>
    </svg>
    <div class="map-legend">
      <span>few</span>
      <span class="map-scale"></span>
      <span>many</span>
      <span>${countriesWithData} countries, ${(geoPoints || []).length} location(s)</span>
    </div>`;
}

async function renderGeo() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Geo</h2><p>Where the detected sources are located.</p></div>
      <div class="toolbar">
        <select id="geo-range" aria-label="Time range">
          ${['6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>last ${r}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="geo-body">${spinner()}</div>`;

  $('#geo-range').addEventListener('change', (event) => {
    state.range = event.target.value;
    route();
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
  state.cache.updatedAt = infra.generated_at;
  infra.machines ||= [];
  infra.bouncers ||= [];
  const machinesAvailable = infra.db && infra.available?.machines !== false;
  const bouncersAvailable = infra.db && infra.available?.bouncers !== false;
  let metrics = null;

  try {
    metrics = (await api('/api/metrics')).summary;
  } catch (error) {
    if (error.name === 'AbortError') throw error;
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
      <td data-sort="${sortDate(machine.last_heartbeat)}">${machine.last_heartbeat ? relTime(machine.last_heartbeat) : 'never'}</td>
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
      <td data-sort="${sortDate(bouncer.last_pull)}">${bouncer.last_pull ? relTime(bouncer.last_pull) : 'never'}</td>
      <td>${bouncer.revoked ? '<span class="badge ban">revoked</span>' : statusBadge(bouncer.last_pull && new Date(bouncer.last_pull).getTime() > cutoff, 'active', 'idle')}</td>
    </tr>`).join('');

  const features = metrics && metrics.features && metrics.features.length
    ? metrics.features.map((feature) => `<span class="badge">${esc(feature)}</span>`).join(' ')
    : '<span class="hint">no metric data</span>';

  $('#infra-body').innerHTML = `
    <div class="cards">
      ${statCard('Machines', machinesAvailable ? `${machinesOnline}/${infra.machines.length}` : '—', 'online (< 5 min)')}
      ${statCard('Bouncers', bouncersAvailable ? `${bouncersActive}/${infra.bouncers.length}` : '—', 'active (< 5 min)')}
      ${metrics ? statCard('LAPI requests', metricNumber(metrics, 'lapi_requests', 'cs_lapi_route_requests_total'), 'counter since reset') : ''}
      ${metrics ? statCard('Bouncer requests', metricNumber(metrics, 'bouncer_requests', 'cs_lapi_bouncer_requests_total'), 'counter since reset') : ''}
    </div>

    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Machines</h3><span class="hint">${infra.db ? 'from the LAPI database' : 'database not readable'}</span></div>
      ${!machinesAvailable ? errorBox(infra.errors?.machines || 'Machine data unavailable: configure a readable SQLite database.') : infra.machines.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Machine</th><th>Version</th><th>OS</th><th>Scenarios</th><th>Last seen</th><th>IP</th><th>State</th></tr></thead>
        <tbody>${machineRows}</tbody></table></div>` : '<div class="empty">No machines registered</div>'}
    </div>

    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Bouncers</h3></div>
      ${!bouncersAvailable ? errorBox(infra.errors?.bouncers || 'Bouncer data unavailable: configure a readable SQLite database.') : infra.bouncers.length ? `<div class="table-wrap"><table>
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
      <div><h2>Metrics</h2><p>Prometheus counters since the engine last reset them. Unparsed lines can be normal and are not automatically parser errors.</p></div>
      <div class="toolbar"><span class="hint" id="metrics-fetched"></span></div>
    </div>
    <div id="metrics-body">${spinner()}</div>`;

  let data;

  try {
    data = await api('/api/metrics');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    $('#metrics-body').innerHTML = errorBox(`Could not scrape metrics: ${error.message}. Enable prometheus in config.yaml and check data.metrics_url.`, true);
    return;
  }

  state.cache.updatedAt = data.fetched_at;
  const m = data.summary;
  $('#metrics-fetched').textContent = `${data.samples} series · ${relTime(data.fetched_at)}`;

  const koRate = m.parser_hits > 0 && (!m.present || m.present.cs_parser_hits_ko_total) ? ((m.parser_ko / m.parser_hits) * 100).toFixed(1) : null;
  const avgParse = m.avg_parse_ms != null ? `${m.avg_parse_ms.toFixed(2)} ms` : '—';
  const lastPull = m.capi_last_pull ? relTime(m.capi_last_pull) : m.present && !m.present.cs_capi_last_pull_timestamp ? '—' : 'never';

  $('#metrics-body').innerHTML = `
    <div class="cards">
      ${statCard('Parser hits', metricNumber(m, 'parser_hits', 'cs_parser_hits_total'), 'lines entering parsing')}
      ${statCard('Parsed OK', metricNumber(m, 'parser_ok', 'cs_parser_hits_ok_total'), 'successfully parsed')}
      ${statCard('Unparsed lines', metricNumber(m, 'parser_ko', 'cs_parser_hits_ko_total'), koRate == null ? 'percentage unavailable' : `${koRate}% of hits`)}
      ${statCard('Avg parse time', avgParse, 'per line')}
      ${statCard('Active buckets', metricNumber(m, 'buckets_current', 'cs_buckets'), `${metricNumber(m, 'bucket_overflows', 'cs_bucket_overflowed_total')} overflows total`)}
      ${statCard('Acquisition lines', metricNumber(m, 'acquisition_lines', 'cs_filesource_hits_total'), 'read from sources')}
      ${statCard('LAPI requests', metricNumber(m, 'lapi_requests', 'cs_lapi_route_requests_total'), 'all routes')}
      ${statCard('CAPI last pull', lastPull, `${metricNumber(m, 'capi_errors', 'cs_capi_errors_total')} errors`)}
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Top parsers by hits</h3></div>
        <div class="panel-body">${renderBarList(m.top_nodes)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Top parsers by unparsed lines</h3></div>
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

    <div class="panel" style="margin-bottom:14px"><div class="panel-head"><h3>Log source diagnostics</h3><span class="hint">— = metric not exported; zero activity can be normal</span></div>
      ${renderMetricRows(m.sources, [['read', 'Read'], ['parsed', 'Parsed'], ['unparsed', 'Unparsed'], ['poured', 'Poured into buckets'], ['allowlisted', 'Allowlisted']])}</div>
    ${m.appsec?.length || m.appsec_rules?.length ? `<div class="panel" style="margin-bottom:14px"><div class="panel-head"><h3>AppSec</h3><span class="hint">counters since reset</span></div>
      ${renderMetricRows(m.appsec, [['processed', 'Processed'], ['blocked', 'Blocked'], ['requested', 'Challenges requested'], ['accepted', 'Challenges accepted'], ['rejected', 'Challenges rejected']])}
      <div class="panel-body"><h4>Most triggered AppSec rules</h4>${renderBarList(m.appsec_rules)}</div></div>` : ''}
    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h3>Acquisition sources</h3><span class="hint">lines read</span></div>
        <div class="panel-body">${renderBarList(m.top_sources)}</div>
      </div>
      <div class="panel">
        <div class="panel-head"><h3>Pipeline health</h3></div>
        <div class="panel-body">
          <dl class="kv" style="margin:0">
            <dt>Postoverflow queue</dt><dd>${metricNumber(m, 'postoverflow_queue', 'cs_postoverflow_queue_depth')} waiting</dd>
            <dt>Postoverflow dropped</dt><dd>${metricNumber(m, 'postoverflow_dropped', 'cs_postoverflow_dropped_total')}</dd>
            <dt>Bucket pours</dt><dd>${metricNumber(m, 'bucket_poured', 'cs_bucket_poured_total')}</dd>
            <dt>CAPI errors</dt><dd>${metricNumber(m, 'capi_errors', 'cs_capi_errors_total')}</dd>
            <dt>Version</dt><dd class="mono">${esc(m.version || '—')}</dd>
          </dl>
        </div>
      </div>
    </div>`;
}

/* ---------------- hub ---------------- */

const hubFilter = { search: '', category: '', installedOnly: true };

let hubData = null;

function hubBadges(item) {
  const state = item.enabled
    ? '<span class="badge ok">active</span>'
    : item.installed
      ? '<span class="badge warn">inactive</span>'
      : '<span class="badge off">not in use</span>';

  if (!item.tainted) return state;

  return `${state} <span class="badge warn" title="changed by hand: an upgrade leaves it alone">edited</span>`;
}

function hubBundles(item) {
  if (!item.dependencies) return '<span class="hint">—</span>';

  return Object.entries(item.dependencies).map(([kind, count]) => `${count} ${kind}`).join(', ');
}

function hubActionButton(category, item) {
  const path = item.enabled ? '/api/hub/remove' : '/api/hub/install';
  const label = item.enabled ? 'Remove' : item.installed ? 'Activate' : 'Install';

  return `<button class="btn ${item.enabled ? 'danger' : ''}" data-hub-action data-path="${path}" ` +
    `data-category="${esc(category)}" data-name="${esc(item.name)}" ` +
    `style="padding:4px 9px;font-size:12px">${label}</button>`;
}

function hubFilteredItems() {
  const rows = [];

  for (const category of hubData.categories) {
    for (const item of category.items) rows.push({ ...item, category: category.name });
  }

  for (const item of hubData.collections) rows.push({ ...item, category: 'collections' });

  const search = hubFilter.search.toLowerCase();

  return rows.filter((item) => {
    if (hubFilter.installedOnly && !item.installed) return false;
    if (hubFilter.category && item.category !== hubFilter.category) return false;

    return !search || item.name.toLowerCase().includes(search) || (item.description || '').toLowerCase().includes(search);
  });
}

function renderHubLists() {
  const status = hubData;
  let available = status.collections.length;
  let installed = 0;
  let enabled = 0;
  let edited = 0;

  for (const item of status.collections) {
    if (item.installed) installed += 1;
    if (item.enabled) enabled += 1;
    if (item.tainted) edited += 1;
  }

  for (const category of status.categories) {
    available += category.available;
    installed += category.installed;
    enabled += category.enabled;

    for (const item of category.items) {
      if (item.tainted) edited += 1;
    }
  }

  $('#hub-summary').innerHTML = `
    <div class="card"><div class="label">Hub index</div>
      <div class="value" style="font-size:20px">${status.index_missing ? 'missing' : esc(relTime(status.index_updated))}</div></div>
    <div class="card"><div class="label">Items in the hub</div><div class="value">${fmtNum(available)}</div></div>
    <div class="card"><div class="label">Active</div><div class="value">${fmtNum(enabled)}</div></div>
    <div class="card"><div class="label">Downloaded</div><div class="value">${fmtNum(installed)}</div></div>
    <div class="card"><div class="label">Edited by hand</div><div class="value" title="cscli will not overwrite these">${fmtNum(edited)}</div></div>`;

  $('#hub-category').innerHTML = ['<option value="">all types</option>']
    .concat([...status.categories.map((category) => category.name), 'collections']
      .map((name) => `<option value="${esc(name)}" ${hubFilter.category === name ? 'selected' : ''}>${esc(name)}</option>`))
    .join('');

  const items = hubFilteredItems();
  const rows = items.map((item) => `
    <tr>
      <td class="mono hub-description">${esc(item.name)}${item.description ? `<div class="hint">${esc(item.description)}</div>` : ''}</td>
      <td>${esc(item.category)}</td>
      <td class="mono">${esc(item.local_version || (item.installed ? 'unknown' : '—'))} → ${esc(item.version || '—')}${item.update_available ? ' ' + badge('update available', 'warn') : ''}</td>
      <td>${hubBadges(item)}</td>
      <td class="hint">${hubBundles(item)}</td>
      <td>${hubActionButton(item.category, item)}${item.update_available ? ` <button class="btn secondary" data-hub-action data-path="/api/hub/upgrade" data-category="${esc(item.category)}" data-name="${esc(item.name)}">Upgrade item</button>` : ''}</td>
    </tr>`).join('');

  $('#hub-items').innerHTML = rows
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Item</th><th>Type</th><th>Installed → available</th><th>State</th><th>Bundles</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
    : '<div class="empty">Nothing matches: untick "installed only" to browse the whole hub</div>';

  $('#hub-count').textContent = `${fmtNum(items.length)} shown`;
  enhanceTables($('#hub-items'));

  const locals = status.local_only || [];

  $('#hub-local').innerHTML = locals.length
    ? `<div class="table-wrap"><table><thead><tr><th>File below ${esc(status.config_dir)}</th></tr></thead><tbody>` +
      locals.map((file) => `<tr><td class="mono">${esc(file)}</td></tr>`).join('') + '</tbody></table></div>'
    : '<div class="empty">Every file in the config tree comes from the hub</div>';

  $$('button[data-hub-action]').forEach((button) => {
    button.addEventListener('click', () => {
      const body = { category: button.dataset.category, name: button.dataset.name };

      if (button.dataset.path === '/api/hub/upgrade' && !confirm(`Upgrade ${body.category}/${body.name} and reload the engine?`)) return;

      if (button.dataset.path === '/api/hub/remove' && !confirm(`Remove ${body.category}/${body.name} and reload the engine?`)) return;

      hubAction(button.dataset.path, body, button);
    });
  });
}

let hubBusy = false;

async function hubAction(path, body, button) {
  if (hubBusy) return;
  hubBusy = true;
  const controls = $$('button, input, select', $('#view')).map((item) => [item, item.disabled]);
  controls.forEach(([item]) => { item.disabled = true; });

  if (button) button.textContent = 'Working…';

  try {
    const result = await api(path, { method: 'POST', body });

    if (result.reload_error) {
      toast(`${result.message} — the engine was NOT reloaded: ${result.reload_error}`, 'error');
    } else {
      toast(result.reload ? `${result.message} · ${result.reload}` : result.message, 'ok');
    }
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    hubBusy = false;
    controls.forEach(([item, disabled]) => { item.disabled = disabled; });
  }

  if (state.route === 'hub' && state.user) route();
}

async function renderHub() {
  const view = $('#view');

  view.innerHTML = `
    <div class="page-header">
      <div><h2>Hub</h2><p>What the engine detects with: parsers, scenarios, contexts, collections.</p></div>
      <div class="toolbar">
        <button class="btn secondary" data-hub-update>Refresh index</button>
        <button class="btn secondary" data-hub-upgrade>Upgrade items</button>
      </div>
    </div>
    <div class="cards" id="hub-summary">${spinner()}</div>
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h3>Items</h3><span class="hint" id="hub-count"></span></div>
      <div class="panel-body">
        <div class="toolbar">
          <input type="text" id="hub-search" aria-label="Search hub items" placeholder="filter by name or description" value="${esc(hubFilter.search)}" style="flex:1;min-width:180px">
          <select id="hub-category" aria-label="Item type"></select>
          <label class="hint"><input type="checkbox" id="hub-installed" ${hubFilter.installedOnly ? 'checked' : ''}> installed only</label>
        </div>
        <div id="hub-items">${spinner()}</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h3>Files not from the hub</h3><span class="hint">added by hand, cscli does not manage them</span></div>
      <div id="hub-local">${spinner()}</div>
    </div>`;

  let status;

  try {
    status = await api('/api/hub');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    view.innerHTML = `<div class="page-header"><div><h2>Hub</h2></div></div>${errorBox(error.message, true)}`;

    return;
  }

  state.cache.updatedAt = status.generated_at;
  hubData = status;
  renderHubLists();

  $('#hub-search').addEventListener('input', (event) => {
    hubFilter.search = event.target.value;
    renderHubLists();
  });

  $('#hub-installed').addEventListener('change', (event) => {
    hubFilter.installedOnly = event.target.checked;
    renderHubLists();
  });

  $('#hub-category').addEventListener('change', (event) => {
    hubFilter.category = event.target.value;
    renderHubLists();
  });

  $('[data-hub-update]').addEventListener('click', (event) => hubAction('/api/hub/update', {}, event.currentTarget));

  $('[data-hub-upgrade]').addEventListener('click', (event) => {
    if (!confirm('Upgrade every installed hub item and reload the engine?')) return;

    hubAction('/api/hub/upgrade', {}, event.currentTarget);
  });
}

boot();
