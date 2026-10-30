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
  return `<div class="empty" role="alert"><p class="error-text">${esc(message)}</p>${retry ? '<button class="btn secondary" data-retry type="button">Try again</button>' : ''}</div>`;
}

function fmtNum(value) {
  const number = Number(value || 0);
  return number.toLocaleString();
}

function flag(country) {
  if (!country || country.length !== 2) return '';
  return String.fromCodePoint(...[...country.toUpperCase()].map((ch) => 0x1F1E6 + ch.charCodeAt(0) - 65));
}

function shortID(value) {
  if (!value) return '—';
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function statusBadge(active, activeText = 'online', inactiveText = 'offline') {
  return active
    ? `<span class="badge ok">${esc(activeText)}</span>`
    : `<span class="badge">${esc(inactiveText)}</span>`;
}

function statCard(label, value, hint) {
  return `<div class="card">
    <div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div>
    <div class="hint">${esc(hint)}</div>
  </div>`;
}

function statPill(label, value, state = '') {
  return `<span class="stat-pill"><span class="dot ${state}"></span><span class="stat-label">${esc(label)}</span><strong>${esc(value)}</strong></span>`;
}

/* ---------------- theme ---------------- */

const THEME_KEY = 'cswebui.theme';

function applyTheme(theme) {
  const root = document.documentElement;
  if (!root) return;
  if (theme) root.dataset.theme = theme;
  else delete root.dataset.theme;
  const icon = $('#theme-toggle use');
  if (icon) icon.setAttribute('href', effectiveTheme(theme) === 'dark' ? '#i-sun' : '#i-moon');
}

function effectiveTheme(theme) {
  if (theme) return theme;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

let storedTheme = '';
try { storedTheme = localStorage.getItem(THEME_KEY) || ''; } catch { /* storage may be unavailable */ }
applyTheme(storedTheme);

$('#theme-toggle')?.addEventListener('click', () => {
  const next = effectiveTheme(storedTheme) === 'dark' ? 'light' : 'dark';
  storedTheme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
  applyTheme(next);
});

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
  const user = state.user || '';
  if ($('#current-user')) $('#current-user').textContent = user;
  if ($('#user-avatar')) $('#user-avatar').textContent = user.slice(0, 2) || '—';
  if ($('#version')) $('#version').textContent = `cswebui ${state.session?.version || ''}`.trim();

  if (state.session && !state.session.features?.blocklist) {
    $('#nav-blocklist')?.classList.add('hidden');
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
  const sidebar = $('.sidebar');
  const wasOpen = sidebar?.classList.contains('nav-open');
  sidebar?.classList.toggle('nav-open', open);
  $('#nav-toggle')?.setAttribute('aria-expanded', String(open));
  $('#nav-toggle')?.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  const scrim = $('#nav-scrim');
  if (scrim) {
    scrim.hidden = !open;
    scrim.classList.toggle('visible', open);
  }
  document.body?.classList.toggle('nav-locked', open);
  // Move focus into the drawer so keyboard users land where the eye is.
  if (open && !wasOpen) {
    const current = $('#nav a.active') || $('#nav a');
    current?.focus?.();
  }
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
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!$('.sidebar')?.classList.contains('nav-open')) return;
  setNavOpen(false);
  $('#nav-toggle').focus();
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
  const label = $('#nav a.active')?.textContent?.trim() || 'Dashboard';
  document.title = `${label} · CrowdSec`;
  const mobileTitle = $('#mobile-title');
  if (mobileTitle) mobileTitle.textContent = label;

  routes[state.route]().then(() => {
    if (signal.aborted) return;
    enhanceTables();
    mountRefresh(state.cache.updatedAt || new Date().toISOString());
  }).catch((error) => {
    if (signal.aborted) return;
    $('#view').innerHTML = errorBox(error.message, true);
  });
}

/* ---------------- shared building blocks ---------------- */

function pageHeader(title, subtitle, toolbar = '') {
  return `<div class="page-header">
      <div><h2>${esc(title)}</h2><p>${esc(subtitle)}</p></div>
      ${toolbar ? `<div class="toolbar">${toolbar}</div>` : ''}
    </div>`;
}

function section(title, body, extra = '') {
  return `<div class="panel${extra ? ` ${extra}` : ''}">
      <div class="panel-head"><h3>${esc(title)}</h3></div>
      <div class="panel-body">${body}</div>
    </div>`;
}

function disclosure(title, body, hint = '') {
  return `<details class="panel disclosure">
      <summary><span>${esc(title)}</span>${hint ? `<span class="hint">${esc(hint)}</span>` : ''}</summary>
      <div class="panel-body">${body}</div>
    </details>`;
}

/* ---------------- dashboard ---------------- */

async function renderDashboard() {
  const view = $('#view');

  view.innerHTML = `
    ${pageHeader('Dashboard', 'Everything your Security Engine knows right now.', `
      <span class="pill" id="lapi-pill"><span class="dot off"></span> Local API</span>
      <select id="range" aria-label="Time range">
        ${['1h', '6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>Last ${r}</option>`).join('')}
      </select>`)}
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
      <div class="card">
        <div class="label">Alerts · last ${esc(state.range)}</div>
        <div class="value">${alertsOk ? fmtNum(data.alerts.total) : '—'}</div>
        <div class="hint">${alertsOk ? `${fmtNum(data.alerts.events)} events ${delta(data.alerts.total, previous?.Total)}` : 'unavailable'}</div>
      </div>
      <div class="card">
        <div class="label">Unique sources</div>
        <div class="value">${alertsOk ? fmtNum(data.alerts.unique_sources) : '—'}</div>
        <div class="hint">${alertsOk ? `distinct IPs ${delta(data.alerts.unique_sources, previous?.UniqueSources)}` : 'unavailable'}</div>
      </div>
      <div class="card">
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
    ? `<div class="grid-2">
        ${section('Top parsers', renderBarList(metrics.top_nodes))}
        ${section('Top buckets', renderBarList(metrics.top_buckets))}
      </div>`
    : `<div class="panel"><div class="panel-body">
         <span class="hint">Prometheus metrics are not reachable. Enable <code>prometheus</code> in <code>config.yaml</code> and set <code>data.metrics_url</code> in the cswebui config.</span>
       </div></div>`;

  $('#dashboard-body').innerHTML = `
    ${onboarding}
    ${situation}
    ${strip}

    <div class="panel">
      <div class="panel-head"><h3>Alerts over time</h3><span class="hint">${esc(state.range)}</span></div>
      <div class="panel-body">
        ${alertsOk ? renderChart(data.alerts.timeline) : '<div class="empty">Alert data unavailable</div>'}
        <div class="chart-legend"><span>${data.alerts.timeline.length ? chartTime(data.alerts.timeline[0].time) : ''}</span><span>peak ${fmtNum(Math.max(0, ...data.alerts.timeline.map((point) => point.count)))}</span><span>${data.alerts.timeline.length ? chartTime(data.alerts.timeline[data.alerts.timeline.length - 1].time) : ''}</span></div>
      </div>
    </div>

    <div class="panel map-panel">
      <div class="panel-head"><h3>Where attacks come from</h3><span class="hint">GeoIP, last ${esc(state.range)}</span></div>
      <div class="panel-body map-split">
        <div class="map-canvas">${alertsOk ? renderWorldMap(data.alerts.geo, data.alerts.by_country) : '<div class="empty">Alert data unavailable</div>'}</div>
        <div class="map-side">${alertsOk ? renderCountryList(data.alerts.by_country) : ''}</div>
      </div>
    </div>

    <div class="grid-2">
      ${section('Top scenarios', renderBarList(data.alerts.by_scenario, ['alerts', 'scenario']))}
      ${section('Decisions by origin', renderBarList(data.decisions.by_origin, ['decisions', 'origin']))}
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Recent alerts</h3><a href="#/alerts">Show all</a></div>
      <div class="table-wrap">${data.data_sources.recent_alerts === false ? '<div class="empty">Recent alerts unavailable</div>' : renderAlertsTable(data.recent_alerts, true)}</div>
    </div>

    ${disclosure('More detail', `
      ${renderHealth(data)}
      <div class="grid-2">
        ${section('Top AS', renderBarList(data.alerts.by_as))}
        ${section('Metrics', metrics ? `<dl class="kv">
            <dt>Parser hits</dt><dd>${metricNumber(metrics, 'parser_hits', 'cs_parser_hits_total')}</dd>
            <dt>Unparsed</dt><dd>${metricNumber(metrics, 'parser_ko', 'cs_parser_hits_ko_total')}${ko ? ` · ${ko}` : ''}</dd>
            <dt>Active buckets</dt><dd>${metricNumber(metrics, 'buckets_current', 'cs_buckets')}</dd>
            <dt>LAPI requests</dt><dd>${metricNumber(metrics, 'lapi_requests', 'cs_lapi_route_requests_total')}</dd>
          </dl>` : '<span class="hint">Metrics unavailable</span>')}
      </div>
      <div class="grid-2">
        <div class="panel m0">
          <div class="panel-head"><h3>Machines</h3><a href="#/infrastructure">Details</a></div>
          ${data.data_sources.machines === false ? '<div class="empty">Machine data unavailable</div>' : renderMachinesTable(data.machines.items.slice(0, 6))}
        </div>
        <div class="panel m0">
          <div class="panel-head"><h3>Bouncers</h3><a href="#/infrastructure">Details</a></div>
          ${data.data_sources.bouncers === false ? '<div class="empty">Bouncer data unavailable</div>' : renderBouncersTable(data.bouncers.items.slice(0, 6))}
        </div>
      </div>
      ${metricsPanels}
    `, metrics ? '' : 'metrics offline')}

    ${!db ? '<p class="hint mt-16">LAPI database not readable: machine/bouncer and geo aggregates are limited. Set <code>data.db_path</code>.</p>' : ''}`;

  $('#onboarding-dismiss')?.addEventListener('click', () => {
    try { localStorage.setItem('cswebui.onboarding.dismissed', '1'); } catch { /* ignore */ }
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
  const badgeEl = $('.filter-count', box);
  if (badgeEl) badgeEl.textContent = count ? `${count} active` : '';
  box.toggleAttribute('open', count > 0);
}

// The checklist disappears once every step is done, or when dismissed.
function renderOnboarding(data) {
  let dismissed = false;
  try { dismissed = localStorage.getItem('cswebui.onboarding.dismissed') === '1'; } catch { /* ignore */ }
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

function chartTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderChart(points) {
  if (!points || points.length === 0) return '<div class="empty">No data</div>';

  const width = 800;
  const height = 170;
  const pad = 8;
  const max = Math.max(1, ...points.map((p) => p.count));
  const step = points.length > 1 ? (width - pad * 2) / (points.length - 1) : 0;

  const coords = points.map((point, index) => {
    const x = pad + index * step;
    const y = height - pad - (point.count / max) * (height - pad * 2);
    return [x, y];
  });

  const line = coords.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const area = `${line} L${coords[coords.length - 1][0].toFixed(1)},${height - pad} L${coords[0][0].toFixed(1)},${height - pad} Z`;
  const grid = [0.25, 0.5, 0.75].map((ratio) => {
    const y = (height - pad) - ratio * (height - pad * 2);
    return `<line x1="${pad}" y1="${y.toFixed(1)}" x2="${width - pad}" y2="${y.toFixed(1)}" stroke="currentColor" stroke-opacity="0.08" stroke-dasharray="3 4"/>`;
  }).join('');

  return `
    <svg class="chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Alerts over time">
      <defs>
        <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.28"/>
          <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.01"/>
        </linearGradient>
      </defs>
      ${grid}
      <path d="${area}" fill="url(#chart-fill)"/>
      <path d="${line}" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
    </svg>`;
}

function renderBarList(items, drilldown = null) {
  if (!items || items.length === 0) return '<div class="empty">No data</div>';

  const max = Math.max(1, ...items.map((item) => item.count));

  return `<div class="bar-list">${items.map((item) => `
    <div class="bar-row">
      ${drilldown ? `<a class="name" href="${esc(filteredLink(drilldown[0], drilldown[1], item.name))}">${esc(item.name)}</a>` : `<span class="name" title="${esc(item.name)}">${esc(item.name)}</span>`}
      <span class="count">${fmtNum(item.count)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(2, (item.count / max) * 100)}%"></div></div>
    </div>`).join('')}</div>`;
}

function renderAlertsTable(alerts, compact = false) {
  if (!alerts || alerts.length === 0) {
    return '<div class="empty">No alerts</div>';
  }

  const rows = alerts.map((alert) => `
    <tr class="clickable" data-alert-id="${alert.id}">
      <td class="nowrap" data-sort="${sortDate(alert.created_at)}" title="${esc(fmtDate(alert.created_at))}">${esc(relTime(alert.created_at))}</td>
      <td class="mono wrap-cell">${esc(alert.scenario)}</td>
      <td class="mono nowrap"><button class="table-link" aria-label="Open alert #${alert.id}: ${esc(alert.source_ip || alert.source_value || 'Details')}">${esc(alert.source_ip || alert.source_value || 'Details')}</button></td>
      <td class="col-country">${alert.source_country ? `<span class="flag">${flag(alert.source_country)}</span> ${esc(alert.source_country)}` : '—'}</td>
      ${compact ? '' : `<td class="col-scope">${esc(alert.source_scope)}</td>`}
      <td class="col-decisions">${alert.decisions}</td>
      <td class="col-events">${alert.events}</td>
      <td class="col-kind">${esc(alert.kind || '—')}</td>
    </tr>`).join('');

  return `<table class="list-table">
    <thead><tr>
      <th>When</th><th>Scenario</th><th>Source</th><th class="col-country">Country</th>${compact ? '' : '<th class="col-scope">Scope</th>'}<th class="col-decisions">Decisions</th><th class="col-events">Events</th><th class="col-kind">Kind</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

/* ---------------- alerts ---------------- */

async function renderAlerts() {
  const view = $('#view');
  view.innerHTML = `
    ${pageHeader('Alerts', 'Everything your scenarios detected.')}
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
          <div class="field"><button class="btn" type="submit">Apply</button></div>
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

    if (body) body.innerHTML = spinner();

    try {
      const data = await api(`/api/alerts?${params}`);
      if (id !== loadID || !body?.isConnected) return;
      state.cache.alerts = data.alerts;
      body.innerHTML = resultCount(data.alerts.length, Number(params.get('limit'))) + (data.alerts.length
        ? `<div class="table-wrap">${renderAlertsTable(data.alerts)}</div>`
        : '<div class="empty">No alerts match the filter</div>');
      enhanceTables(body);
      mountRefresh(data.generated_at || new Date().toISOString());
    } catch (error) {
      if (id === loadID && body?.isConnected && error.name !== 'AbortError') body.innerHTML = errorBox(error.message, true);
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
      ${decisions ? `<h4 class="modal-section">Decisions</h4><div class="table-wrap"><table>
        <thead><tr><th>Value</th><th>Scope</th><th>Type</th><th>Duration</th><th>Origin</th></tr></thead>
        <tbody>${decisions}</tbody></table></div>` : ''}
      <h4 class="modal-section">Events</h4>
      <pre class="json">${esc(JSON.stringify(alert.events || [], null, 2))}</pre>
      <div class="form-actions end">
        ${source.ip ? `<button class="btn secondary" data-inspect-ip="${esc(source.ip)}">Inspect IP</button>` : ''}
        <button class="btn secondary" id="alert-close">Close</button>
        <button class="btn danger" id="alert-delete"><svg class="btn-icon" viewBox="0 0 24 24"><use href="#i-trash"/></svg>Delete alert</button>
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

  const sources = [
    ['', 'All'],
    ['CAPI', 'Community'],
    ['lists', 'Lists'],
    ['crowdsec', 'Local'],
    ['cscli', 'Manual'],
  ];

  view.innerHTML = `
    ${pageHeader('Decisions', 'What your remediators enforce.', `
        <div class="chips" role="group" aria-label="Decision source">
          ${sources.map(([value, label]) => `<button type="button" class="chip" data-source="${value}">${label}</button>`).join('')}
        </div>
        <button class="btn" id="add-decision"><svg class="btn-icon" viewBox="0 0 24 24"><use href="#i-plus"/></svg>Add decision</button>`)}
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
          <div class="field"><button class="btn" type="submit">Apply</button></div>
        </form>
      ${filterPanelClose()}
    <div class="panel"><div id="decisions-body">${spinner()}</div></div>`;

  // One CAPI alert carries thousands of decisions, so rendering everything at
  // once cost seconds on every refresh. Page the rows and sort the data, not
  // the DOM, so sorting still covers rows that are not shown yet.
  const pageSize = 200;
  const page = { items: [], visible: pageSize, sortIndex: null, asc: true };
  let loadID = 0;

  const sorted = () => (page.sortIndex === null
    ? page.items
    : sortDecisions(page.items, page.sortIndex, page.asc));

  const markSourceChip = (origin) => {
    $$('.chips .chip').forEach((chip) => {
      chip.classList.toggle('active', (chip.dataset.source || '') === (origin || ''));
    });
  };

  const draw = () => {
    const body = $('#decisions-body');
    if (!body) return;
    const items = sorted();
    const slice = items.slice(0, page.visible);
    const byId = new Map(items.map((item) => [item.id, item]));

    body.innerHTML = items.length === 0
      ? '<div class="empty">No decisions</div>'
      : `${renderDecisionsTable(slice, true, { sortIndex: page.sortIndex, asc: page.asc })}
         <p class="result-count">Showing ${fmtNum(slice.length)} of ${fmtNum(items.length)}${page.sortIndex === null ? '' : ' · sorted'}</p>
         ${slice.length < items.length ? `<div class="table-tools"><button class="btn secondary" id="decisions-more" type="button">Show ${fmtNum(Math.min(pageSize, items.length - slice.length))} more</button></div>` : ''}`;

    $$('#decisions-body th[data-col]', body).forEach((th) => {
      $('button', th)?.addEventListener('click', () => {
        const index = Number(th.dataset.col);
        page.asc = page.sortIndex !== index ? true : !page.asc;
        page.sortIndex = index;
        draw();
      });
    });

    $('#decisions-more')?.addEventListener('click', () => {
      page.visible += pageSize;
      draw();
    });

    $$('#decisions-body tr[data-decision-id]', body).forEach((row) => {
      const button = $('button[data-delete]', row);
      if (!button) return;
      button.addEventListener('click', async (event) => {
        event.stopPropagation();
        await deleteDecision(byId.get(Number(row.dataset.decisionId)), load, button);
      });
    });
  };

  const load = async () => {
    const id = ++loadID;
    const params = new URLSearchParams();
    filterFields.decisions.map((key) => [key, `#d-${key}`]).forEach(([key, sel]) => {
      const value = $(sel)?.value.trim();
      if (value) params.set(key, value);
    });
    rememberFilters('decisions', params);
    updateFilterBadge('decisions');
    markSourceChip(params.get('origin'));

    const body = $('#decisions-body');
    if (body) body.innerHTML = spinner();

    try {
      const data = await api(`/api/decisions?${params}`);
      if (id !== loadID || !$('#decisions-body')?.isConnected) return;
      page.items = data.decisions || [];
      page.visible = pageSize;
      draw();
      mountRefresh(data.generated_at || new Date().toISOString());
    } catch (error) {
      if (id === loadID && error.name !== 'AbortError') {
        const body2 = $('#decisions-body');
        if (body2) body2.innerHTML = errorBox(error.message, true);
      }
    }
  };

  $('#decision-filters').addEventListener('submit', (event) => {
    event.preventDefault();
    load();
  });

  $$('.chips .chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      $('#d-origin').value = chip.dataset.source;
      load();
    });
  });

  $('#add-decision').addEventListener('click', () => showDecisionForm('local', load));

  Object.entries(state.filters.decisions).forEach(([key, value]) => { const input = $(`#d-${key}`); if (input) input.value = value; });
  markSourceChip(state.filters.decisions.origin || '');
  await load();
}

// The sort key belongs to the column, so renaming or reordering a column cannot
// silently sort by another field.
const decisionColumns = [
  { label: 'Value', cls: '', key: (d) => d.value },
  { label: 'Type', cls: '', key: (d) => d.type },
  { label: 'Country', cls: 'col-country', key: (d) => d.country || '' },
  { label: 'AS', cls: 'col-as', key: (d) => d.as_name || '' },
  { label: 'Expires', cls: '', key: (d) => sortDate(d.until) },
  { label: 'Scenario', cls: 'col-scenario', key: (d) => d.scenario || '' },
  { label: 'Origin', cls: 'col-origin', key: (d) => d.origin || '' },
  { label: 'Alert', cls: 'col-alert', key: (d) => d.alert_id || 0 },
];

function sortDecisions(items, index, ascending) {
  const { key } = decisionColumns[index] || {};
  if (!key) return items;
  const direction = ascending ? 1 : -1;
  return [...items].sort((a, b) => {
    const left = key(a);
    const right = key(b);
    if (typeof left === 'number' && typeof right === 'number') return (left - right) * direction;
    return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: 'base' }) * direction;
  });
}

function renderDecisionsTable(decisions, actionable = true, view = {}) {
  if (!decisions || decisions.length === 0) return '<div class="empty">No decisions</div>';

  const rows = decisions.map((decision) => `
    <tr data-decision-id="${decision.id}" data-origin="${esc(decision.origin)}">
      <td class="mono nowrap">${decision.scope === 'ip' ? `<button class="table-link" data-inspect-ip="${esc(decision.value)}">${esc(decision.value)}</button>` : `<span data-copy="${esc(decision.value)}" title="Click to copy">${esc(decision.value)}</span>`}${decision.scope === 'range' ? ' ' + badge('range', 'off') : ''}</td>
      <td class="nowrap">${typeBadge(decision.type)}${decision.simulated ? ' ' + badge('simulated', 'sim') : ''}</td>
      <td class="col-country">${decision.country ? `<span class="flag">${flag(decision.country)}</span> ${esc(decision.country)}` : '—'}</td>
      <td class="mono nowrap col-as" title="${esc(decision.as_name || '')}">${esc(decision.as_name || '—')}</td>
      <td class="mono" data-sort="${sortDate(decision.until)}" title="${esc(fmtDate(decision.until))}">${esc(fmtDuration(decision.duration))}</td>
      <td class="mono wrap-cell col-scenario">${esc(decision.scenario)}</td>
      <td class="mono col-origin">${esc(decision.origin)}</td>
      <td class="col-alert">${decision.alert_id ? `<button class="table-link" data-alert-id="${decision.alert_id}">#${decision.alert_id}</button>` : '—'}</td>${actionable ? '<td><button class="btn danger" data-delete type="button">Unban</button></td>' : ''}
    </tr>`).join('');

  const head = decisionColumns.map(({ label, cls }, index) => {
    const active = view.sortIndex === index;
    const sort = active ? (view.asc ? 'ascending' : 'descending') : null;
    return `<th data-col="${index}"${cls ? ` class="${cls}"` : ''}${sort ? ` aria-sort="${sort}"` : ''}><button class="table-sort" type="button" aria-label="Sort by ${esc(label)}">${esc(label)}</button></th>`;
  }).join('');

  return `<div class="table-wrap"><table class="list-table" data-no-enhance>
    <thead><tr>${head}${actionable ? '<th></th>' : ''}</tr></thead>
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
      <div class="field mt-16"><label for="n-reason">Reason</label><input id="n-reason" type="text" placeholder="manual ban from cswebui"></div>
      <div class="form-actions end">
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
    `${pageHeader('Allowlists', 'Never ban these values.', '<button class="btn" data-allowlist-create><svg class="btn-icon" viewBox="0 0 24 24"><use href="#i-plus"/></svg>Create allowlist</button>')}
     <div class="panel"><div id="allowlists-body">${spinner()}</div></div>`;

  let data;
  try {
    data = await api('/api/allowlists');
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    $('#allowlists-body').innerHTML = errorBox(error.message, true);
    return;
  }
  state.cache.updatedAt = data.generated_at;

  if (!data.allowlists.length) {
    $('#allowlists-body').innerHTML = '<div class="empty">No allowlists configured</div>';
    return;
  }

  $('#allowlists-body').innerHTML = `<div class="table-wrap"><table class="list-table">
      <thead><tr><th>Name</th><th class="col-desc">Description</th><th>Items</th><th class="col-managed">Managed by console</th></tr></thead>
      <tbody>${data.allowlists.map((list) => `
        <tr class="clickable" data-allowlist="${esc(list.name)}">
          <td class="mono"><button class="table-link">${esc(list.name)}</button></td>
          <td class="wrap col-desc">${esc(list.description)}</td>
          <td>${(list.items || []).length}</td>
          <td class="col-managed">${list.console_managed ? badge('console', 'warn') : badge('local', 'off')}</td>
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
      ${items ? `<div class="table-wrap mt-16"><table>
        <thead><tr><th>Value</th><th>Description</th><th>Expiration</th>${allowlist.console_managed ? '' : '<th></th>'}</tr></thead>
        <tbody>${items}</tbody></table></div>` : '<div class="empty">No items</div>'}
      ${allowlist.console_managed ? '<p class="hint mt-16">Managed by the CrowdSec Console; local editing is disabled.</p>' : `<div class="form-actions"><button class="btn" data-allowlist-add="${esc(name)}">Add entry</button><button class="btn danger" data-allowlist-remove data-allowlist-name="${esc(name)}">Delete allowlist</button></div>`}`);
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
    ${pageHeader('Shared blocklist', 'Decisions exchanged through your own blocklist server.', '<button class="btn" id="share-decision">Share decision</button>')}
    ${filterPanelOpen('blocklist')}<form id="blocklist-filters" class="form-grid">
      <div class="field"><label for="bl-value">Value</label><input id="bl-value" type="text"></div>
      <div class="field"><label for="bl-scenario">Scenario</label><input id="bl-scenario" type="text"></div>
      <div class="field"><label for="bl-limit">Limit</label><select id="bl-limit"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select></div>
      <div class="field"><button class="btn" type="submit">Apply</button></div></form>${filterPanelClose()}
    <div class="cards" id="blocklist-stats"></div>
    <div class="panel">
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
      <div class="card"><div class="label">Entries</div><div class="value">${fmtNum(stats.active_decisions)}</div></div>
      <div class="card"><div class="label">Engines</div><div class="value">${fmtNum(stats.machines)}</div></div>
      <div class="card"><div class="label">Revision</div><div class="value">${fmtNum(stats.revision)}</div></div>`;
  }

  const entries = (decisions.decisions || []).map((decision) => `
    <tr>
      <td class="mono">${esc(decision.value)}</td>
      <td>${esc(decision.scope)}</td>
      <td class="mono">${esc(decision.scenario)}</td>
      <td class="mono">${esc(fmtDuration(decision.duration))}</td>
      <td class="mono" data-sort="${sortDate(decision.until)}">${esc(fmtDate(decision.until))}</td>
      <td>${esc(decision.source)}</td>
      <td><button class="btn danger" data-blocklist-id="${decision.id}" type="button">Remove</button></td>
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
      <td class="mono">${esc(machine.last_ip)}</td>
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
    ${pageHeader('Configuration', 'Edit the engine configuration and reload it.', `
      <button class="btn secondary" id="config-check">Check saved config</button><button class="btn secondary" id="config-reload">Reload engine</button>`)}
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
    return { fill: 'transparent', opacity: 0 };
  }

  // Any country with data is clearly visible; the busiest one is near opaque.
  const ratio = count / Math.max(1, max);
  return { fill: 'var(--accent)', opacity: (0.18 + 0.62 * ratio).toFixed(3) };
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
      const { opacity } = mapIntensity(count, max);
      const className = count > 0 ? 'map-country has-data' : 'map-country';
      const style = count > 0 ? ` style="--intensity:${opacity}"` : '';
      return `<path class="${className}" d="${path}"${style}><title>${esc(title)}</title></path>`;
    }).join('');
  }

  // Small dots keep the exact cluster visible on top of the country shading.
  const dots = (geoPoints || []).map((point) => {
    const [x, y] = projectGeo(point.lat, point.lon);
    const label = point.country ? `${point.country}: ${point.count} alert(s)` : `${point.count} alert(s)`;
    return `<circle class="map-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="1.2"><title>${esc(label)}</title></circle>`;
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
    ${pageHeader('Geo', 'Where the detected sources are located.', `
      <select id="geo-range" aria-label="Time range">
        ${['6h', '24h', '7d', '30d'].map((r) => `<option value="${r}" ${r === state.range ? 'selected' : ''}>Last ${r}</option>`).join('')}
      </select>`)}
    <div id="geo-body">${spinner()}</div>`;

  $('#geo-range').addEventListener('change', (event) => {
    state.range = event.target.value;
    route();
  });

  const data = await api(`/api/overview?since=${encodeURIComponent(state.range)}`);
  const alerts = data.alerts;
  const countries = alerts.by_country || [];
  const topCountry = countries[0] ? `${flag(countries[0].name)} ${countries[0].name}` : '—';

  state.cache.updatedAt = data.generated_at;

  $('#geo-body').innerHTML = `
    <div class="cards">
      ${statCard(`Alerts (${state.range})`, fmtNum(alerts.total), `${fmtNum(alerts.events)} events`)}
      ${statCard('Countries', fmtNum(countries.length), 'distinct source countries')}
      ${statCard('Top country', topCountry, countries[0] ? `${fmtNum(countries[0].count)} alert(s)` : 'no geo data')}
      ${statCard('Locations', fmtNum((alerts.geo || []).length), 'map clusters')}
    </div>

    <div class="panel map-panel map-large">
      <div class="panel-head"><h3>Origin map</h3><span class="hint">GeoLite2 via the geoip-enrich parser</span></div>
      <div class="panel-body">${renderWorldMap(alerts.geo, countries)}</div>
    </div>

    <div class="grid-2">
      ${section('Top countries', renderCountryList(countries))}
      ${section('Top networks (AS)', renderBarList(alerts.by_as))}
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Recent alerts with geo</h3><a href="#/alerts">All alerts</a></div>
      <div class="table-wrap">${renderAlertsTable(data.recent_alerts, false)}</div>
    </div>`;
}

/* ---------------- infrastructure ---------------- */

async function renderInfrastructure() {
  const view = $('#view');

  view.innerHTML = `
    ${pageHeader('Infrastructure', 'Engines, bouncers and how they talk to the API.')}
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
      <td class="mono ellipsis" title="${esc(machine.machine_id)}">${esc(machine.machine_id)}</td>
      <td class="mono">${esc(machine.version || '—')}</td>
      <td>${esc([machine.osname, machine.osversion].filter(Boolean).join(' ') || '—')}</td>
      <td title="${esc(machine.scenarios || '')}">${(machine.scenarios || '').split(',').filter(Boolean).length}</td>
      <td data-sort="${sortDate(machine.last_heartbeat)}">${machine.last_heartbeat ? relTime(machine.last_heartbeat) : 'never'}</td>
      <td class="mono">${esc(machine.ip_address || '—')}</td>
      <td>${machine.validated ? badge('valid', 'ok') : badge('pending', 'warn')}</td>
    </tr>`).join('');

  const bouncerRows = infra.bouncers.map((bouncer) => `
    <tr>
      <td class="mono">${esc(bouncer.name)}</td>
      <td>${esc(bouncer.type || '—')}</td>
      <td class="mono">${esc(bouncer.version || '—')}</td>
      <td>${esc([bouncer.osname, bouncer.osversion].filter(Boolean).join(' ') || '—')}</td>
      <td class="mono">${esc(bouncer.ip_address || '—')}</td>
      <td data-sort="${sortDate(bouncer.last_pull)}">${bouncer.last_pull ? relTime(bouncer.last_pull) : 'never'}</td>
      <td>${bouncer.revoked ? badge('revoked', 'ban') : statusBadge(bouncer.last_pull && new Date(bouncer.last_pull).getTime() > cutoff, 'active', 'idle')}</td>
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

    <div class="panel">
      <div class="panel-head"><h3>Machines</h3><span class="hint">${infra.db ? 'from the LAPI database' : 'database not readable'}</span></div>
      ${!machinesAvailable ? errorBox(infra.errors?.machines || 'Machine data unavailable: configure a readable SQLite database.') : infra.machines.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Machine</th><th>Version</th><th>OS</th><th>Scenarios</th><th>Last seen</th><th>IP</th><th>State</th></tr></thead>
        <tbody>${machineRows}</tbody></table></div>` : '<div class="empty">No machines registered</div>'}
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Bouncers</h3></div>
      ${!bouncersAvailable ? errorBox(infra.errors?.bouncers || 'Bouncer data unavailable: configure a readable SQLite database.') : infra.bouncers.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Type</th><th>Version</th><th>OS</th><th>IP</th><th>Last pull</th><th>State</th></tr></thead>
        <tbody>${bouncerRows}</tbody></table></div>` : '<div class="empty">No bouncers registered</div>'}
    </div>

    <div class="grid-3">
      ${section('LAPI routes', renderBarList(metrics ? metrics.top_routes : []))}
      ${section('Chattiest machines', renderBarList(metrics ? metrics.top_machines : []))}
      ${section('Chattiest bouncers', renderBarList(metrics ? metrics.top_bouncers : []))}
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
    ${pageHeader('Metrics', 'Prometheus counters since the engine last reset them. Unparsed lines can be normal and are not automatically parser errors.', '<span class="hint" id="metrics-fetched"></span>')}
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
  $('#metrics-fetched').textContent = `${fmtNum(data.samples)} series`;

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
      ${section('Top parsers by hits', renderBarList(m.top_nodes))}
      ${section('Top parsers by unparsed lines', renderBarList(m.top_nodes_ko))}
    </div>

    <div class="grid-2">
      ${section('Active buckets', renderBarList(m.top_buckets))}
      ${section('Bucket overflows', renderBarList(m.top_overflows))}
    </div>

    <div class="panel">
      <div class="panel-head"><h3>Log source diagnostics</h3><span class="hint">— = metric not exported; zero activity can be normal</span></div>
      ${renderMetricRows(m.sources, [['read', 'Read'], ['parsed', 'Parsed'], ['unparsed', 'Unparsed'], ['poured', 'Poured into buckets'], ['allowlisted', 'Allowlisted']])}
    </div>
    ${m.appsec?.length || m.appsec_rules?.length ? `<div class="panel">
      <div class="panel-head"><h3>AppSec</h3><span class="hint">counters since reset</span></div>
      ${renderMetricRows(m.appsec, [['processed', 'Processed'], ['blocked', 'Blocked'], ['requested', 'Challenges requested'], ['accepted', 'Challenges accepted'], ['rejected', 'Challenges rejected']])}
      <div class="panel-body"><h4>Most triggered AppSec rules</h4>${renderBarList(m.appsec_rules)}</div></div>` : ''}
    <div class="grid-2">
      ${section('Acquisition sources', renderBarList(m.top_sources))}
      ${section('Pipeline health', `<dl class="kv m0">
            <dt>Postoverflow queue</dt><dd>${metricNumber(m, 'postoverflow_queue', 'cs_postoverflow_queue_depth')} waiting</dd>
            <dt>Postoverflow dropped</dt><dd>${metricNumber(m, 'postoverflow_dropped', 'cs_postoverflow_dropped_total')}</dd>
            <dt>Bucket pours</dt><dd>${metricNumber(m, 'bucket_poured', 'cs_bucket_poured_total')}</dd>
            <dt>CAPI errors</dt><dd>${metricNumber(m, 'capi_errors', 'cs_capi_errors_total')}</dd>
            <dt>Version</dt><dd class="mono">${esc(m.version || '—')}</dd>
          </dl>`)}
    </div>`;
}

/* ---------------- hub ---------------- */

const hubFilter = { search: '', category: '', installedOnly: true };

let hubData = null;

function hubBadges(item) {
  const itemState = item.enabled
    ? '<span class="badge ok">active</span>'
    : item.installed
      ? '<span class="badge warn">inactive</span>'
      : '<span class="badge off">not in use</span>';

  if (!item.tainted) return itemState;

  return `${itemState} <span class="badge warn" title="changed by hand: an upgrade leaves it alone">edited</span>`;
}

function hubBundles(item) {
  if (!item.dependencies) return '<span class="hint">—</span>';

  return Object.entries(item.dependencies).map(([kind, count]) => `${count} ${kind}`).join(', ');
}

function hubActionButton(category, item) {
  const path = item.enabled ? '/api/hub/remove' : '/api/hub/install';
  const label = item.enabled ? 'Remove' : item.installed ? 'Activate' : 'Install';

  return `<button class="btn ${item.enabled ? 'danger' : ''}" data-hub-action data-path="${path}" ` +
    `data-category="${esc(category)}" data-name="${esc(item.name)}">${label}</button>`;
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
      <div class="value compact">${status.index_missing ? 'missing' : esc(relTime(status.index_updated))}</div></div>
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
      <td class="hub-description"><span class="mono">${esc(item.name)}</span><div class="hub-inline">${hubBadges(item)}</div>${item.description ? `<div class="hint">${esc(item.description)}</div>` : ''}</td>
      <td class="col-type">${esc(item.category)}</td>
      <td class="mono col-version">${esc(item.local_version || (item.installed ? 'unknown' : '—'))} → ${esc(item.version || '—')}${item.update_available ? ' ' + badge('update available', 'warn') : ''}</td>
      <td class="col-state">${hubBadges(item)}</td>
      <td class="hint col-bundles">${hubBundles(item)}</td>
      <td class="col-actions"><div class="row-actions">${hubActionButton(item.category, item)}${item.update_available ? `<button class="btn secondary" data-hub-action data-path="/api/hub/upgrade" data-category="${esc(item.category)}" data-name="${esc(item.name)}">Upgrade</button>` : ''}</div></td>
    </tr>`).join('');

  $('#hub-items').innerHTML = rows
    ? `<div class="table-wrap hub-table"><table class="hub-list">
        <thead><tr><th>Item</th><th class="col-type">Type</th><th class="col-version">Installed → available</th><th class="col-state">State</th><th class="col-bundles">Bundles</th><th class="col-actions"></th></tr></thead>
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
    ${pageHeader('Hub', 'What the engine detects with: parsers, scenarios, contexts, collections.', `
        <button class="btn secondary" data-hub-update>Refresh index</button>
        <button class="btn secondary" data-hub-upgrade>Upgrade items</button>`)}
    <div class="cards" id="hub-summary">${spinner()}</div>
    <div class="panel">
      <div class="panel-head"><h3>Items</h3><span class="hint" id="hub-count"></span></div>
      <div class="panel-body">
        <div class="toolbar mb-14">
          <input type="text" id="hub-search" aria-label="Search hub items" placeholder="Filter by name or description" value="${esc(hubFilter.search)}" class="grow">
          <select id="hub-category" aria-label="Item type"></select>
          <label class="checkbox"><input type="checkbox" id="hub-installed" ${hubFilter.installedOnly ? 'checked' : ''}>Installed only</label>
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
    view.innerHTML = `${pageHeader('Hub', 'What the engine detects with.')}${errorBox(error.message, true)}`;

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
