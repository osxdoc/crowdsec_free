/* Console actions shared by the dashboard and list views. */
const filterFields = {
  alerts: ['scenario', 'ip', 'limit', 'since', 'origin', 'include_capi', 'kind'],
  decisions: ['ip', 'range', 'value', 'type', 'origin', 'scope', 'scenario', 'limit'],
  blocklist: ['value', 'scenario', 'limit'],
};
let refreshTimer = null;
let refreshInterval = 0;
let freshnessTimer = null;

function rememberFilters(kind, params) {
  state.filters[kind] = Object.fromEntries(params);
  state.hash = `#/${kind}?${params}`;
  history.replaceState(null, '', state.hash);
}

function filteredLink(kind, key, value) {
  const params = new URLSearchParams({ [key]: value });
  if (kind === 'alerts') params.set('since', state.range);
  return `#/${kind}?${params}`;
}

function freshness(iso) {
  return iso ? `Updated ${relTime(iso)} · ${fmtDate(iso)}` : 'Data timestamp unavailable';
}

function mountRefresh(iso) {
  clearTimeout(refreshTimer);
  clearTimeout(freshnessTimer);
  const toolbar = $('.page-header .toolbar') || $('.page-header');
  if (!toolbar || state.route === 'config' || state.route === 'inspect') return;
  $('.refresh-controls', toolbar)?.remove();
  const controls = document.createElement('div');
  controls.className = 'refresh-controls';
  controls.innerHTML = `
    <span class="hint" data-freshness>${esc(freshness(iso))}</span>
    <button class="icon-btn" data-refresh type="button" title="Refresh now" aria-label="Refresh now">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/></svg>
    </button>
    <details class="menu" data-auto-menu>
      <summary class="icon-btn" title="Auto refresh" aria-label="Auto refresh">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
      </summary>
      <div class="menu-body">
        <label for="auto-refresh">Auto refresh</label>
        <select aria-label="Auto refresh interval" id="auto-refresh">
          ${[[0, 'Off'], [30, '30 seconds'], [60, '1 minute'], [300, '5 minutes']].map(([value, label]) => `<option value="${value}" ${refreshInterval === value ? 'selected' : ''}>${label}</option>`).join('')}
        </select>
      </div>
    </details>`;
  toolbar.appendChild(controls);
  const updateTime = () => {
    if (!controls.isConnected || !state.user) return;
    $('[data-freshness]', controls).textContent = freshness(iso);
    freshnessTimer = setTimeout(updateTime, 10000);
  };
  updateTime();
  $('[data-refresh]', controls).addEventListener('click', route);
  $('#auto-refresh', controls).addEventListener('change', (event) => {
    refreshInterval = Number(event.target.value);
    scheduleRefresh();
    $('[data-auto-menu]', controls).removeAttribute('open');
  });
  scheduleRefresh();
}

function scheduleRefresh() {
  clearTimeout(refreshTimer);
  if (!refreshInterval || !state.user || ['config', 'inspect'].includes(state.route)) return;
  refreshTimer = setTimeout(() => {
    if (!state.user) return;
    const active = document.activeElement;
    if (!document.hidden && !$('#modal-root dialog') && !active?.closest('input, select, textarea, form') && !hubBusy) route();
    else scheduleRefresh();
  }, refreshInterval * 1000);
}

function csvCell(value) {
  let text = String(value ?? '').trim();
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function sortDate(iso) {
  const timestamp = iso && !iso.startsWith('0001') ? Date.parse(iso) : NaN;
  return Number.isFinite(timestamp) ? timestamp : Number.MAX_SAFE_INTEGER;
}

function enhanceTables(root = $('#view')) {
  $$('table', root).forEach((table) => {
    if (table.dataset.tools || table.hasAttribute('data-no-enhance')) return;
    table.dataset.tools = 'true';
    $$('thead th', table).forEach((th, index) => {
      const label = th.textContent.trim();
      if (!label) return;
      const button = document.createElement('button');
      button.className = 'table-sort';
      button.textContent = label;
      button.setAttribute('aria-label', `Sort by ${label}`);
      button.addEventListener('click', () => {
        const ascending = th.getAttribute('aria-sort') !== 'ascending';
        $$('th', table).forEach((header) => header.removeAttribute('aria-sort'));
        th.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
        const rows = $$('tbody tr', table);
        rows.sort((a, b) => {
          const left = a.cells[index]?.dataset.sort ?? a.cells[index]?.textContent.trim() ?? '';
          const right = b.cells[index]?.dataset.sort ?? b.cells[index]?.textContent.trim() ?? '';
          const numeric = a.cells[index]?.dataset.sort != null && b.cells[index]?.dataset.sort != null && Number.isFinite(Number(left)) && Number.isFinite(Number(right));
          const result = numeric ? Number(left) - Number(right) : String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: 'base' });
          return ascending ? result : -result;
        });
        $('tbody', table).replaceChildren(...rows);
      });
      th.replaceChildren(button);
    });
    const tools = document.createElement('div');
    tools.className = 'table-tools';
    const exportButton = document.createElement('button');
    exportButton.className = 'btn secondary';
    exportButton.textContent = `Export ${$$('tbody tr', table).length} displayed rows (CSV)`;
    exportButton.addEventListener('click', () => {
      const csv = $$('tr', table).map((row) => Array.from(row.cells).map((cell) => csvCell(cell.textContent)).join(',')).join('\r\n');
      const url = URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url; link.download = `crowdsec-${state.route}.csv`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    tools.appendChild(exportButton);
    (table.closest('.table-wrap') || table).before(tools);
  });
}

function metricNumber(summary, key, metric) {
  return summary.present && !summary.present[metric] ? '—' : fmtNum(summary[key]);
}

function renderMetricRows(rows, columns) {
  if (!rows?.length) return '<div class="empty">No source metrics exported</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Source / engine</th>${columns.map(([, label]) => `<th>${esc(label)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map((row) => `<tr><td class="mono wrap">${esc(row.name)}</td>${columns.map(([key]) => `<td${row.values[key] == null ? '' : ` data-sort="${row.values[key]}"`}>${row.values[key] == null ? '—' : fmtNum(row.values[key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

function renderHealth(data) {
  if (!data.health) return '';
  const names = { lapi: 'Local API', database: 'Database', metrics: 'Metrics', blocklist: 'Blocklist server' };
  return `<div class="panel health-panel"><div class="panel-head"><h3>Service health</h3><span class="hint">${esc(freshness(data.generated_at))}</span></div>
    <div class="health-grid">${Object.entries(data.health).map(([name, health]) => `<div><strong>${esc(names[name] || name)}</strong>
      ${badge(health.state.replaceAll('_', ' '), health.state === 'ok' ? 'ok' : health.state === 'not_configured' ? 'off' : 'warn')}
      ${health.detail ? `<p class="hint">${esc(health.detail)}</p>` : ''}</div>`).join('')}</div>
    <p class="hint panel-note">Alert aggregates: ${esc(data.alert_source || 'unknown')}${data.alert_source === 'api' ? ' · based on at most 1,000 matching alerts; not a guaranteed full total' : ''}${data.alerts_limited ? ' · limit reached' : ''}. Prometheus counters accumulate until the engine resets them; they do not use the alert time range.</p></div>`;
}

function resultCount(count, limit, limited = count >= limit) {
  return `<p class="hint result-count" role="status">${fmtNum(count)} shown · retrieval limit ${fmtNum(limit)}${limited ? ' · limit reached; refine the filters to find other entries' : ''}</p>`;
}

function configDiff(before, after) {
  if (before === after) return 'No changes';
  const a = before.split('\n'), b = after.split('\n');
  let start = 0, end = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  while (end < a.length - start && end < b.length - start && a[a.length - end - 1] === b[b.length - end - 1]) end++;
  return [
    ...a.slice(Math.max(0, start - 3), start).map((line) => `  ${line}`),
    ...a.slice(start, a.length - end).map((line) => `- ${line}`),
    ...b.slice(start, b.length - end).map((line) => `+ ${line}`),
    ...a.slice(a.length - end, a.length - end + 3).map((line) => `  ${line}`),
  ].join('\n');
}

async function checkSavedConfig() {
  if (isDirty()) { toast('Save your changes before checking the engine configuration.', 'error'); return; }
  const button = $('#config-check');
  const editor = $('#config-editor');
  button.disabled = true;
  $('#config-reload').disabled = true;
  try {
    const result = await api('/api/config/check', { method: 'POST', body: {} });
    if (!editor.isConnected) return;
    if (!isDirty()) $('#config-status').textContent = result.message;
    openModal('Engine configuration check', `<p>${esc(result.message)}</p><pre class="json">${esc(result.output || 'Check completed without errors.')}</pre>`);
    if (editor.isConnected) $('#config-reload').disabled = isDirty();
  } catch (error) {
    if (editor.isConnected) $('#config-status').textContent = 'Validation failed · review the configuration before reloading';
    toast(error.message, 'error');
  } finally { button.disabled = editor.isConnected && isDirty(); }
}

async function renderInspect() {
  const ip = new URLSearchParams(location.hash.split('?')[1] || '').get('ip') || '';
  $('#view').innerHTML = `<div class="page-header"><div><h2>IP lookup</h2><p>Alerts, active decisions and allowlist matches, including ranges containing this IP.</p></div></div>
    <div class="panel"><div class="panel-body"><form id="ip-lookup" class="toolbar"><label for="inspect-ip">IP address</label><input id="inspect-ip" type="text" value="${esc(ip)}" placeholder="192.0.2.1 or 2001:db8::1" required><button class="btn">Inspect</button></form></div></div><div id="inspect-body"></div>`;
  $('#ip-lookup').addEventListener('submit', (event) => {
    event.preventDefault();
    const hash = `#/inspect?${new URLSearchParams({ ip: $('#inspect-ip').value.trim() })}`;
    if (location.hash === hash) route(); else location.hash = hash;
  });
  if (!ip) return;
  $('#inspect-body').innerHTML = spinner();
  const data = await api(`/api/inspect?${new URLSearchParams({ ip })}`);
  $('#inspect-body').innerHTML = `<p class="hint">${esc(freshness(data.generated_at))}</p>
    <div class="panel" style="margin-top:14px"><div class="panel-head"><h3>Allowlist match</h3></div><div class="panel-body">${data.errors.allowlist ? errorBox(data.errors.allowlist) : `${badge(data.allowlist?.allowlisted ? 'allowlisted' : 'no match', data.allowlist?.allowlisted ? 'ok' : '')} <span>${esc(data.allowlist?.reason || '')}</span>`}</div></div>
    <div class="panel" style="margin-top:14px"><div class="panel-head"><h3>Active decisions</h3></div>${data.errors.decisions ? errorBox(data.errors.decisions) : renderDecisionsTable(data.decisions, false) + resultCount(data.decisions.length, data.limit, data.decisions_limited)}</div>
    <div class="panel" style="margin-top:14px"><div class="panel-head"><h3>Matching alerts</h3></div>${data.errors.alerts ? errorBox(data.errors.alerts) : `<div class="table-wrap">${renderAlertsTable(data.alerts)}</div>${resultCount(data.alerts.length, data.limit, data.alerts_limited)}`}</div>`;
}

function showAllowlistForm(name = null) {
  openModal(name ? `Add entry to ${name}` : 'Create allowlist', `<form id="allowlist-form">
    ${name ? `<div class="field"><label for="al-value">IP or CIDR range</label><input id="al-value" type="text" required autofocus></div>
      <div class="field"><label for="al-duration">Duration (empty = permanent)</label><input id="al-duration" type="text" placeholder="7d"></div>` : '<div class="field"><label for="al-name">Name</label><input id="al-name" type="text" maxlength="128" required autofocus></div>'}
    <div class="field"><label for="al-description">${name ? 'Comment' : 'Description'}</label><input id="al-description" type="text" maxlength="1024" ${name ? '' : 'required'}></div>
    <p class="hint">${name ? 'Matching existing decisions will be removed immediately. No engine reload is needed.' : 'Create a local allowlist. Console-managed lists remain read-only.'}</p>
    <div class="form-actions"><button class="btn" type="submit">${name ? 'Add entry' : 'Create'}</button></div></form>`, () => {
    $('#allowlist-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = $('button[type="submit"]', form);
      if (button.disabled) return;
      button.disabled = true;
      try {
        const body = { description: $('#al-description').value.trim() };
        if (name) { body.value = $('#al-value').value.trim(); body.duration = $('#al-duration').value.trim(); }
        else body.name = $('#al-name').value.trim();
        const result = await api(name ? `/api/allowlists/${encodeURIComponent(name)}/items` : '/api/allowlists', { method: 'POST', body });
        if (form.isConnected) closeModal();
        toast(result.output || result.message || 'Allowlist updated', 'ok');
        if (state.route === 'allowlists') route();
      } catch (error) { toast(error.message, 'error'); }
      finally { button.disabled = false; }
    });
  });
}

async function removeAllowlistEntry(button) {
  const name = button.dataset.allowlistName;
  const value = button.dataset.allowlistValue;
  if (!confirm(value ? `Remove ${value} from ${name}?` : `Delete allowlist ${name} and all its entries?`)) return;
  button.disabled = true;
  const modal = button.closest('dialog');
  try {
    await api(`/api/allowlists/${encodeURIComponent(name)}${value ? '/items' : ''}`, { method: 'DELETE', ...(value ? { body: { value } } : {}) });
    if (modal?.isConnected) closeModal();
    toast('Allowlist updated', 'ok');
    if (state.route === 'allowlists') route();
  } catch (error) { toast(error.message, 'error'); }
  finally { button.disabled = false; }
}

function handleConsoleAction(event) {
  const target = event.target.closest('[data-inspect-ip], [data-allowlist-create], [data-allowlist-add], [data-allowlist-remove], [data-config-preview]');
  if (!target) return;
  if (target.hasAttribute('data-inspect-ip')) {
    const hash = `#/inspect?${new URLSearchParams({ ip: target.dataset.inspectIp })}`;
    if (location.hash === hash) route(); else location.hash = hash;
  } else if (target.hasAttribute('data-allowlist-create')) showAllowlistForm();
  else if (target.hasAttribute('data-allowlist-add')) showAllowlistForm(target.dataset.allowlistAdd);
  else if (target.hasAttribute('data-allowlist-remove')) removeAllowlistEntry(target);
  else if (target.hasAttribute('data-config-preview')) openModal(`Changes · ${currentConfig.name || 'configuration'}`, `<p class="hint">− original content when opened · + current draft. Review before saving.</p><pre class="json config-diff">${esc(configDiff(currentConfig.content, $('#config-editor').value))}</pre>`);
}
