// Run with: node --test pkg/webui/frontend_test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('assets/operations.js', import.meta.url), 'utf8') + '\n' + readFileSync(new URL('assets/app.js', import.meta.url), 'utf8').replace(/\nboot\(\);\s*$/, '\n');

function ui(options = {}) {
  const elements = new Map();
  const groups = new Map();
  const listenerSink = [];
  const windowListeners = [];
  const element = (selector, value = '') => {
    const node = {
      value, disabled: false, isConnected: true, innerHTML: '', textContent: '', dataset: {},
      listeners: {}, attributes: {},
      classList: {
        tokens: new Set(),
        add(token) { this.tokens.add(token); },
        remove(token) { this.tokens.delete(token); },
        contains(token) { return this.tokens.has(token); },
        toggle(token, force) {
          const next = force ?? !this.tokens.has(token);
          if (next) this.tokens.add(token); else this.tokens.delete(token);
          return next;
        },
      },
      addEventListener(name, fn) { this.listeners[name] = fn; },
      setAttribute(name, val) { this.attributes[name] = val; },
      getAttribute(name) { return this.attributes[name]; },
      removeAttribute(name) { delete this.attributes[name]; },
      querySelector(selector) { return elements.get(selector) || null; },
      querySelectorAll(selector) { return groups.get(selector) || []; },
      focus() {},
    };
    elements.set(selector, node);
    return node;
  };
  for (const selector of ['#login-form', '#logout', '#nav-toggle', '.sidebar', '.skip-link', '#view', '#modal-root']) element(selector);
  const context = vm.createContext({
    AbortController, URLSearchParams, console, setTimeout, clearTimeout,
    location: { hash: '#/config' },
    history: { replaceState(_state, _title, hash) { context.location.hash = hash; } },
    window: {
      addEventListener(name, fn) { windowListeners.push({ name, fn }); },
      matchMedia: options.matchMedia,
    },
    localStorage: options.storage,
    document: {
      addEventListener(name, fn) { listenerSink.push({ name, fn }); },
      documentElement: options.documentElement,
      querySelector: (selector) => elements.get(selector) || null,
      querySelectorAll: (selector) => groups.get(selector) || [],
    },
    confirm: () => false,
    ...options.globals,
  });
  if (options.seed) options.seed(element, elements);
  const run = (code) => vm.runInContext(code, context);
  run(source);
  // The browser dispatches a key event to every registered listener; tests must
  // do the same, otherwise adding a handler silently changes which one "wins".
  const pressKey = (event) => {
    for (const listener of windowListeners) {
      if (listener.name === 'keydown') listener.fn(event);
    }
  };
  return { element, elements, groups, context, run, documentListeners: listenerSink, windowListeners, pressKey };
}

test('configuration navigation asks before discarding edits', async (t) => {
  for (const allowed of [false, true]) {
    await t.test(allowed ? 'discard confirmed' : 'discard cancelled', () => {
      const { element, context, run } = ui();
      const editor = element('#config-editor', 'edited');
      context.confirm = () => allowed;
      run(`currentConfig = { name: 'config.yaml', content: 'saved' };
        state.hash = '#/config'; state.user = 'admin';
        routes.alerts = async () => { state.rendered = true; };
        location.hash = '#/alerts'; route();`);
      assert.equal(run('state.rendered === true'), allowed);
      assert.equal(context.location.hash, allowed ? '#/alerts' : '#/config');
      assert.equal(editor.value, 'edited');
    });
  }
});

test('reselecting the current config file cannot silently overwrite edits', async () => {
  const { element, run } = ui();
  const editor = element('#config-editor', 'edited');
  run(`currentConfig = { name: 'config.yaml', content: 'saved' };
    api = async () => { throw new Error('must not fetch'); };`);
  await run(`loadConfigFile('config.yaml')`);
  assert.equal(editor.value, 'edited');
});

test('signing out can be cancelled when the editor has unsaved changes', async () => {
  const { element, elements, run } = ui();
  element('#config-editor', 'edited');
  run(`currentConfig = { name: 'config.yaml', content: 'saved' };
    state.user = 'admin'; api = async () => { throw new Error('must not log out'); };`);
  await elements.get('#logout').listeners.click();
  assert.equal(run('state.user'), 'admin');
});

test('blocklist API failures are never presented as empty lists', async (t) => {
  for (const resource of ['decisions', 'machines']) {
    await t.test(resource, async () => {
      const { element, run } = ui();
      for (const id of ['#share-decision', '#blocklist-stats', '#blocklist-decisions', '#blocklist-count', '#blocklist-machines']) element(id);
      run(`api = async (path) => {
        if (path.split('?')[0].endsWith('/${resource}')) throw new Error('Service unavailable');
        return { active_decisions: 0, machines: [], decisions: [] };
      };`);
      await run('renderBlocklist()');
      assert.match(run(`$('#blocklist-${resource}').innerHTML`), /Service unavailable/);
      assert.match(run(`$('#blocklist-${resource}').innerHTML`), /data-retry/);
      assert.doesNotMatch(run(`$('#blocklist-${resource}').innerHTML`), /No shared decisions|No engine registered/);
    });
  }
});

test('hub actions restore controls after success and failure without locking sign out', async (t) => {
  for (const fails of [false, true]) {
    await t.test(fails ? 'API failure' : 'success', async () => {
      const { element, elements, groups, context, run } = ui();
      const button = element('#hub-install');
      const previouslyDisabled = element('#previously-disabled');
      previouslyDisabled.disabled = true;
      groups.set('button, input, select', [button, previouslyDisabled]);
      context.job = new Promise((resolve, reject) => {
        context.finish = () => fails ? reject(new Error('Failed')) : resolve({ message: 'Done' });
      });
      run(`state.user = 'admin'; state.route = 'hub'; state.refreshes = 0;
        toast = () => {}; route = () => { state.refreshes++; }; api = () => job;`);
      const pending = run(`hubAction('/api/hub/install', {}, $('#hub-install'))`);
      assert.equal(button.disabled, true);
      assert.equal(elements.get('#logout').disabled, false);
      context.finish();
      await pending;
      assert.equal(button.disabled, false);
      assert.equal(previouslyDisabled.disabled, true);
      assert.equal(run('state.refreshes'), 1);
    });
  }
});

test('finishing a hub action after navigation does not reopen the hub', async () => {
  const { context, run } = ui();
  context.job = new Promise((resolve) => { context.finish = resolve; });
  run(`state.user = 'admin'; state.route = 'hub'; toast = () => {};
    route = () => { throw new Error('must not navigate'); }; api = () => job;`);
  const pending = run(`hubAction('/api/hub/update', {})`);
  run(`state.route = 'alerts'`);
  context.finish({ message: 'Done' });
  await pending;
});

test('decision filters survive rendering and unban refreshes the filtered results', async () => {
  const { element, context, run } = ui();
  for (const id of ['#d-ip', '#d-range', '#d-value', '#d-type', '#decisions-body', '#decision-filters', '#add-decision']) element(id);
  const button = element('#unban');
  context.confirm = () => true;
  run(`state.filters.decisions = { ip: '192.0.2.1', type: 'ban' };
    state.requests = []; toast = () => {};
    api = async (path) => { state.requests.push(path); return { decisions: [] }; };`);
  await run('renderDecisions()');
  assert.equal(run(`$('#d-ip').value`), '192.0.2.1');
  assert.match(run('state.requests[0]'), /ip=192.0.2.1&type=ban/);
  run(`route = () => { throw new Error('must refresh in place'); };
    state.refreshed = false;
    state.toasts = [];
    toast = (message, kind, action) => { state.toasts.push({ message, kind, action }); };`);
  await run(`deleteDecision({ id: 42, value: '192.0.2.1', scope: 'ip', type: 'ban', duration: '4h' },
    async () => { state.refreshed = true; }, $('#unban'))`);
  assert.equal(run('state.refreshed'), true);
  assert.equal(run(`$('#d-ip').value`), '192.0.2.1');
  assert.equal(button.disabled, false);
  assert.equal(run('state.toasts[0].action.label'), 'Undo');

  await run('state.toasts[0].action.onClick()');
  assert.match(run('state.requests[state.requests.length - 1]'), /^\/api\/decisions$/);
});

test('navigation aborts stale reads so they cannot populate the new view', async () => {
  const { context, run } = ui();
  context.fetch = async () => ({
    text: () => new Promise((resolve) => { context.finish = () => resolve('{}'); }),
    status: 200, ok: true,
  });
  const pending = run(`api('/api/alerts')`);
  await new Promise(setImmediate);
  run(`viewController.abort(); viewController = new AbortController();`);
  context.finish();
  await assert.rejects(pending, { name: 'AbortError' });
});

test('config saves lock conflicting controls and keep failed edits retryable', async (t) => {
  for (const fails of [false, true]) {
    await t.test(fails ? 'save fails' : 'save succeeds', async () => {
      const { element, groups, context, run } = ui();
      const editor = element('#config-editor', 'name: edited');
      const save = element('#config-save');
      const reload = element('#config-reload');
      const file = element('#config-file');
      element('#config-status');
      groups.set('#config-files button', [file]);
      context.job = new Promise((resolve, reject) => {
        context.finish = () => fails ? reject(new Error('Save failed')) : resolve({});
      });
      run(`currentConfig = { name: 'config.yaml', content: 'name: original' };
        toast = () => {}; api = (path, options) => { state.savedRequest = options.body.content; return job; };`);
      const pending = run('saveConfigFile()');
      assert.equal(editor.disabled, true);
      assert.equal(save.disabled, true);
      assert.equal(reload.disabled, true);
      assert.equal(file.disabled, true);
      context.finish();
      await pending;
      assert.equal(run('state.savedRequest'), 'name: edited');
      assert.equal(run('currentConfig.content'), fails ? 'name: original' : 'name: edited');
      assert.equal(editor.value, 'name: edited');
      assert.equal(editor.disabled, false);
      assert.equal(file.disabled, false);
      assert.equal(save.disabled, !fails);
      assert.equal(reload.disabled, fails);
    });
  }
});

test('failed config file loading restores controls and retains the current contents', async () => {
  const { element, groups, run } = ui();
  const editor = element('#config-editor', 'name: original');
  const file = element('#config-file');
  element('#config-save');
  groups.set('#config-files button', [file]);
  run(`currentConfig = { name: 'config.yaml', content: 'name: original' };
    api = async () => { throw new Error('Load failed'); };`);
  await assert.rejects(run(`loadConfigFile('profiles.yaml')`), /Load failed/);
  assert.equal(editor.value, 'name: original');
  assert.equal(editor.disabled, false);
  assert.equal(file.disabled, false);
  assert.equal(run('currentConfig.name'), 'config.yaml');
});

test('out-of-order filter responses cannot overwrite newer results', async (t) => {
  for (const kind of ['alerts', 'decisions']) {
    for (const fails of [false, true]) {
      await t.test(`${kind}: stale ${fails ? 'failure' : 'success'}`, async () => {
        const { element, elements, context, run } = ui();
        const prefix = kind === 'alerts' ? 'f' : 'd';
        const fields = kind === 'alerts'
          ? ['scenario', 'ip', 'limit', 'value', 'contains', 'decision_type', 'has_active_decision']
          : ['ip', 'range', 'value', 'type'];
        for (const field of fields) element(`#${prefix}-${field}`, field === 'limit' ? '100' : '');
        for (const id of [`#${kind}-body`, kind === 'alerts' ? '#alert-filters' : '#decision-filters', '#add-decision']) element(id);
        context.pending = [];
        run(`api = () => new Promise((resolve, reject) => pending.push({ resolve, reject }));`);
        const initial = run(kind === 'alerts' ? 'renderAlerts()' : 'renderDecisions()');
        elements.get(`#${prefix}-ip`).value = '192.0.2.1';
        elements.get(kind === 'alerts' ? '#alert-filters' : '#decision-filters').listeners.submit({ preventDefault() {} });
        const response = (value) => ({ [kind]: [{ id: 1, source_ip: value, value, origin: 'cscli', type: 'ban' }] });
        context.pending[1].resolve(response('new-result'));
        await new Promise(setImmediate);
        if (fails) context.pending[0].reject(new Error('Old request failed'));
        else context.pending[0].resolve(response('old-result'));
        await initial;
        const html = elements.get(`#${kind}-body`).innerHTML;
        assert.match(html, /new-result/);
        assert.doesNotMatch(html, /old-result|Old request failed/);
      });
    }
  }
});

test('CSV exports quote fields and neutralize spreadsheet formulas', async (t) => {
  const { run, context } = ui();
  for (const [input, expected] of [
    ['normal', '"normal"'], ['a,"b"', '"a,""b"""'], ['=SUM(A1:A2)', '"\'=SUM(A1:A2)"'],
    [' +cmd', '"\'+cmd"'], ['-2+3', '"\'-2+3"'], ['@SUM(A1)', '"\'@SUM(A1)"'],
  ]) {
    await t.test(input, () => { context.input = input; assert.equal(run('csvCell(input)'), expected); });
  }
});

test('configuration review includes removed and added content with context', async (t) => {
  const { run, context } = ui();
  for (const [before, after, expected] of [
    ['same', 'same', 'No changes'],
    ['first\nold\nlast', 'first\nnew\nlast', '  first\n- old\n+ new\n  last'],
    ['a', 'a\nb', '  a\n+ b'],
    ['a\nb', 'a', '  a\n- b'],
    ['', '<script>', '- \n+ <script>'],
  ]) {
    await t.test(`${before} → ${after}`, () => {
      context.before = before; context.after = after;
      assert.equal(run('configDiff(before, after)'), expected);
    });
  }
});

test('missing metrics remain distinct from exported zero counters', () => {
  const { run } = ui();
  assert.equal(run(`metricNumber({ present: {}, parser_ko: 0 }, 'parser_ko', 'cs_parser_hits_ko_total')`), '—');
  assert.equal(run(`metricNumber({ present: { cs_parser_hits_ko_total: true }, parser_ko: 0 }, 'parser_ko', 'cs_parser_hits_ko_total')`), '0');
  const html = run(`renderMetricRows([{ name: '<source>', values: { read: 0 } }], [['read','Read'],['parsed','Parsed']])`);
  assert.match(html, /&lt;source&gt;/);
  assert.match(html, /<td data-sort="0">0<\/td><td>—<\/td>/);
});

test('drilldown URLs carry the selected time range and only supported filters are restored', async () => {
  const { run, context } = ui();
  assert.equal(run(`state.range = '6h'; filteredLink('alerts', 'scenario', 'author/name & test')`), '#/alerts?scenario=author%2Fname+%26+test&since=6h');
  context.location.hash = '#/alerts?scenario=author%2Fname&since=6h&unknown=value';
  await run(`routes.alerts = async () => {}; route();`);
  assert.equal(run('state.filters.alerts.scenario'), 'author/name');
  assert.equal(run('state.filters.alerts.since'), '6h');
  assert.equal(run(`'unknown' in state.filters.alerts`), false);
});

test('automatic refresh pauses for hidden pages, forms, dialogs and hub changes', async (t) => {
  for (const reason of ['none', 'hidden', 'form', 'dialog', 'hub', 'config', 'inspect', 'off']) {
    await t.test(reason, () => {
      const { run, context, element } = ui();
      const timers = [];
      context.setTimeout = (callback) => { timers.push(callback); return timers.length; };
      context.clearTimeout = () => {};
      context.document.hidden = reason === 'hidden';
      context.document.activeElement = { closest: () => reason === 'form' ? {} : null };
      if (reason === 'dialog') element('#modal-root dialog');
      run(`state.user = 'admin'; state.route = '${['config','inspect'].includes(reason) ? reason : 'dashboard'}';
        refreshInterval = ${reason === 'off' ? 0 : 30}; hubBusy = ${reason === 'hub'};
        state.refreshes = 0; route = () => { state.refreshes++; }; scheduleRefresh();`);
      if (['config','inspect','off'].includes(reason)) { assert.equal(timers.length, 0); return; }
      timers[0]();
      assert.equal(run('state.refreshes'), reason === 'none' ? 1 : 0);
      assert.equal(timers.length, reason === 'none' ? 1 : 2);
    });
  }
});

test('a queued refresh does not fetch after sign out', () => {
  const { run, context } = ui();
  let queued;
  context.setTimeout = (callback) => { queued = callback; return 1; };
  context.clearTimeout = () => {};
  run(`state.user = 'admin'; state.route = 'dashboard'; refreshInterval = 30;
    route = () => { throw new Error('must not refresh after logout'); }; scheduleRefresh(); state.user = null;`);
  queued();
});

test('notifications remain dismissible and cannot cover the page with an unbounded stack', () => {
  const { run, context, element } = ui();
  const region = element('#toasts');
  region.children = [];
  region.appendChild = (node) => { region.children.push(node); node.parent = region; };
  region.querySelectorAll = () => region.children;
  context.document.createElement = () => ({
    children: [], listeners: {}, attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
    appendChild(node) { this.children.push(node); },
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); },
  });
  context.setTimeout = () => 1;
  run(`for (let i = 0; i < 8; i++) toast('Message ' + i);`);
  assert.deepEqual(region.children.map((node) => node.textContent), ['Message 5','Message 6','Message 7']);
  const dismiss = region.children[0].children[0];
  assert.equal(dismiss.attributes['aria-label'], 'Dismiss notification');
  dismiss.listeners.click();
  assert.equal(region.children.length, 2);
});

test('date sorting uses timestamps and puts missing or permanent expiry after real dates', () => {
  const { run } = ui();
  assert.equal(run(`sortDate('1970-01-01T00:00:00Z')`), 0);
  assert.equal(run(`sortDate('2026-01-01T00:00:00Z') < sortDate('2026-02-01T00:00:00Z')`), true);
  for (const value of ['', '0001-01-01T00:00:00Z', 'invalid']) {
    assert.equal(run(`sortDate(${JSON.stringify(value)})`), Number.MAX_SAFE_INTEGER);
  }
});

test('each decisions column sorts by the field it displays', () => {
  const { run } = ui();
  run(`state.items = [
    { value: '10.0.0.9', type: 'captcha', country: 'DE', as_name: 'Zeta', until: '2026-03-01T00:00:00Z', scenario: 'b/second', origin: 'cscli', alert_id: 7 },
    { value: '10.0.0.10', type: 'ban', country: 'AT', as_name: 'Alpha', until: '2026-01-01T00:00:00Z', scenario: 'a/first', origin: 'CAPI', alert_id: 3 },
  ];`);
  const order = (index, ascending) => run(
    `sortDecisions(state.items.slice(), ${index}, ${ascending}).map((d) => d.value).join(',')`,
  );
  // Column labels come from the table header order; index 1 is "Type".
  assert.match(run(`decisionColumns[1].label`), /^Type$/);
  assert.equal(order(1, true), '10.0.0.10,10.0.0.9');
  assert.equal(order(1, false), '10.0.0.9,10.0.0.10');
  assert.equal(order(0, true), '10.0.0.9,10.0.0.10', 'IP segments compare numerically, not lexicographically');
  assert.equal(order(4, true), '10.0.0.10,10.0.0.9', 'expiry sorts by timestamp');
  assert.equal(order(5, true), '10.0.0.10,10.0.0.9', 'scenario sorts by its own column');
  assert.equal(order(7, false), '10.0.0.9,10.0.0.10', 'alert id sorts numerically');
});

test('the theme toggle survives reloads and reflects the effective scheme', () => {
  const stored = new Map([['cswebui.theme', 'dark']]);
  const documentElement = { dataset: {} };
  const icon = { attributes: {}, setAttribute(name, value) { this.attributes[name] = value; } };
  const { run } = ui({
    storage: {
      getItem: (key) => (stored.has(key) ? stored.get(key) : null),
      setItem: (key, value) => stored.set(key, value),
    },
    documentElement,
    seed: (element, elements) => {
      element('#theme-toggle');
      elements.set('#theme-toggle use', icon);
    },
  });
  assert.equal(documentElement.dataset.theme, 'dark');
  assert.equal(icon.attributes.href, '#i-sun');

  run(`$('#theme-toggle').listeners.click()`);
  assert.equal(stored.get('cswebui.theme'), 'light');
  assert.equal(documentElement.dataset.theme, 'light');
  assert.equal(icon.attributes.href, '#i-moon');
});

test('the mobile drawer closes on Escape and restores focus to its toggle', () => {
  const { elements, run, pressKey } = ui();
  run(`setNavOpen(true)`);
  const sidebar = elements.get('.sidebar');
  const toggle = elements.get('#nav-toggle');
  assert.equal(sidebar.classList.contains('nav-open'), true);
  assert.equal(toggle.attributes['aria-expanded'], 'true');
  pressKey({ key: 'Escape' });
  assert.equal(sidebar.classList.contains('nav-open'), false);
  assert.equal(toggle.attributes['aria-expanded'], 'false');
});

test('an allowlist failure keeps the page usable instead of blanking the view', async () => {
  const { element, run } = ui();
  const body = element('#allowlists-body');
  run(`api = async () => { throw new Error('Service unavailable'); };`);
  await run('renderAllowlists()');
  assert.match(body.innerHTML, /Service unavailable/);
  assert.match(body.innerHTML, /data-retry/);
  assert.doesNotMatch(body.innerHTML, /No allowlists configured/);
});

test('collapsing the sidebar persists and only overlays when the rail is hovered', () => {
  const stored = new Map();
  const app = { classList: {
    tokens: new Set(),
    add(t) { this.tokens.add(t); }, remove(t) { this.tokens.delete(t); },
    contains(t) { return this.tokens.has(t); },
    toggle(t, force) { const on = force ?? !this.tokens.has(t); if (on) this.tokens.add(t); else this.tokens.delete(t); return on; },
  } };
  const { run } = ui({
    storage: { getItem: (k) => stored.get(k) ?? null, setItem: (k, v) => stored.set(k, v) },
    seed: (element, elements) => {
      elements.set('#app', app);
      element('#nav-collapse');
    },
  });
  run(`applySidebar(false)`);
  assert.equal(app.classList.contains('rail'), false);

  run(`$('#nav-collapse').listeners.click()`);
  assert.equal(stored.get('cswebui.sidebar'), 'collapsed');
  assert.equal(app.classList.contains('rail'), true);
  // A collapsed rail must not overlay until it is hovered or focused.
  assert.equal(app.classList.contains('rail-hover'), false);
  run(`setRailHover(true)`);
  assert.equal(app.classList.contains('rail-hover'), true);
  run(`setRailHover(false)`);
  assert.equal(app.classList.contains('rail-hover'), false);
  // A full sidebar never overlays.
  run(`applySidebar(false); setRailHover(true)`);
  assert.equal(app.classList.contains('rail-hover'), false);
});

test('Escape closes the rail overlay before the drawer', () => {
  const app = { classList: {
    tokens: new Set(),
    add(t) { this.tokens.add(t); }, remove(t) { this.tokens.delete(t); },
    contains(t) { return this.tokens.has(t); },
    toggle(t, force) { const on = force ?? !this.tokens.has(t); if (on) this.tokens.add(t); else this.tokens.delete(t); return on; },
  } };
  const { run, pressKey } = ui({ seed: (_element, elements) => { elements.set('#app', app); } });
  run(`applySidebar(true); setNavOpen(true); setRailHover(true)`);
  pressKey({ key: 'Escape' });
  assert.equal(app.classList.contains('rail-hover'), false);
  assert.equal(run(`$('.sidebar').classList.contains('nav-open')`), true, 'the first Escape only dismisses the overlay');
  pressKey({ key: 'Escape' });
  assert.equal(run(`$('.sidebar').classList.contains('nav-open')`), false);
});

test('the chart hover readout snaps to real samples and stays inside the frame', () => {
  const points = [
    { time: '2026-10-30T08:00:00Z', count: 3 },
    { time: '2026-10-30T09:00:00Z', count: 9 },
    { time: '2026-10-30T10:00:00Z', count: 0 },
  ];
  const html = (() => {
    const { run } = ui();
    return run(`renderChart(${JSON.stringify(points)})`);
  })();
  assert.match(html, /data-chart/);
  assert.match(html, /chart-tip/);
  assert.match(html, /class="chart-data"/);
  const payload = JSON.parse(/<script type="application\/json" class="chart-data">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.deepEqual(payload.map((s) => s.count), [3, 9, 0]);
  assert.equal(payload[0].x, 8, 'first sample starts at the padding');
  assert.equal(payload.at(-1).x, 792, 'last sample ends at the padding');

  const { run } = ui();
  const pick = (ratio) => run(`chartIndexAt(${ratio}, 3)`);
  assert.equal(pick(-0.5), 0, 'left of the plot snaps to the first sample');
  assert.equal(pick(1.5), 2, 'right of the plot snaps to the last sample');
  assert.equal(pick(0.4), 1, 'the middle of the frame selects the middle bucket');
});

test('the stacked chart never invents bands and keeps the total readable', () => {
  const { run } = ui();
  const points = [
    { time: '2026-10-30T08:00:00Z', count: 5, breakdown: { 'a/one': 3, 'b/two': 2 } },
    { time: '2026-10-30T09:00:00Z', count: 4, breakdown: { 'a/one': 4 } },
  ];
  const html = run(`renderStackedChart(${JSON.stringify(points)}, [{name:'a/one',count:7},{name:'b/two',count:2}])`);
  const payload = JSON.parse(/<script type="application\/json" class="chart-data">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.deepEqual(payload.map((p) => p.count), [5, 4]);
  assert.deepEqual(payload[0].breakdown, { 'a/one': 3, 'b/two': 2 });
  assert.match(html, /chart-legend-series/);
  assert.match(html, /a\/one/, 'the legend names every band');

  // Without a breakdown the caller gets the plain line chart instead.
  assert.doesNotMatch(run(`renderStackedChart(${JSON.stringify(points)}, [])`), /chart-legend-series/);
});

test('the expiry horizon buckets only future expiries and keeps permanents apart', () => {
  const now = Date.parse('2026-10-30T12:00:00Z');
  const minutes = (m) => new Date(now + m * 60000).toISOString();
  const decisions = [
    { until: minutes(10) }, { until: minutes(59) },
    { until: minutes(120) }, { until: minutes(500) },
    { until: minutes(2000) }, { until: minutes(20000) },
    { until: '0001-01-01T00:00:00Z' },
    { until: minutes(-30) },
  ];
  const { run } = ui();
  // Values from the vm context carry foreign prototypes; compare as plain data.
  const summary = JSON.parse(JSON.stringify(run(`summarizeExpiry(${JSON.stringify(decisions)}, ${now})`)));
  assert.deepEqual(summary.buckets.map((b) => [b.id, b.count]), [
    ['soon', 2], ['today', 1], ['day', 1], ['week', 1], ['later', 1],
  ], 'expired decisions are dropped, not counted');
  assert.equal(summary.permanent, 1, 'permanent bans are their own bucket');

  const html = run(`renderExpiryHorizon(${JSON.stringify(decisions)}, ${now})`);
  assert.match(html, /horizon-bar permanent/);
  assert.doesNotMatch(html, /No active decisions/, 'a populated set draws bars');
  assert.match(run(`renderExpiryHorizon([], ${now})`), /No active decisions/);
});

test('a set filter is visible as a chip and can be removed without opening the panel', () => {
  const { run, context } = ui();
  run(`state.filters.alerts = { scenario: 'crowdsecurity/ssh-bf', limit: '100', include_capi: 'false', value: '1.2.3.4', contains: 'true' };
       state.range = '24h';`);
  const chips = JSON.parse(JSON.stringify(run('activeFilterChips("alerts")')));
  assert.deepEqual(chips.map((chip) => chip.key), ['scenario', 'value', 'contains'], 'limit and include_capi are noise, not filters');

  const html = run(`filterChips('alerts')`);
  assert.match(html, /data-remove-filter="scenario"/);
  assert.match(html, /crowdsecurity\/ssh-bf/);
  assert.match(html, /Clear all/);
  assert.match(run(`filterChips('decisions')`), /^$/, 'no filters, no chip row');

  // Removing a value must also drop the now-meaningless "contains" flag.
  context.routed = 0;
  run(`state.route = 'alerts'; route = () => { state.routed++; };`);
  run(`removeFilter('alerts', 'value')`);
  assert.equal(run(`state.filters.alerts.value`), undefined);
  assert.equal(run(`state.filters.alerts.contains`), undefined);
  assert.equal(run(`state.filters.alerts.scenario`), 'crowdsecurity/ssh-bf');
  assert.match(run(`state.hash`), /scenario=crowdsecurity%2Fssh-bf/);
});

test('the command palette matches every word across label, hint and keywords', () => {
  const { run } = ui();
  const names = (query) => JSON.parse(JSON.stringify(run(`matchPaletteActions(${JSON.stringify(query)}).map((a) => a.id)`)));
  assert.ok(names('').length > 5, 'an empty query lists everything');
  assert.deepEqual(names('ban'), ['decisions', 'new-decision'], 'a keyword finds its action, not just the label');
  assert.deepEqual(names('ip lookup'), ['inspect']);
  // Words from two different actions: only AND may drop both.
  assert.deepEqual(names('hub map'), [], 'a word per action must not match either');
  assert.deepEqual(names('nothing-like-this'), []);
  assert.deepEqual(names('DARK'), ['theme'], 'matching is case-insensitive');
});

test('the palette opens on Cmd/Ctrl+K only while signed in and closes on a second press', () => {
  const { run, pressKey, elements } = ui();
  let opened = 0;
  let closed = 0;
  const dialog = { dataset: {}, isConnected: true, close() { this.isConnected = false; } };
  elements.set('#modal-root', {
    innerHTML: '',
    querySelector: (selector) => (selector === 'dialog' ? dialog : null),
    querySelectorAll: () => [],
    set innerHTML(value) { this._html = value; },
    get innerHTML() { return this._html || ''; },
  });
  run(`openPalette = () => { state.opened = true; }; closePalette = () => { state.closed = true; };`);
  pressKey({ key: 'k', metaKey: true });
  assert.equal(run('state.opened'), undefined, 'signed out, no palette');

  run(`state.user = 'admin'`);
  pressKey({ key: 'k', metaKey: true, preventDefault() {} });
  assert.equal(run('state.opened'), true);
  pressKey({ key: 'k', ctrlKey: true, preventDefault() {} });
  assert.equal(run('state.opened'), true);
});

test('palette ranking puts a name match above an incidental keyword', () => {
  const { run } = ui();
  const names = (query) => JSON.parse(JSON.stringify(run(`matchPaletteActions(${JSON.stringify(query)}).map((a) => a.id)`)));

  assert.equal(names('add')[0], 'new-decision');
  assert.equal(names('map')[0], 'geo', 'the Geo page matches on its hint');
  assert.equal(names('decision')[0], 'decisions', 'a label starting with the word wins');
  // "col" is the start of "Collapse sidebar"; "collections" is only a Hub keyword.
  assert.equal(names('col')[0], 'collapse', 'a name match must outrank a keyword match');
  assert.deepEqual(names('zzz'), []);
  assert.equal(names('')[0], 'dashboard', 'an empty query keeps declaration order');
});

test('an empty expiry bucket draws no bar instead of a misleading stub', () => {
  const { run } = ui();
  assert.equal(run('barHeight(0, 40)'), 0, 'a zero-hour must not look like data');
  assert.equal(run('barHeight(40, 40)'), 100);
  assert.ok(run('barHeight(1, 1000)') >= 3, 'a real count stays visible');
  assert.equal(run('barHeight(0, 0)'), 0, 'an empty set draws nothing');
});

test('the chart tooltip stays inside the frame on every side', () => {
  const { run } = ui();
  const top = (pointY, h, frameH) => run(`tooltipTop(${pointY}, ${h}, ${frameH})`);

  // Plenty of room above.
  assert.equal(top(140, 40, 170), 90);
  // Not enough above: go below the point.
  assert.equal(top(12, 40, 170), 22);
  // 93px tooltip in a 170px frame fits on neither side: clamp, never overflow.
  const clamped = top(85, 93, 170);
  assert.ok(clamped >= 0 && clamped + 93 <= 170, `clamped tooltip must fit, got ${clamped}`);
  // A short frame with a tall tooltip still never exceeds the frame.
  assert.ok(top(5, 200, 100) >= 0);
  // No layout yet: leave the default alone.
  assert.equal(top(50, 40, 0), null);

  assert.equal(run('tooltipPlacement(140, 40, 170)'), 'above');
  assert.equal(run('tooltipPlacement(12, 40, 170)'), 'below');
});

