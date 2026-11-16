'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'proxy-pool.js'), 'utf8');

class Element {
  constructor(tagName = 'div') {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.events = {};
    this.dataset = {};
    this.attributes = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.ownText = '';
    this.classList = {
      values: new Set(),
      add: (...names) => names.forEach(name => this.classList.values.add(name)),
      remove: (...names) => names.forEach(name => this.classList.values.delete(name)),
      toggle: (name, force) => {
        const add = force === undefined ? !this.classList.values.has(name) : !!force;
        if (add) this.classList.values.add(name);
        else this.classList.values.delete(name);
        return add;
      },
      contains: name => this.classList.values.has(name),
    };
  }
  set textContent(value) { this.ownText = String(value ?? ''); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent || '').join(''); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.ownText = ''; this.children = [...items]; }
  querySelectorAll(selector) {
    if (selector !== '[data-write-action]') return [];
    const found = [];
    const visit = element => {
      if (element?.dataset?.writeAction) found.push(element);
      for (const child of element?.children || []) visit(child);
    };
    visit(this);
    return found;
  }
  addEventListener(name, callback) { this.events[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  focus() { this.focused = true; }
  reset() {
    if (this.id !== 'proxyPoolNodeForm') return;
    const fields = this.ownerDocument.elements;
    fields.get('proxyPoolNodeId').value = '';
    fields.get('proxyPoolNodeURL').value = '';
    fields.get('proxyPoolNodeEnabled').checked = true;
  }
}

function setup(fetchImpl = async () => reply({ ok: true, configured: false, enabled: false, nodes: [], accounts: [] })) {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) {
      const element = new Element(id.endsWith('Form') ? 'form' : 'div');
      element.id = id;
      element.ownerDocument = { elements };
      elements.set(id, element);
    }
    return elements.get(id);
  };
  const document = {
    elements,
    getElementById,
    querySelector(selector) {
      if (selector === 'meta[name="app-token"]') return { content: 'fixture-token' };
      return null;
    },
    createElement: tag => new Element(tag),
    createTextNode: text => ({ textContent: String(text) }),
  };
  const listeners = {};
  const timers = new Map();
  let nextTimer = 1;
  const window = {
    location: { hash: '' },
    addEventListener(name, callback) { listeners[name] = callback; },
    setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
  };
  const context = vm.createContext({
    document, window, fetch: fetchImpl, URL, Date, Intl, Set, Map, Number, String, JSON,
    Promise, Error, Array, Object, RegExp, TextEncoder,
  });
  vm.runInContext(source, context, { filename: 'proxy-pool.js' });
  return { elements, get: getElementById, context, window, controller: window.proxyPoolController, listeners, timers };
}

function reply(body, { ok = true, status = 200 } = {}) {
  return { ok, status, async json() { return body; } };
}

function status({ nodes = [], accounts = [], configured = nodes.length > 0, enabled = false } = {}) {
  return { ok: true, configured, enabled, max_accounts_per_exit: 1, nodes, assignments: [], accounts };
}

test('a successful node test clears the password and renders only protocol and host', async () => {
  const requests = [];
  const ui = setup(async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/node')) {
      return reply(status({
        nodes: [{ id: 'tokyo', scheme: 'https', endpoint: 'proxy.example:8443', exit_ip: '203.0.113.8', enabled: true }],
        accounts: [],
      }));
    }
    return reply(status({
      nodes: [{ id: 'tokyo', scheme: 'https', endpoint: 'proxy.example:8443', exit_ip: '203.0.113.8', enabled: true }],
      accounts: [],
    }));
  });
  ui.get('proxyPoolNodeId').value = 'tokyo';
  ui.get('proxyPoolNodeURL').type = 'password';
  ui.get('proxyPoolNodeURL').value = 'https://alice:private-secret@proxy.example:8443';
  ui.get('proxyPoolNodeEnabled').checked = true;

  assert.equal(await ui.controller.submitNode(), true);
  assert.equal(requests[0].url, '/api/proxy-pool/node');
  assert.equal(requests[0].options.headers['X-App-Token'], 'fixture-token');
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    id: 'tokyo', url: 'https://alice:private-secret@proxy.example:8443', enabled: true,
  });
  assert.equal(ui.get('proxyPoolNodeURL').value, '');
  const nodeText = ui.get('proxyPoolNodes').textContent;
  assert.match(nodeText, /https:\/\/proxy\.example:8443/);
  assert.match(nodeText, /203\.0\.113\.8/);
  assert.doesNotMatch(nodeText, /alice|private-secret/);
  assert.doesNotMatch(ui.get('proxyPoolFeedback').textContent, /private-secret/);
});

test('a failed save stays busy until the response, retains the password, and hides server error text', async () => {
  let resolvePost;
  let requestCount = 0;
  const pending = new Promise(resolve => { resolvePost = resolve; });
  const ui = setup(async url => {
    requestCount += 1;
    assert.equal(url, '/api/proxy-pool/node');
    return pending;
  });
  ui.get('proxyPoolNodeId').value = 'west';
  ui.get('proxyPoolNodeURL').value = 'http://user:secret@proxy.example:8080';
  const save = ui.controller.submitNode();
  assert.equal(ui.get('proxyPoolNodeSubmit').disabled, true);
  assert.match(ui.get('proxyPoolNodeSubmit').textContent, /正在测试并保存/);
  assert.equal(await ui.controller.submitNode(), false);
  assert.equal(requestCount, 1);

  resolvePost(reply({ ok: false, message: 'server echoed secret@proxy.example:8080' }));
  assert.equal(await save, false);
  assert.equal(ui.get('proxyPoolNodeURL').value, 'http://user:secret@proxy.example:8080');
  assert.equal(ui.get('proxyPoolNodeSubmit').disabled, false);
  assert.match(ui.get('proxyPoolFeedback').textContent, /节点测试或保存失败/);
  assert.doesNotMatch(ui.get('proxyPoolFeedback').textContent, /server echoed|secret|proxy\.example/);
});

test('out-of-order status responses cannot replace the latest refresh', async () => {
  const pending = [];
  const ui = setup(url => {
    assert.equal(url, '/api/proxy-pool/status');
    return new Promise(resolve => pending.push(resolve));
  });
  const older = ui.controller.loadStatus();
  const newer = ui.controller.loadStatus();

  pending[1](reply(status({ nodes: [{ id: 'new', scheme: 'socks5h', endpoint: 'fresh.example:1080', exit_ip: '203.0.113.10', enabled: true }] })));
  assert.equal(await newer, true);
  pending[0](reply(status({ nodes: [{ id: 'old', scheme: 'http', endpoint: 'stale.example:8080', exit_ip: '203.0.113.11', enabled: true }] })));
  assert.equal(await older, false);

  assert.match(ui.get('proxyPoolNodes').textContent, /fresh\.example:1080/);
  assert.doesNotMatch(ui.get('proxyPoolNodes').textContent, /stale\.example|old/);
});

test('editing a node with an empty URL posts an empty secret to retain the saved credential', async () => {
  const requests = [];
  const ui = setup(async (url, options) => {
    requests.push({ url, options });
    return reply(status({ nodes: [{ id: 'east', scheme: 'socks5', endpoint: 'east.example:1080', exit_ip: '203.0.113.20', enabled: true }] }));
  });
  ui.controller.beginEdit({ id: 'east', enabled: false });
  const result = await ui.controller.submitNode();
  assert.equal(result, true);
  assert.equal(requests[0].url, '/api/proxy-pool/node');
  assert.deepEqual(JSON.parse(requests[0].options.body), { id: 'east', url: '', enabled: false });
});

test('unsupported proxy protocols are rejected locally without echoing or sending the URL', async () => {
  let requestCount = 0;
  const ui = setup(async () => { requestCount += 1; throw new Error('request should not be sent'); });
  ui.get('proxyPoolNodeId').value = 'subscription';
  ui.get('proxyPoolNodeURL').value = 'ss://user:private-token@feed.example:443';
  assert.equal(await ui.controller.submitNode(), false);
  assert.equal(requestCount, 0);
  assert.equal(ui.get('proxyPoolNodeURL').value, 'ss://user:private-token@feed.example:443');
  assert.match(ui.get('proxyPoolFeedback').textContent, /仅支持 http、https、socks5、socks5h/);
  assert.doesNotMatch(ui.get('proxyPoolFeedback').textContent, /private-token|feed\.example/);
});

test('remove is blocked in the UI when the node has assigned accounts', async () => {
  let requestCount = 0;
  const loadUi = setup(async () => reply(status({
    nodes: [{ id: 'shared', scheme: 'http', endpoint: 'shared.example:8080', exit_ip: '203.0.113.30', enabled: true, assigned_accounts: ['account-a'] }],
    accounts: [],
  })));
  await loadUi.controller.loadStatus();
  loadUi.context.fetch = async () => { requestCount += 1; throw new Error('remove should not be called'); };
  assert.equal(await loadUi.controller.removeNode('shared'), false);
  assert.match(loadUi.get('proxyPoolFeedback').textContent, /已绑定 1 个账号，不能删除/);
  assert.equal(requestCount, 0);
});

test('capacity settings use the fixed endpoint and integer payload', async () => {
  let posted;
  const ui = setup(async (url, options) => {
    if (url.endsWith('/settings')) posted = { url, options };
    return reply({ ...status({ nodes: [{ id: 'north', scheme: 'http', endpoint: 'north.example:8080', exit_ip: '203.0.113.40', enabled: true }] }), max_accounts_per_exit: 4 });
  });
  ui.get('proxyPoolMaxAccounts').value = '4';
  assert.equal(await ui.controller.saveSettings(), true);
  assert.equal(posted.url, '/api/proxy-pool/settings');
  assert.equal(posted.options.headers['X-App-Token'], 'fixture-token');
  assert.deepEqual(JSON.parse(posted.options.body), { max_accounts_per_exit: 4 });
  assert.equal(ui.get('proxyPoolMaxAccounts').value, '4');
});

test('apply posts an empty body without confirmation and displays returned account application states', async () => {
  const requests = [];
  const enabled = status({
    nodes: [{ id: 'ready', scheme: 'https', endpoint: 'ready.example:443', exit_ip: '203.0.113.50', enabled: true, assigned_accounts: ['account-a'] }],
    accounts: [{ account_id: 'account-a', node_id: 'ready', exit_ip: '203.0.113.50', applied: true, running: true, state: 'running' }],
    enabled: true,
  });
  const ui = setup(async (url, options) => {
    requests.push({ url, options });
    return reply(enabled);
  });
  await ui.controller.loadStatus();
  assert.equal(ui.get('proxyPoolApply').disabled, false);
  assert.equal(await ui.controller.applyPool(), true);
  assert.equal(requests[1].url, '/api/proxy-pool/apply');
  assert.deepEqual(JSON.parse(requests[1].options.body), {});
  assert.equal(requests[1].options.headers['X-App-Token'], 'fixture-token');
  assert.match(ui.get('proxyPoolAccounts').textContent, /account-a/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /已应用/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /运行中/);
  assert.match(ui.get('proxyPoolFeedback').textContent, /发起恢复|已有会话恢复/);
});

test('an in-progress apply disables writes, shows status, and schedules a status refresh', async () => {
  const ui = setup(async () => reply({
    ...status({ nodes: [{ id: 'pending', scheme: 'https', endpoint: 'pending.example:443', exit_ip: '203.0.113.60', enabled: true }] }),
    applying: true,
  }));
  ui.window.location.hash = '#proxy-pool';
  await ui.controller.loadStatus();
  assert.equal(ui.get('proxyPoolNodeSubmit').disabled, true);
  assert.equal(ui.get('proxyPoolSettingsSubmit').disabled, true);
  assert.equal(ui.get('proxyPoolApply').disabled, true);
  assert.match(ui.get('proxyPoolBadge').textContent, /正在应用/);
  assert.match(ui.get('proxyPoolSummary').textContent, /状态会自动刷新/);
  assert.equal([...ui.timers.values()][0].delay, 2500);
});

test('safe account recovery messages appear below the application status', async () => {
  const ui = setup(async () => reply(status({
    nodes: [{ id: 'verify', scheme: 'http', endpoint: 'verify.example:8080', exit_ip: '203.0.113.70', enabled: true }],
    accounts: [{ account_id: 'account-b', node_id: 'verify', exit_ip: '203.0.113.70', applied: false, running: false, state: 'stopped', message: '该账号需要验证，请在账号页处理' }],
  })));
  await ui.controller.loadStatus();
  assert.match(ui.get('proxyPoolAccounts').textContent, /该账号需要验证，请在账号页处理/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /已停止/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /未应用/);
});

test('status polling observes accounts that apply successfully after the POST returns', async () => {
  const node = { id: 'queued', scheme: 'https', endpoint: 'queued.example:443', exit_ip: '203.0.113.80', enabled: true, assigned_accounts: ['account-c'] };
  const queued = status({
    nodes: [node], enabled: true,
    accounts: [{ account_id: 'account-c', node_id: 'queued', exit_ip: '203.0.113.80', applied: false, running: false, state: 'stopped', message: '账号后台正在恢复' }],
  });
  const applied = status({
    nodes: [node], enabled: true,
    accounts: [{ account_id: 'account-c', node_id: 'queued', exit_ip: '203.0.113.80', applied: true, running: true, state: 'running' }],
  });
  let current = status({ nodes: [node], enabled: false, accounts: [] });
  let statusReads = 0;
  const ui = setup(async url => {
    if (url.endsWith('/status')) {
      statusReads += 1;
      return reply(current);
    }
    if (url.endsWith('/apply')) {
      current = queued;
      return reply({ ...queued, message: '已启用并发起已有会话恢复，账号状态正在更新。' });
    }
    throw new Error(`unexpected request ${url}`);
  });
  ui.window.location.hash = '#proxy-pool';
  await ui.controller.loadStatus();
  assert.equal(await ui.controller.applyPool(), true);
  assert.match(ui.get('proxyPoolFeedback').textContent, /发起已有会话恢复/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /未应用/);
  assert.equal(statusReads, 2);

  current = applied;
  const timer = [...ui.timers.values()][0];
  await timer.callback();
  assert.match(ui.get('proxyPoolAccounts').textContent, /已应用/);
  assert.match(ui.get('proxyPoolAccounts').textContent, /运行中/);
  assert.equal(statusReads, 3);
});

test('a GET started before a node save cannot overwrite the saved status', async () => {
  let resolveStale;
  let statusReads = 0;
  const saved = status({ nodes: [{ id: 'saved', scheme: 'http', endpoint: 'saved.example:8080', exit_ip: '203.0.113.90', enabled: true }] });
  const stale = status({ nodes: [{ id: 'old', scheme: 'http', endpoint: 'old.example:8080', exit_ip: '203.0.113.91', enabled: true }] });
  const ui = setup(async url => {
    if (url.endsWith('/status')) {
      statusReads += 1;
      if (statusReads === 1) return new Promise(resolve => { resolveStale = resolve; });
      return reply(saved);
    }
    if (url.endsWith('/node')) return reply(saved);
    throw new Error(`unexpected request ${url}`);
  });
  ui.window.location.hash = '#proxy-pool';
  const pendingRead = ui.controller.loadStatus();
  ui.get('proxyPoolNodeId').value = 'saved';
  ui.get('proxyPoolNodeURL').value = 'http://proxy.example:8080';
  assert.equal(await ui.controller.submitNode(), true);
  resolveStale(reply(stale));
  assert.equal(await pendingRead, false);
  assert.match(ui.get('proxyPoolNodes').textContent, /saved\.example:8080/);
  assert.doesNotMatch(ui.get('proxyPoolNodes').textContent, /old\.example/);
});

test('proxy pool requests use literal endpoints and the client never stores credentials locally', () => {
  for (const endpoint of ['status', 'node', 'remove', 'settings', 'apply']) {
    assert.ok(source.includes(`fetch('/api/proxy-pool/${endpoint}'`), `missing literal endpoint ${endpoint}`);
  }
  assert.doesNotMatch(source, /\blocalStorage\b/);
  const index = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(index, /id="proxyPoolNodeURL" type="password" autocomplete="off"/);
  assert.match(index, /href="#proxy-pool" class="nav-item"/);
  assert.doesNotMatch(`${source}\n${index}`, /'[^']*\bworker\b[^']*'|'[^']*host:port[^']*'|'[^']*节点 ID[^']*'/i);
});
