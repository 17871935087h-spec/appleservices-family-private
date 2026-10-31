'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const appPath = path.join(__dirname, 'web', 'app.js');
const appSource = fs.readFileSync(appPath, 'utf8');
const indexSource = fs.readFileSync(path.join(__dirname, 'web', 'index.html'), 'utf8');
const eventMarker = "$('reloadView').addEventListener";
const eventOffset = appSource.indexOf(eventMarker);
if (eventOffset < 0) throw new Error('Could not find dashboard event binding boundary');
const reconnectBinding = appSource.split(/\r?\n/).find(line => line.startsWith("$('hmeReconnectButton').addEventListener"));
if (!reconnectBinding) throw new Error('Could not find HME reconnect event binding');

class FakeClassList {
  constructor() { this.values = new Set(); }
  add(...names) { for (const name of names) this.values.add(name); }
  remove(...names) { for (const name of names) this.values.delete(name); }
  contains(name) { return this.values.has(name); }
  toggle(name, force) {
    const shouldAdd = force === undefined ? !this.values.has(name) : !!force;
    if (shouldAdd) this.values.add(name);
    else this.values.delete(name);
    return shouldAdd;
  }
}

class FakeElement {
  constructor() {
    this.classList = new FakeClassList();
    this.dataset = {};
    this.handlers = new Map();
    this.hidden = false;
    this.textContent = '';
    this.value = '';
    this.children = [];
  }
  addEventListener(type, handler) {
    const handlers = this.handlers.get(type) || [];
    handlers.push(handler);
    this.handlers.set(type, handlers);
  }
  dispatch(type, event = {}) {
    for (const handler of this.handlers.get(type) || []) handler(event);
  }
  focus() { this.focused = true; }
  querySelector() { return new FakeElement(); }
  replaceChildren(...children) { this.children = [...children]; }
  append(...children) { this.children.push(...children); }
  setAttribute() {}
  showModal() { this.modalShown = true; }
  close() { this.modalShown = false; }
}

function jsonResponse(body) {
  return { ok: true, status: 200, json: async () => body };
}

function createHarness(fetchImplementation) {
  const elements = new Map();
  const timers = [];
  const fetchCalls = [];
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  getElementById('notice').hidden = true;
  getElementById('hmeCandidatePanel').hidden = true;
  const document = {
    body: getElementById('body'),
    getElementById,
    querySelector: () => Object.assign(new FakeElement(), { content: 'fixture' }),
    createElement: () => new FakeElement(),
  };
  const context = {
    document,
    localStorage: {
      getItem: key => key === 'selected-account' ? 'fixture-account' : null,
      setItem() {},
      removeItem() {},
    },
    fetch: (...args) => {
      fetchCalls.push(args);
      return fetchImplementation(...args);
    },
    setTimeout: (callback, delay) => {
      const timer = { callback, delay };
      timers.push(timer);
      return timer;
    },
    clearTimeout() {},
    confirm: () => true,
    console,
  };
  context.globalThis = context;
  const script = `${appSource.slice(0, eventOffset)}\n${reconnectBinding}\npoll=async()=>{};\nglobalThis.__hmeTest={action,resetHME,setSelectedAccount(value){selectedAccount=value;},state(){return {busy,selectedAccount,loginAccount,loginMode};}};`;
  vm.runInNewContext(script, context, { filename: 'app.js' });
  return { context, elements, timers, fetchCalls, action: context.__hmeTest.action, state: context.__hmeTest.state };
}

test('failed generation keeps safe message after the global toast expires and offers reconnect', async () => {
  let resolveFetch;
  const harness = createHarness(() => new Promise(resolve => { resolveFetch = resolve; }));
  const request = harness.action('hme-generate');
  const status = harness.elements.get('hmeActionStatus');
  const card = harness.elements.get('hmeCard');

  assert.equal(status.textContent, '正在生成候选地址…');
  assert.equal(status.dataset.state, 'loading');
  assert.equal(card.classList.contains('is-loading'), true);
  assert.equal(harness.fetchCalls.length, 1);
  assert.match(harness.fetchCalls[0][0], /^\/api\/action\?/);
  assert.equal(JSON.parse(harness.fetchCalls[0][1].body).action, 'hme-generate');

  resolveFetch(jsonResponse({ ok: false, message: 'fixture safe message', stage: 'hme-session', http_status: 502 }));
  await request;

  assert.match(status.textContent, /fixture safe message/);
  assert.match(status.textContent, /hme-session/);
  assert.match(status.textContent, /HTTP 502/);
  assert.equal(status.dataset.state, 'error');
  assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
  assert.equal(card.classList.contains('is-loading'), false);
  assert.equal(harness.elements.get('body').classList.contains('busy'), false);

  const noticeTimer = harness.timers.find(timer => timer.delay === 6500);
  assert.ok(noticeTimer, 'global notice should retain its existing timeout');
  noticeTimer.callback();
  assert.equal(harness.elements.get('notice').hidden, true);
  assert.match(status.textContent, /fixture safe message/);

  harness.context.__hmeTest.resetHME();
  assert.equal(status.hidden, true);
  assert.equal(harness.elements.get('hmeActionFeedback').hidden, true);
  assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
  harness.elements.get('hmeReconnectButton').dispatch('click');
  assert.equal(harness.state().loginMode, 'reconnect');
  assert.equal(harness.state().loginAccount, 'fixture-account');
  assert.equal(harness.elements.get('loginDialog').modalShown, true);
});

test('reconnect button stays visible in the HME title for every action state', async () => {
  const sectionStart = indexSource.indexOf('id="hmeCard"');
  const sectionEnd = indexSource.indexOf('</section>', sectionStart);
  const hmeSection = indexSource.slice(sectionStart, sectionEnd);
  assert.match(hmeSection, /<div class="commerce-actions"><button id="hmeReconnectButton" class="text-button" type="button">重新连接当前账号<\/button>/);
  assert.doesNotMatch(hmeSection.match(/<button id="hmeReconnectButton"[^>]*>/)?.[0] || '', /\shidden(?:[ =>])/);
  assert.match(appSource, /\$\('hmeReconnectButton'\)\.disabled=busy/);

  for (const stage of ['reconnect-required', 'other-stage']) {
    const harness = createHarness(async () => jsonResponse({ ok: false, message: 'fixture error', stage }));
    await harness.action('hme-generate');
    assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
  }
});

test('successful generation displays the candidate and replaces prior feedback', async () => {
  const harness = createHarness(async () => jsonResponse({ ok: true, hme_candidate: 'candidate@example.invalid' }));
  await harness.action('hme-generate');

  assert.equal(harness.elements.get('hmeActionStatus').textContent, '候选地址已生成，请确认后再创建。');
  assert.equal(harness.elements.get('hmeActionStatus').dataset.state, 'success');
  assert.equal(harness.elements.get('hmeActionFeedback').hidden, false);
  assert.equal(harness.elements.get('hmeCandidatePanel').hidden, false);
  assert.equal(harness.elements.get('hmeCandidateAddress').textContent, 'candidate@example.invalid');
  assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
});

test('successful response without a candidate is reported as an error', async () => {
  const harness = createHarness(async () => jsonResponse({ ok: true, message: 'fixture success without candidate' }));
  await harness.action('hme-generate');

  assert.match(harness.elements.get('hmeActionStatus').textContent, /未返回候选地址/);
  assert.equal(harness.elements.get('hmeActionStatus').dataset.state, 'error');
  assert.equal(harness.elements.get('hmeCandidatePanel').hidden, true);
  assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
});

test('late response from a previously selected account cannot replace the new account status', async () => {
  let resolveFetch;
  const harness = createHarness(() => new Promise(resolve => { resolveFetch = resolve; }));
  const request = harness.action('hme-generate');
  harness.context.__hmeTest.setSelectedAccount('other-fixture-account');
  resolveFetch(jsonResponse({ ok: false, message: 'stale fixture error', stage: 'hme-session' }));
  await request;

  assert.equal(harness.elements.get('hmeActionStatus').hidden, true);
  assert.equal(harness.elements.get('hmeReconnectButton').hidden, false);
  assert.equal(harness.elements.get('notice').hidden, true);
  assert.equal(harness.state().busy, false);
});
