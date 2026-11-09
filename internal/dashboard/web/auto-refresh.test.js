'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const appSource = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

function extractFunction(source, name) {
  const declaration = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`);
  const match = declaration.exec(source);
  assert.ok(match, `missing function ${name}`);
  const start = match.index;
  let open = -1;
  let paramsDepth = 1;
  let paramsQuote = '';
  let paramsLineComment = false;
  let paramsBlockComment = false;
  for (let index = start + match[0].length; index < source.length; index += 1) {
    const current = source[index];
    const next = source[index + 1];
    if (paramsLineComment) {
      if (current === '\n') paramsLineComment = false;
      continue;
    }
    if (paramsBlockComment) {
      if (current === '*' && next === '/') {
        paramsBlockComment = false;
        index += 1;
      }
      continue;
    }
    if (paramsQuote) {
      if (current === '\\') {
        index += 1;
        continue;
      }
      if (current === paramsQuote) paramsQuote = '';
      continue;
    }
    if (current === '/' && next === '/') {
      paramsLineComment = true;
      index += 1;
      continue;
    }
    if (current === '/' && next === '*') {
      paramsBlockComment = true;
      index += 1;
      continue;
    }
    if (current === "'" || current === '"' || current === '`') {
      paramsQuote = current;
      continue;
    }
    if (current === '(') paramsDepth += 1;
    if (current === ')') {
      paramsDepth -= 1;
      if (paramsDepth === 0) {
        open = source.indexOf('{', index + 1);
        break;
      }
    }
  }
  assert.notEqual(open, -1, `missing body for ${name}`);

  let depth = 0;
  let quote = '';
  let lineComment = false;
  let blockComment = false;
  for (let index = open; index < source.length; index += 1) {
    const current = source[index];
    const next = source[index + 1];

    if (lineComment) {
      if (current === '\n') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (current === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (current === '\\') {
        index += 1;
        continue;
      }
      if (current === quote) quote = '';
      continue;
    }
    if (current === '/' && next === '/') {
      lineComment = true;
      index += 1;
      continue;
    }
    if (current === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (current === "'" || current === '"' || current === '`') {
      quote = current;
      continue;
    }
    if (current === '{') depth += 1;
    if (current === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  assert.fail(`unterminated function ${name}`);
}

function fakeStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key) { return values.has(String(key)) ? values.get(String(key)) : null; },
    setItem(key, value) { values.set(String(key), String(value)); },
    removeItem(key) { values.delete(String(key)); },
    has(key) { return values.has(String(key)); },
    raw(key) { return values.get(String(key)); },
  };
}

function fakeClock(start = 1_000_000) {
  let now = start;
  let nextID = 1;
  const timers = new Map();
  const delays = [];
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  return {
    Date: ClockDate,
    delays,
    setTimeout(callback, delay = 0) {
      const id = nextID++;
      const numericDelay = Number(delay) || 0;
      delays.push(numericDelay);
      timers.set(id, { at: now + numericDelay, callback });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
    async advance(milliseconds) {
      const target = now + milliseconds;
      while (true) {
        const next = [...timers.entries()]
          .filter(([, timer]) => timer.at <= target)
          .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!next) break;
        const [id, timer] = next;
        timers.delete(id);
        now = timer.at;
        timer.callback();
        await flushMicrotasks();
      }
      now = target;
      await flushMicrotasks();
    },
    get now() { return now; },
    get timerCount() { return timers.size; },
  };
}

async function flushMicrotasks() {
  for (let index = 0; index < 8; index += 1) await Promise.resolve();
}

const lifecycleFunctions = [
  'autoRefreshLeaseKey',
  'autoRefreshAttemptKey',
  'acquireAutoRefreshLease',
  'renewAutoRefreshLease',
  'releaseAutoRefreshLease',
  'autoRefreshAttemptStatus',
  'autoRefreshAttempted',
  'markAutoRefreshAttempt',
  'finishAutoRefreshAttempt',
  'clearAutoRefreshAttempt',
  'autoRefreshKey',
];

function createContext(extra = {}, names = lifecycleFunctions) {
  const clock = extra.clock || fakeClock();
  const state = {
    selectedAccount: 'account-a',
    autoRefreshOwner: 'tab-a',
    autoRefreshMaxAge: 150000,
    autoRefreshState: new Map(),
    localStorage: fakeStorage(),
    Date: clock.Date,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    AbortController,
    ...extra,
  };
  vm.createContext(state);
  const declarations = names.map(name => extractFunction(appSource, name)).join('\n');
  const exports = names.map(name => `globalThis.__${name} = ${name};`).join('\n');
  vm.runInContext(`${declarations}\n${exports}`, state);
  state.clock = clock;
  return state;
}

function storedAttempt(state, key) {
  return JSON.parse(state.localStorage.getItem(`appleservices:auto-attempt:${key}`));
}

test('legacy or invalid refreshing attempts expire into a persistent failed state', async t => {
  const cases = [
    ['older than max age', now => now - 150001],
    ['at the max-age boundary', now => now - 150000],
    ['missing timestamp', () => undefined],
    ['invalid timestamp', () => 'not-a-time'],
    ['future timestamp', now => now + 1],
  ];
  for (const [label, makeTimestamp] of cases) {
    await t.test(label, () => {
      const state = createContext();
      const key = 'account-a|family|snapshot-1';
      state.localStorage.setItem(`appleservices:auto-attempt:${key}`, JSON.stringify({
        status: 'refreshing', owner: 'old-tab', at: makeTimestamp(state.clock.now),
      }));

      assert.equal(state.__autoRefreshAttemptStatus(key), 'failed');
      assert.equal(state.autoRefreshState.get(key).status, 'failed');
      assert.equal(storedAttempt(state, key).status, 'failed');
    });
  }
});

test('a fresh attempt owned by another tab stays active and its lease blocks this tab', () => {
  const state = createContext();
  const key = 'account-a|family|snapshot-2';
  state.localStorage.setItem(`appleservices:auto-attempt:${key}`, JSON.stringify({
    status: 'refreshing', owner: 'tab-b', at: state.clock.now - 149999,
  }));
  state.localStorage.setItem('appleservices:auto-refresh:account-a', JSON.stringify({
    owner: 'tab-b', expires: state.clock.now + 1,
  }));

  assert.equal(state.__autoRefreshAttemptStatus(key), 'refreshing');
  assert.equal(state.__acquireAutoRefreshLease('account-a'), false);
  assert.equal(JSON.parse(state.localStorage.getItem('appleservices:auto-refresh:account-a')).owner, 'tab-b');
});

test('mark, finish, and clear update both stores without overwriting another owner', () => {
  const state = createContext();
  const key = 'account-a|storage|snapshot-3';

  state.__markAutoRefreshAttempt(key);
  assert.equal(state.autoRefreshState.get(key).status, 'refreshing');
  assert.equal(storedAttempt(state, key).owner, 'tab-a');

  state.__finishAutoRefreshAttempt(key, 'done');
  assert.equal(state.autoRefreshState.get(key).status, 'done');
  assert.equal(storedAttempt(state, key).status, 'done');
  assert.equal(state.__autoRefreshAttempted(key), true);

  state.localStorage.setItem(`appleservices:auto-attempt:${key}`, JSON.stringify({
    status: 'refreshing', owner: 'tab-b', at: state.clock.now,
  }));
  state.__finishAutoRefreshAttempt(key, 'failed');
  assert.equal(storedAttempt(state, key).owner, 'tab-b');
  assert.equal(storedAttempt(state, key).status, 'refreshing');

  state.__clearAutoRefreshAttempt(key);
  assert.equal(state.autoRefreshState.has(key), false);
  assert.equal(state.localStorage.has(`appleservices:auto-attempt:${key}`), false);
});

function familyMetaContext({ includeScheduler = false, ...extra } = {}) {
  const elements = new Map();
  const state = createContext({
    familyInfo: { member: true },
    familyCheckedAt: 'snapshot-ui',
    familyStale: false,
    time(value) { return value; },
    $(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          textContent: '',
          classList: { toggle() {} },
        });
      }
      return elements.get(id);
    },
    busy: false,
    autoRefreshScheduled: false,
    storageCheckedAt: '',
    planCheckedAt: '',
    window: { setTimeout() { throw new Error('a completed snapshot must not schedule a retry'); } },
    renderStorage() {},
    renderPlans() {},
    action() { throw new Error('a completed snapshot must not dispatch another refresh'); },
    ...extra,
  }, [
    ...lifecycleFunctions,
    'cacheLabel',
    'updateFamilyCacheMeta',
    ...(includeScheduler ? ['scheduleAutoRefresh'] : []),
  ]);
  state.element = id => elements.get(id);
  return state;
}

test('expired refreshing family state leaves the spinner label and restores the refresh button', () => {
  const state = familyMetaContext();
  const key = 'account-a|family|snapshot-ui';
  state.localStorage.setItem(`appleservices:auto-attempt:${key}`, JSON.stringify({
    status: 'refreshing', owner: 'old-tab', at: state.clock.now - 150000,
  }));

  state.__updateFamilyCacheMeta('snapshot-ui', true, true);

  assert.equal(state.element('familyCacheNote').textContent, '核验未完成 · 可重新核验');
  assert.notEqual(state.element('familyCacheNote').textContent, '正在后台核验 Apple…');
  assert.equal(state.element('familyRefreshButton').textContent, '重新核验 Apple');
  assert.equal(storedAttempt(state, key).status, 'failed');
});

test('done family refresh shows cache-update state and does not retry that stale snapshot', () => {
  const state = familyMetaContext({ includeScheduler: true });
  const key = 'account-a|family|snapshot-ui';
  state.__markAutoRefreshAttempt(key);
  state.__finishAutoRefreshAttempt(key, 'done');

  state.__updateFamilyCacheMeta('snapshot-ui', true, true);
  assert.equal(state.element('familyCacheNote').textContent, '已完成核验 · 缓存待更新');
  assert.equal(state.element('familyRefreshButton').textContent, '重新核验 Apple');

  state.__scheduleAutoRefresh({
    family: { member: true }, family_stale: true, family_checked_at: 'snapshot-ui',
  }, true);
  assert.equal(storedAttempt(state, key).status, 'done');
});

test('stale family scheduling uses the direct reader and attempts a cache snapshot once', () => {
  const callbacks = [];
  const calls = [];
  const state = createContext({
    busy: false,
    autoRefreshScheduled: false,
    familyCheckedAt: 'snapshot-4',
    storageCheckedAt: '',
    planCheckedAt: '',
    window: { setTimeout(callback, delay) { callbacks.push({ callback, delay }); } },
    updateFamilyCacheMeta() {},
    renderStorage() {},
    renderPlans() {},
    action(name, extra, options) {
      calls.push({ name, extra, options });
      state.__finishAutoRefreshAttempt(options.autoKey, 'done');
    },
  }, [...lifecycleFunctions, 'scheduleAutoRefresh']);
  const view = { family: { member: true }, family_stale: true, family_checked_at: 'snapshot-4' };

  state.__scheduleAutoRefresh(view, true);
  state.__scheduleAutoRefresh(view, true);
  assert.equal(callbacks.length, 1);
  assert.equal(callbacks[0].delay, 80);
  assert.equal(state.autoRefreshScheduled, true);

  callbacks[0].callback();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, 'family-info-direct');
  assert.equal(calls[0].options.autoKey, 'account-a|family|snapshot-4');
  assert.equal(storedAttempt(state, calls[0].options.autoKey).status, 'done');

  state.__scheduleAutoRefresh(view, true);
  assert.equal(callbacks.length, 1);
  assert.equal(calls.length, 1);

  const failedKey = 'account-a|family|snapshot-6';
  state.__markAutoRefreshAttempt(failedKey);
  state.__finishAutoRefreshAttempt(failedKey, 'failed');
  state.__scheduleAutoRefresh({
    family: { member: true }, family_stale: true, family_checked_at: 'snapshot-6',
  }, true);
  assert.equal(callbacks.length, 1);
  assert.equal(calls.length, 1);
});

test('api applies the configured deadlines only to reads and read-refresh actions', async () => {
  const requests = [];
  const state = createContext({
    token: 'test-token',
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, async json() { return { ok: true }; } };
    },
  }, ['api']);

  await state.api('view');
  for (const action of ['family-info', 'family-info-direct', 'storage-info', 'storage-plan']) {
    await state.api('action', { action });
  }
  const deadlines = state.clock.delays;
  assert.deepEqual(deadlines, [12000, 100000, 100000, 100000, 100000]);
  assert.ok(requests.slice(0, 5).every(({ options }) => options.signal instanceof AbortSignal));

  const before = state.clock.delays.length;
  await state.api('action', { action: 'devices' });
  assert.equal(state.clock.delays.length, before);
  assert.equal('signal' in requests.at(-1).options, false);
});

test('api deadline aborts a pending fetch and keeps response.json inside the same deadline', async t => {
  await t.test('pending fetch', async () => {
    let observedSignal;
    const state = createContext({
      token: 'test-token',
      fetch(_url, options) {
        observedSignal = options.signal;
        return new Promise((resolve, reject) => {
          options.signal.addEventListener('abort', () => reject(new Error('fetch aborted')), { once: true });
        });
      },
    }, ['api']);
    const request = state.api('action', { action: 'family-info' });
    await flushMicrotasks();
    assert.equal(state.clock.delays[0], 100000);
    await state.clock.advance(100000);
    await assert.rejects(request, /读取 Apple 状态超时/);
    assert.equal(observedSignal.aborted, true);
    assert.equal(state.clock.timerCount, 0);
  });

  await t.test('pending response.json', async () => {
    let observedSignal;
    let jsonStarted = false;
    const state = createContext({
      token: 'test-token',
      async fetch(_url, options) {
        observedSignal = options.signal;
        return {
          ok: true,
          json() {
            jsonStarted = true;
            return new Promise((resolve, reject) => {
              options.signal.addEventListener('abort', () => reject(new Error('json aborted')), { once: true });
            });
          },
        };
      },
    }, ['api']);
    const request = state.api('action', { action: 'storage-info' });
    await flushMicrotasks();
    assert.equal(jsonStarted, true);
    await state.clock.advance(100000);
    await assert.rejects(request, /读取 Apple 状态超时/);
    assert.equal(observedSignal.aborted, true);
    assert.equal(state.clock.timerCount, 0);
  });
});

function actionContext(response, beforeResponse = () => {}) {
  const localStorage = fakeStorage();
  const elements = new Map();
  const renderFamilyCalls = [];
  const notices = [];
  const context = createContext({
    selectedAccount: 'account-a',
    familyCheckedAt: 'snapshot-5',
    storageCheckedAt: 'storage-snapshot',
    planCheckedAt: 'plan-snapshot',
    current: null,
    busy: false,
    localStorage,
    document: { body: { classList: { add() {}, remove() {} } } },
    $(id) {
      if (!elements.has(id)) elements.set(id, { classList: { add() {}, remove() {} }, textContent: '' });
      return elements.get(id);
    },
    api: async () => {
      beforeResponse();
      if (response instanceof Error) throw response;
      return response;
    },
    renderFamily(...args) { renderFamilyCalls.push(args); },
    activity() {},
    notice(...args) { notices.push(args); },
    poll: async () => {},
    render() {},
    setHMEFeedback() {},
    autoRefreshOwner: 'tab-a',
  }, [...lifecycleFunctions, 'action']);
  context.renderFamilyCalls = renderFamilyCalls;
  context.notices = notices;
  return context;
}

test('manual family refresh records success and failure, then releases its lease', async () => {
  const family = { member: true, organizer: false, storage_participating: true };
  const success = actionContext({ ok: true, family });
  const successKey = 'account-a|family|snapshot-5';
  await success.__action('family-info-direct', {}, { silent: true });
  assert.equal(storedAttempt(success, successKey).status, 'done');
  assert.equal(success.renderFamilyCalls.length, 1);
  assert.equal(success.localStorage.has('appleservices:auto-refresh:account-a'), false);

  const failure = actionContext({ ok: false, message: 'read failed' });
  const failureKey = 'account-a|family|snapshot-5';
  await failure.__action('family-info', {}, { silent: true });
  assert.equal(storedAttempt(failure, failureKey).status, 'failed');
  assert.equal(failure.localStorage.has('appleservices:auto-refresh:account-a'), false);
});

test('a late refresh response after account switch cannot update the newly selected account', async () => {
  const previousFamily = { member: true, members: 7 };
  const state = actionContext({ ok: true, family: { member: true, members: 2 } }, () => {
    state.selectedAccount = 'account-b';
  });
  state.current = { selected: 'account-a', family: previousFamily };
  state.selectedAccount = 'account-a';

  await state.__action('family-info-direct', {}, { silent: true });

  assert.equal(state.selectedAccount, 'account-b');
  assert.strictEqual(state.current.family, previousFamily);
  assert.equal(state.renderFamilyCalls.length, 0);
  assert.equal(storedAttempt(state, 'account-a|family|snapshot-5').status, 'failed');
  assert.equal(state.localStorage.has('appleservices:auto-refresh:account-a'), false);
  assert.equal(state.localStorage.has('appleservices:auto-refresh:account-b'), false);
});
