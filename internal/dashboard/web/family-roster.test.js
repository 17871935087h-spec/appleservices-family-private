'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const appSource = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

function extractFunction(source, name) {
  const starts = [source.indexOf(`function ${name}(`), source.indexOf(`async function ${name}(`)]
    .filter(index => index >= 0);
  assert.ok(starts.length, `missing function ${name}`);
  const start = Math.min(...starts);
  const open = source.indexOf('{', start);
  assert.notEqual(open, -1, `missing body for ${name}`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  assert.fail(`unterminated function ${name}`);
}

function fakeElement(tag = 'div') {
  const element = {
    tag,
    value: '',
    textContent: '',
    disabled: false,
    options: [],
    children: [],
    classList: { add() {}, remove() {} },
    replaceChildren(...children) {
      this.options = [];
      this.children = [];
      this.value = '';
      this.append(...children);
    },
    append(...children) {
      for (const child of children) {
        this.children.push(child);
        if (child.tag === 'option') this.options.push(child);
      }
    },
  };
  Object.defineProperty(element, 'selectedOptions', {
    get() { return this.options.filter(option => option.value === this.value); },
  });
  return element;
}

function rosterHarness() {
  const elements = Object.fromEntries([
    'familyRemoveMember', 'familyRosterStatus', 'familyRemoveButton', 'familyRosterButton', 'familyCard',
  ].map(id => [id, fakeElement(id === 'familyRemoveMember' ? 'select' : 'div')]));
  let apiHandler = async () => ({ ok: true });
  const apiCalls = [];
  const notices = [];
  const context = {
    selectedAccount: 'organizer-a',
    familyRoster: null,
    familyRosterMessage: '尚未读取',
    familyRosterRequest: 0,
    current: null,
    busy: false,
    document: {
      getElementById: id => elements[id],
      createElement: tag => fakeElement(tag),
      body: { classList: { add() {}, remove() {} } },
    },
    $: id => elements[id],
    api: (...args) => {
      apiCalls.push(JSON.parse(JSON.stringify(args)));
      return apiHandler(...args);
    },
    notice: (...args) => notices.push(args),
    confirm: () => true,
    render() {},
    renderFamily() {},
    poll: async () => {},
  };
  vm.createContext(context);
  const functionNames = [
    'familyRosterStatus', 'renderFamilyRoster', 'invalidateFamilyRoster',
    'familyRosterRequestCurrent', 'readFamilyRoster', 'removeFamilyRosterMember',
  ];
  vm.runInContext(
    `${functionNames.map(name => extractFunction(appSource, name)).join('\n')}\n` +
      `globalThis.rosterAPI={${functionNames.join(',')}};`,
    context,
  );
  return {
    context,
    elements,
    apiCalls,
    notices,
    functions: context.rosterAPI,
    setApi(handler) { apiHandler = handler; },
  };
}

test('dropdown uses only freshly read organizer roster refs, even when local member accounts are absent', async () => {
  const state = rosterHarness();
  const memberRef = 'A'.repeat(43);
  state.context.current = { accounts: [] };
  state.setApi(async (_path, payload) => {
    assert.equal(payload.action, 'family-roster');
    return {
      ok: true,
      message: '已读取组织者当前家庭成员',
      family_roster: {
        members: [{ ref: memberRef, label: '成员 A***@example.test' }],
        unidentified_count: 1,
        total_count: 3,
      },
    };
  });

  await state.functions.readFamilyRoster();
  const options = state.elements.familyRemoveMember.options;
  assert.deepEqual(options.map(option => option.value), ['', memberRef]);
  assert.equal(options[1].textContent, '成员 A***@example.test');
  assert.match(state.elements.familyRosterStatus.textContent, /另有 1 位无法识别/);
  assert.match(state.elements.familyRosterStatus.textContent, /由服务端保护/);
  assert.doesNotMatch(appSource, /renderFamilyMemberOptions/);
  assert.equal(state.apiCalls.length, 1);

  state.elements.familyRemoveMember.value = memberRef;
  state.setApi(async (_path, payload) => {
    assert.equal(payload.action, 'family-remove-ref');
    assert.equal(payload.code, memberRef);
    return { ok: true, message: '组织者已确认成员移出家庭' };
  });
  await state.functions.removeFamilyRosterMember();

  assert.equal(state.apiCalls.length, 2);
  assert.equal(state.apiCalls[1][1].action, 'family-remove-ref');
  assert.equal(state.apiCalls[1][1].code, memberRef);
  assert.equal(state.context.familyRoster, null);
  assert.deepEqual(state.elements.familyRemoveMember.options.map(option => option.value), ['']);
  assert.match(state.elements.familyRosterStatus.textContent, /旧成员名单已清除/);
});

test('switching the selected organizer invalidates an in-flight roster response', async () => {
  const state = rosterHarness();
  let resolveRead;
  state.setApi(() => new Promise(resolve => { resolveRead = resolve; }));

  const pendingRead = state.functions.readFamilyRoster();
  assert.match(state.elements.familyRosterStatus.textContent, /正在读取/);
  const staleRequest = state.context.familyRosterRequest;
  state.context.selectedAccount = 'organizer-b';
  state.functions.invalidateFamilyRoster('当前组织者已切换，请重新读取新组织者的家庭成员名单。');
  resolveRead({
    ok: true,
    family_roster: { members: [{ ref: 'B'.repeat(43), label: '旧组织者成员' }], unidentified_count: 0, total_count: 1 },
  });
  await pendingRead;

  assert.equal(state.context.familyRosterRequest > staleRequest, true);
  assert.equal(state.context.familyRoster, null);
  assert.equal(state.elements.familyRosterStatus.textContent, '当前组织者已切换，请重新读取新组织者的家庭成员名单。');
  assert.deepEqual(state.elements.familyRemoveMember.options.map(option => option.value), ['']);
});

test('read failure clears an older candidate list and explains the unidentified case', async () => {
  const state = rosterHarness();
  state.context.familyRoster = {
    account: 'organizer-a',
    members: [{ ref: 'C'.repeat(43), label: '旧候选' }],
    unidentified_count: 0,
    total_count: 1,
  };
  state.functions.renderFamilyRoster();
  assert.equal(state.elements.familyRemoveMember.options.length, 2);

  state.setApi(async () => ({ ok: false, message: '无法读取组织者当前成员' }));
  await state.functions.readFamilyRoster();
  assert.equal(state.context.familyRoster, null);
  assert.deepEqual(state.elements.familyRemoveMember.options.map(option => option.value), ['']);
  assert.match(state.elements.familyRosterStatus.textContent, /旧成员名单已失效/);

  state.setApi(async () => ({
    ok: true,
    family_roster: { members: [], unidentified_count: 2, total_count: 2 },
  }));
  await state.functions.readFamilyRoster();
  assert.equal(state.elements.familyRemoveButton.disabled, true);
  assert.match(state.elements.familyRosterStatus.textContent, /没有可供选择的已识别成员/);
  assert.match(state.elements.familyRosterStatus.textContent, /2 位成员无法安全识别/);
});

test('an unconfirmed removal invalidates its roster and does not retry', async () => {
  const state = rosterHarness();
  const memberRef = 'D'.repeat(43);
  state.setApi(async () => ({
    ok: true,
    family_roster: { members: [{ ref: memberRef, label: '成员 D***@example.test' }], unidentified_count: 0, total_count: 1 },
  }));
  await state.functions.readFamilyRoster();
  state.elements.familyRemoveMember.value = memberRef;
  state.setApi(async () => ({ ok: false, stage: 'family-remove-unknown', message: '移除结果尚未确认，请先到 Apple 核对' }));

  await state.functions.removeFamilyRosterMember();

  assert.equal(state.apiCalls.length, 2);
  assert.equal(state.apiCalls[1][1].action, 'family-remove-ref');
  assert.equal(state.context.familyRoster, null);
  assert.deepEqual(state.elements.familyRemoveMember.options.map(option => option.value), ['']);
  assert.match(state.elements.familyRosterStatus.textContent, /移除结果尚未确认/);
  assert.match(state.elements.familyRosterStatus.textContent, /旧成员名单已清除/);
});
