'use strict';
(() => {
  const ids = ['Card','Read','Status','SaveConsent','DeviceConsent','Connect','Workspace','CreateForm','Description','PasswordChallenge','Create','ShowResult','SecretPanel','Secret','Copy','Hide','Items','Empty','Review','ReviewConfirm','ReviewButton'];
  const nodes = Object.fromEntries(ids.map(name => [name, document.getElementById('appPasswords' + name)]));
  const stageMessages = {
    idle: '选择账号后读取状态。不会自动连接或生成密码。',
    session_required: '需要先连接管理会话。连接前请明确勾选本机保存和受信任设备验证授权。',
    ready: '管理会话已就绪。读取列表后可新建 App 专用密码。',
    generated: '密码已生成。请妥善保存；密码不会显示在列表中。',
    password_required: '当前步骤需要主密码复核。只有勾选本次允许后，才会继续。',
    verification_required: '需要受信任设备验证。此流程不会发送短信。',
    risk_blocked: 'Apple 暂停了此操作。请稍后从状态读取恢复，不要重复提交。',
    terms_required: '需要先在 Apple 页面确认条款；本面板不会代替确认。',
    credential_required: '当前账号没有可用的已保存密码，请先检查管理会话。',
    outcome_unknown: '新建结果待核对。请读取列表确认状态；核对前不会允许再次新建。',
    busy: '当前账号仍在处理中，请等待状态更新。',
    invalid_request: '请求未通过校验。请检查标签后读取状态。',
    unavailable: '读取或连接未完成，请检查连接后重新读取。'
  };
  const busyMessages = {
    status: '正在读取当前账号的密码列表…',
    connect: '正在连接管理会话…',
    create: '正在提交新建请求…',
    result: '正在读取最近一次生成结果…',
    review: '正在解除本机待核对阻挡…'
  };
  let owner = '';
  let revision = 0;
  let running = false;
  let currentAction = '';
  let controller = null;
  let secret = '';
  let feedback = '';
  let listRead = false;
  let visibilityRevision = 0;
  let state = {stage:'idle',can_create:false,result_available:false,items:[]};
  const unknownByAccount = new Map();
  const pendingCreateByAccount = new Map();
  const reviewReadAccounts = new Set();
  const createLatch = new Set();
  const activeAccount = () => typeof selectedAccount === 'string' ? selectedAccount : '';
  const safeString = value => typeof value === 'string' ? value : (typeof value === 'number' && Number.isFinite(value) ? String(value) : '');
  const requestCurrent = (requestOwner, requestRevision) => owner === requestOwner && revision === requestRevision;

  function clearSecret() {
    secret = '';
    nodes.Secret.textContent = '';
    nodes.SecretPanel.hidden = true;
  }

  function syncAccount() {
    const account = activeAccount();
    if (account === owner) return false;
    revision++;
    if (controller) controller.abort();
    controller = null;
    running = false;
    currentAction = '';
    clearSecret();
    feedback = '';
    listRead = false;
    owner = account;
    state = unknownByAccount.has(owner)
      ? {stage:'outcome_unknown',can_create:false,result_available:false,request_id:unknownByAccount.get(owner),items:[]}
      : {stage:'idle',can_create:false,result_available:false,items:[]};
    nodes.SaveConsent.checked = false;
    nodes.DeviceConsent.checked = false;
    nodes.PasswordChallenge.checked = false;
    nodes.ReviewConfirm.checked = false;
    nodes.Description.value = pendingCreateByAccount.has(owner) ? pendingCreateByAccount.get(owner).description : '邮件客户端';
    render();
    return true;
  }

  function responseState(result) {
    const knownStage = Object.prototype.hasOwnProperty.call(stageMessages, result.stage) && result.stage !== 'idle';
    const items = Array.isArray(result.items) ? result.items.filter(item => item && typeof item === 'object').map(item => ({
      id:safeString(item.id),
      description:safeString(item.description),
      created_at:safeString(item.created_at)
    })) : [];
    return {
      stage:knownStage ? result.stage : 'unavailable',
      can_create:result.can_create === true,
      result_available:result.result_available === true,
      request_id:safeString(result.request_id),
      description:safeString(result.description),
      items
    };
  }

  function message() {
    if (running) return busyMessages[currentAction] || '正在处理当前账号…';
    if (feedback) return feedback;
    return stageMessages[state.stage] || stageMessages.idle;
  }

  function renderItems() {
    nodes.Items.replaceChildren();
    const items = Array.isArray(state.items) ? state.items : [];
    for (const item of items) {
      const row = document.createElement('li');
      const label = document.createElement('span');
      const time = document.createElement('span');
      label.textContent = item.description || '未命名';
      time.textContent = item.created_at || '';
      row.append(label,time);
      nodes.Items.append(row);
    }
    nodes.Empty.hidden = items.length > 0;
    if (!items.length) nodes.Empty.textContent = !owner
      ? '请先选择账号。'
      : (listRead ? '尚无专用密码。' : '尚未读取当前账号的密码列表。');
  }

  function render() {
    const blockId = unknownByAccount.get(owner) || '';
    const hasUnknown = Boolean(owner && unknownByAccount.has(owner));
    const continuation = pendingCreateByAccount.get(owner);
    const continuingPasswordChallenge = Boolean(continuation && state.stage === 'password_required');
    const showCreateForm = owner && !running && !hasUnknown && (
      continuingPasswordChallenge || (state.stage === 'ready' && state.can_create === true && !pendingCreateByAccount.has(owner))
    );
    const canCreate = owner && !running && !hasUnknown && (
      (continuingPasswordChallenge && nodes.PasswordChallenge.checked && nodes.Description.value.trim() === continuation.description) ||
      (!continuingPasswordChallenge && !pendingCreateByAccount.has(owner) && !createLatch.has(owner) && state.stage === 'ready' && state.can_create === true)
    );
    nodes.Card.setAttribute('aria-busy', String(running));
    nodes.Read.disabled = !owner || running;
    nodes.Read.textContent = running && currentAction === 'status' ? '正在读取…' : '读取列表';
    nodes.Status.textContent = message();
    nodes.Status.dataset.tone = ['risk_blocked','terms_required','credential_required','outcome_unknown','invalid_request','unavailable'].includes(state.stage) || (feedback && /失败|待核对|暂停|阻挡/.test(feedback)) ? 'error' : 'normal';
    nodes.SaveConsent.disabled = !owner || running;
    nodes.DeviceConsent.disabled = !owner || running;
    nodes.Connect.disabled = !owner || running || !nodes.SaveConsent.checked || !nodes.DeviceConsent.checked;
    nodes.Connect.textContent = running && currentAction === 'connect' ? '正在连接…' : '连接管理会话';
    nodes.Workspace.hidden = !owner || state.stage === 'idle';
    nodes.CreateForm.hidden = !showCreateForm;
    nodes.Description.disabled = !showCreateForm || continuingPasswordChallenge;
    nodes.PasswordChallenge.disabled = !showCreateForm;
    nodes.Create.disabled = !canCreate;
    nodes.Create.textContent = running && currentAction === 'create' ? '正在新建…' : (continuingPasswordChallenge ? '继续复核并新建' : '新建 App 专用密码');
    nodes.ShowResult.hidden = !owner || state.result_available !== true || !state.request_id;
    nodes.ShowResult.disabled = running;
    nodes.SecretPanel.hidden = !secret;
    nodes.Secret.textContent = secret;
    nodes.Copy.disabled = !secret || running;
    nodes.Hide.disabled = !secret;
    nodes.Review.hidden = !hasUnknown;
    nodes.ReviewConfirm.disabled = !hasUnknown || running;
    nodes.ReviewButton.disabled = !hasUnknown || !blockId || running || !reviewReadAccounts.has(owner) || !nodes.ReviewConfirm.checked;
    renderItems();
  }

  function lockUnknown(requestId) {
    if (owner) {
      unknownByAccount.set(owner, requestId || '');
      pendingCreateByAccount.delete(owner);
      reviewReadAccounts.delete(owner);
    }
    listRead = false;
    state = {...state,stage:'outcome_unknown',can_create:false,request_id:requestId || state.request_id || ''};
    nodes.ReviewConfirm.checked = false;
  }

  function normalizedDescription(value) {
    return Array.from(value).slice(0,64).join('');
  }

  function currentDescription() {
    return normalizedDescription(nodes.Description.value.trim() || '邮件客户端');
  }

  function limitDescriptionInput() {
    const points = Array.from(nodes.Description.value);
    if (points.length > 64) nodes.Description.value = points.slice(0,64).join('');
  }

  function payloadFor(action, requestId) {
    if (action === 'connect') return {allow_web_login:true,allow_device_verification:true};
    if (action === 'create') return {
      description:currentDescription(),
      request_id:requestId,
      allow_password_challenge:nodes.PasswordChallenge.checked === true
    };
    if (action === 'result' || action === 'review') return {request_id:requestId};
    return {};
  }

  function applyResponse(action, result, requestId, canRevealSecret=false) {
    let next = responseState(result);
    if (action === 'status') {
      listRead = true;
      if (next.stage === 'outcome_unknown') {
        lockUnknown(next.request_id || requestId);
        listRead = true;
        if (next.request_id) unknownByAccount.set(owner,next.request_id);
        reviewReadAccounts.add(owner);
        state = {...next,stage:'outcome_unknown',can_create:false,request_id:next.request_id || requestId};
      } else if (unknownByAccount.has(owner)) {
        const lockedId = next.request_id || unknownByAccount.get(owner) || '';
        if (lockedId) unknownByAccount.set(owner,lockedId);
        reviewReadAccounts.add(owner);
        state = {...next,stage:'outcome_unknown',can_create:false,request_id:lockedId};
      } else {
        state = next;
        if (state.stage === 'password_required' && state.request_id && pendingCreateByAccount.has(owner)) {
          const pending = pendingCreateByAccount.get(owner);
          pendingCreateByAccount.set(owner,{requestId:state.request_id,description:pending.description});
        }
        if (state.stage === 'ready' && state.can_create) {
          createLatch.delete(owner);
          pendingCreateByAccount.delete(owner);
        }
      }
      return;
    }
    if (action === 'create') {
      if (next.stage === 'outcome_unknown') {
        lockUnknown(next.request_id || requestId);
        state = {...next,stage:'outcome_unknown',can_create:false,request_id:next.request_id || requestId};
        return;
      }
      if (next.stage === 'password_required') {
        const pending = pendingCreateByAccount.get(owner);
        pendingCreateByAccount.set(owner,{requestId:next.request_id || requestId,description:pending ? pending.description : safeString(payloadFor('create',requestId).description)});
        state = {...next,request_id:next.request_id || requestId,can_create:false};
        createLatch.delete(owner);
        return;
      }
      pendingCreateByAccount.delete(owner);
      listRead = false;
      state = {...next,request_id:next.request_id || requestId};
      if (next.stage === 'generated' && typeof result.password === 'string' && result.password.length > 0) {
        if (canRevealSecret) {
          secret = result.password;
          feedback = '密码已显示。复制后请立即保存，或隐藏并清除。';
        } else {
          clearSecret();
          feedback = '结果已保存，返回后显式恢复。';
        }
      }
      return;
    }
    if (action === 'result') {
      const preservedItems = state.items;
      state = unknownByAccount.has(owner)
        ? {...next,stage:'outcome_unknown',can_create:false,request_id:unknownByAccount.get(owner),items:preservedItems}
        : {...next,items:preservedItems};
      if (typeof result.password === 'string' && result.password.length > 0) {
        if (canRevealSecret) {
          secret = result.password;
          feedback = '最近一次生成结果已显示。复制后请立即保存，或隐藏并清除。';
        } else {
          clearSecret();
          feedback = '结果已保存，返回后显式恢复。';
        }
      } else {
        feedback = '最近一次结果暂不可显示，请重新读取列表。';
      }
      return;
    }
    if (action === 'review') {
      if (next.stage === 'session_required' || (next.stage === 'ready' && next.can_create)) {
        unknownByAccount.delete(owner);
        reviewReadAccounts.delete(owner);
        createLatch.delete(owner);
        pendingCreateByAccount.delete(owner);
        state = next;
        feedback = next.stage === 'ready'
          ? '已解除本机阻挡。列表已核对，可以新建。'
          : '已解除本机阻挡，请显式读取列表后再新建。';
      } else {
        state = {...next,stage:'outcome_unknown',can_create:false,request_id:unknownByAccount.get(owner) || requestId};
      }
      nodes.ReviewConfirm.checked = false;
      return;
    }
    state = next;
    if (action === 'connect') {
      nodes.SaveConsent.checked = false;
      nodes.DeviceConsent.checked = false;
    }
  }

  async function request(action) {
    syncAccount();
    if (!owner || running) return;
    const blockId = unknownByAccount.get(owner) || '';
    if (action === 'connect' && (!nodes.SaveConsent.checked || !nodes.DeviceConsent.checked)) return;
    const continuation = pendingCreateByAccount.get(owner);
    const continuingPasswordChallenge = Boolean(continuation && state.stage === 'password_required');
    if (action === 'create' && unknownByAccount.has(owner)) return;
    if (action === 'create' && continuingPasswordChallenge && (!nodes.PasswordChallenge.checked || nodes.Description.value.trim() !== continuation.description || createLatch.has(owner))) return;
    if (action === 'create' && !continuingPasswordChallenge && (state.stage !== 'ready' || state.can_create !== true || createLatch.has(owner) || pendingCreateByAccount.has(owner))) return;
    if (action === 'result' && (state.result_available !== true || !state.request_id)) return;
    if (action === 'review' && (!blockId || !reviewReadAccounts.has(owner) || !nodes.ReviewConfirm.checked)) return;
    let requestId = action === 'create' ? (continuingPasswordChallenge ? continuation.requestId : crypto.randomUUID()) : (action === 'review' ? blockId : state.request_id || '');
    if (action === 'create' && !requestId) {
      feedback = '无法生成安全请求编号，请重新读取状态。'; render(); return;
    }
    const requestOwner = owner;
    const requestRevision = ++revision;
    const requestVisibilityRevision = visibilityRevision;
    controller = new AbortController();
    const activeController = controller;
    running = true;
    currentAction = action;
    feedback = '';
    if (action === 'create') {
      createLatch.add(owner);
      if (!continuingPasswordChallenge) pendingCreateByAccount.set(owner,{requestId,description:currentDescription()});
    }
    render();
    try {
      const response = await fetch('/api/app-passwords/' + action + '?account=' + encodeURIComponent(requestOwner), {
        method:'POST',
        headers:{'Content-Type':'application/json','X-App-Token':token},
        body:JSON.stringify(payloadFor(action,requestId)),
        cache:'no-store',
        signal:activeController.signal
      });
      if (!response.ok) throw new Error('request_failed');
      const result = await response.json();
      syncAccount();
      if (!requestCurrent(requestOwner,requestRevision)) return;
      if (!result || result.account_id !== requestOwner) throw new Error('account_mismatch');
      if ((action === 'create' || action === 'result') && result.request_id && result.request_id !== requestId) throw new Error('request_mismatch');
      const canRevealSecret = visibilityRevision === requestVisibilityRevision && document.visibilityState === 'visible';
      applyResponse(action,result,requestId,canRevealSecret);
    } catch (error) {
      if (!requestCurrent(requestOwner,requestRevision)) return;
      if (action === 'create') {
        lockUnknown(requestId);
        feedback = '';
      } else if (action === 'status') {
        if (unknownByAccount.has(owner)) {
          state = {...state,stage:'outcome_unknown',can_create:false,request_id:unknownByAccount.get(owner) || state.request_id};
        } else {
          state = {...state,stage:'unavailable',can_create:false};
        }
        feedback = '读取未完成，请检查连接后重新读取。';
      } else if (action === 'review') {
        state = {...state,stage:'outcome_unknown',can_create:false,request_id:unknownByAccount.get(owner) || requestId};
        feedback = '未能解除待核对阻挡，请重新读取列表。';
      } else if (action === 'result') {
        feedback = '最近一次结果未能读取，请稍后重试。';
      } else {
        state = {...state,stage:'unavailable',can_create:false};
        feedback = '管理会话连接未完成，请读取状态后重试。';
      }
    } finally {
      if (requestCurrent(requestOwner,requestRevision)) {
        running = false;
        currentAction = '';
        controller = null;
        render();
      }
    }
  }

  nodes.Read.addEventListener('click',() => request('status'));
  nodes.Connect.addEventListener('click',() => request('connect'));
  nodes.CreateForm.addEventListener('submit',event => {event.preventDefault(); return request('create');});
  nodes.ShowResult.addEventListener('click',() => request('result'));
  nodes.ReviewButton.addEventListener('click',() => request('review'));
  nodes.Copy.addEventListener('click',async() => {
    const value = secret;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      if (secret === value) {feedback = '已复制到剪贴板，请妥善保存。'; render();}
    } catch {
      if (secret === value) {feedback = '复制失败，请手动选择并复制密码。'; render();}
    }
  });
  nodes.Hide.addEventListener('click',() => {clearSecret();feedback = '密码已从页面清除。需要时可再次读取最近结果。';render();});
  for (const key of ['SaveConsent','DeviceConsent','PasswordChallenge','ReviewConfirm']) nodes[key].addEventListener('input',render);
  nodes.Description.addEventListener('input',() => {limitDescriptionInput();render();});
  document.addEventListener('visibilitychange',() => {
    if (document.visibilityState === 'hidden') {visibilityRevision++;clearSecret();feedback = '页面已隐藏，密码显示已清除。';render();}
  });
  window.addEventListener('pagehide',() => {visibilityRevision++;clearSecret();});
  new MutationObserver(syncAccount).observe(document.getElementById('accountList'),{childList:true});
  window.addEventListener('storage',syncAccount);
  syncAccount();
  render();
})();
