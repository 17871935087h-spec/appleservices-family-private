'use strict';
(() => {
  const element = id => document.getElementById(id);
  const nodes = Object.fromEntries(['Card','Read','Status','Address','Form','Prefix','Permanent','WebLogin','Create'].map(name => [name, element('primaryMail' + name)]));
  let owner = '', revision = 0, running = false;
  let state = { stage: 'unknown', can_create: false };
  const activeAccount = () => typeof selectedAccount === 'string' ? selectedAccount : '';
  function syncAccount() {
    const account = activeAccount();
    if (account === owner) return;
    owner = account; revision++; running = false;
    state = {stage:'unknown',can_create:false};
    nodes.Prefix.value = ''; nodes.Permanent.checked = false; nodes.WebLogin.checked = false;
    render();
  }
  function render() {
    nodes.Card.setAttribute('aria-busy', String(running));
    nodes.Read.disabled = !owner || running;
    nodes.Read.textContent = running ? '处理中…' : '读取状态';
    const canCreate = state.can_create === true && ['not_open','web_login_required'].includes(state.stage);
    nodes.Form.hidden = !canCreate;
    nodes.Address.hidden = !state.email;
    nodes.Address.textContent = state.email || '';
    nodes.Status.textContent = running ? '正在处理当前账号，请等待结果。' : (state.message || (owner ? '尚未读取当前账号的主邮箱状态。' : '请先选择账号。'));
    nodes.Status.classList.toggle('primary-mail-error', ['outcome_unknown','risk_blocked','terms_required','unavailable'].includes(state.stage));
    for (const key of ['Prefix','Permanent','WebLogin']) nodes[key].disabled = running;
    const prefix = nodes.Prefix.value.trim();
    nodes.Create.disabled = running || !canCreate || !nodes.Permanent.checked || (prefix !== '' && !/^[a-z][a-z0-9._]{2,19}$/.test(prefix));
    nodes.Create.textContent = running ? '正在开通…' : '开通 iCloud 邮箱';
  }
  async function request(action) {
    syncAccount();
    if (!owner || running) return;
    if (action === 'create' && nodes.Create.disabled) return;
    const requestOwner = owner, requestRevision = ++revision;
    const payload = action === 'create' ? {prefix:nodes.Prefix.value.trim(),confirm_permanent:nodes.Permanent.checked,allow_web_login:nodes.WebLogin.checked} : {};
    running = true; render();
    try {
      const response = await fetch('/api/primary-mail/' + action + '?account=' + encodeURIComponent(requestOwner), {method:'POST',headers:{'Content-Type':'application/json','X-App-Token':token},body:JSON.stringify(payload),cache:'no-store'});
      if (!response.ok) throw new Error('request_failed');
      const result = await response.json();
      syncAccount();
      if (owner !== requestOwner || revision !== requestRevision) return;
      if (result.account_id !== owner) throw new Error('account_mismatch');
      state = result;
    } catch {
      syncAccount();
      if (owner !== requestOwner || revision !== requestRevision) return;
      state = {stage:action === 'create' ? 'outcome_unknown' : 'unavailable',can_create:false,message:action === 'create' ? '创建结果待核验，请读取状态，勿重复提交。' : '读取未完成，请检查连接后再次读取。'};
    } finally {
      if (owner === requestOwner && revision === requestRevision) {running = false; render();}
    }
  }
  nodes.Read.addEventListener('click', () => request('status'));
  nodes.Form.addEventListener('submit', event => {event.preventDefault(); request('create');});
  for (const key of ['Prefix','Permanent','WebLogin']) nodes[key].addEventListener('input', render);
  new MutationObserver(syncAccount).observe(element('accountList'), {childList:true});
  window.addEventListener('storage', syncAccount);
  syncAccount(); render();
})();
