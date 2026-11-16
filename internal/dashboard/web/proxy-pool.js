'use strict';
(() => {
  if (typeof document === 'undefined') return;

  const $ = id => document.getElementById(id);
  const token = document.querySelector('meta[name="app-token"]')?.content || '';
  const supportedSchemes = new Set(['http', 'https', 'socks5', 'socks5h']);
  let status = null;
  let statusLoading = false;
  let busy = false;
  let statusSequence = 0;
  let statusPollTimer = null;
  let pageHidden = false;
  let editingID = '';
  let settingsDirty = false;

  function setFeedback(message, tone = 'success') {
    const feedback = $('proxyPoolFeedback');
    feedback.textContent = message;
    feedback.dataset.tone = tone;
    feedback.hidden = !message;
  }

  function setBadge(stateName, label) {
    const badge = $('proxyPoolBadge');
    badge.dataset.state = stateName;
    badge.replaceChildren();
    const dot = document.createElement('i');
    dot.setAttribute('aria-hidden', 'true');
    badge.append(dot, document.createTextNode(label));
  }

  function syncButtons() {
    const writesBlocked = busy || !!status?.applying;
    $('proxyPoolRefresh').disabled = busy || statusLoading;
    $('proxyPoolApply').disabled = writesBlocked || statusLoading || !canApply();
    $('proxyPoolNodeSubmit').disabled = writesBlocked;
    $('proxyPoolSettingsSubmit').disabled = writesBlocked;
    for (const button of $('proxyPoolNodes').querySelectorAll('[data-write-action]')) button.disabled = writesBlocked;
    if (!busy) $('proxyPoolApply').textContent = status?.applying ? '正在应用到账号…' : '启用并应用到账号';
  }

  function invalidatePendingStatus() {
    statusSequence += 1;
    statusLoading = false;
    clearStatusPoll();
    syncButtons();
  }

  function canApply() {
    return !!status?.configured && (status.nodes || []).some(node => node.enabled);
  }

  function nodeAssignedAccounts(nodeID) {
    const node = (status?.nodes || []).find(item => item.id === nodeID);
    const accounts = new Set([
      ...(node?.assigned_accounts || []),
      ...(status?.assignments || []).filter(item => item.node_id === nodeID).map(item => item.account),
      ...(status?.accounts || []).filter(item => item.node_id === nodeID).map(item => item.account_id),
    ].filter(Boolean).map(String));
    return [...accounts];
  }

  function safeEndpoint(node) {
    const scheme = String(node?.scheme || '').toLowerCase();
    const safeScheme = supportedSchemes.has(scheme) ? scheme : '代理';
    let endpoint = String(node?.endpoint || '').trim();
    endpoint = endpoint.split(/[/?#]/, 1)[0];
    endpoint = endpoint.slice(endpoint.lastIndexOf('@') + 1);
    if (!endpoint || /[\r\n\t]/.test(endpoint)) return '—';
    return `${safeScheme}://${endpoint.slice(0, 180)}`;
  }

  function addCell(row, label, value, className = '') {
    const cell = document.createElement('td');
    cell.dataset.label = label;
    if (className) cell.className = className;
    if (value && typeof value === 'object') cell.append(value);
    else cell.textContent = value == null || value === '' ? '—' : String(value);
    row.append(cell);
    return cell;
  }

  function emptyRow(tbody, colspan, message) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = colspan;
    cell.className = 'proxy-pool-empty';
    cell.textContent = message;
    row.append(cell);
    tbody.replaceChildren(row);
  }

  function formatCheckedAt(value) {
    if (!value) return '';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return '';
    return `测试于 ${new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(date)}`;
  }

  function renderNodes() {
    const nodes = status?.nodes || [];
    $('proxyPoolNodeCount').textContent = `${nodes.length} 个节点`;
    if (!nodes.length) {
      emptyRow($('proxyPoolNodes'), 6, status?.configured ? '尚未添加代理节点。支持 http、https、socks5、socks5h。' : '代理池尚未配置；测试并保存一个节点后会显示在这里。');
      return;
    }

    const body = $('proxyPoolNodes');
    body.replaceChildren();
    for (const node of nodes) {
      const row = document.createElement('tr');
      addCell(row, '节点名称', node.id);
      const endpoint = document.createElement('span');
      endpoint.className = 'proxy-pool-endpoint';
      endpoint.textContent = safeEndpoint(node);
      addCell(row, '代理地址', endpoint);

      const exit = document.createElement('span');
      exit.className = 'proxy-pool-ip';
      exit.textContent = node.exit_ip || '尚未测试';
      const exitCell = addCell(row, '已测出口 IP', exit);
      const checkedAt = formatCheckedAt(node.checked_at);
      if (checkedAt) {
        const meta = document.createElement('small');
        meta.className = 'proxy-pool-meta';
        meta.textContent = checkedAt;
        exitCell.append(meta);
      }

      const assigned = nodeAssignedAccounts(node.id);
      addCell(row, '绑定账号', assigned.length ? assigned.join('、') : '未绑定');
      const state = document.createElement('span');
      state.className = `proxy-pool-state ${node.enabled ? 'on' : 'off'}`;
      state.textContent = node.enabled ? '已启用' : '已停用';
      addCell(row, '状态', state);

      const actions = document.createElement('div');
      actions.className = 'proxy-pool-actions';
      const edit = document.createElement('button');
      edit.type = 'button';
      edit.className = 'text-button';
      edit.dataset.writeAction = 'edit';
      edit.textContent = '编辑';
      edit.setAttribute('aria-label', `编辑节点 ${node.id}`);
      edit.addEventListener('click', () => beginEdit(node));
      actions.append(edit);

      if (assigned.length) {
        const blocked = document.createElement('button');
        blocked.type = 'button';
        blocked.className = 'text-button';
        blocked.disabled = true;
        blocked.textContent = '已绑定，不能删除';
        blocked.title = `节点已绑定 ${assigned.length} 个账号，不能删除。`;
        blocked.setAttribute('aria-label', `不能删除节点 ${node.id}：已绑定 ${assigned.length} 个账号`);
        actions.append(blocked);
      } else {
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'text-button danger-text';
        remove.dataset.writeAction = 'delete';
        remove.disabled = busy || !!status?.applying;
        remove.textContent = '删除';
        remove.setAttribute('aria-label', `删除未绑定节点 ${node.id}`);
        remove.addEventListener('click', () => removeNode(node.id));
        actions.append(remove);
      }
      addCell(row, '操作', actions);
      body.append(row);
    }
  }

  const stateLabels = new Map([
    ['running', '运行中'], ['active', '运行中'], ['stopped', '已停止'],
    ['not_running', '未运行'], ['starting', '启动中'], ['error', '需检查'],
    ['failed', '未完成'], ['waiting', '等待中'], ['idle', '空闲'],
  ]);

  function renderAccounts() {
    const accounts = status?.accounts || [];
    if (!accounts.length) {
      emptyRow($('proxyPoolAccounts'), 5, '暂无账号应用状态。应用代理池后，服务端会返回已分配账号。');
      return;
    }
    const body = $('proxyPoolAccounts');
    body.replaceChildren();
    for (const account of accounts) {
      const row = document.createElement('tr');
      addCell(row, '账号', account.account_id);
      addCell(row, '代理节点', account.node_id);
      const exit = document.createElement('span');
      exit.className = 'proxy-pool-ip';
      exit.textContent = account.exit_ip || '—';
      addCell(row, '已测出口 IP', exit);
      const accountRuntime = document.createElement('span');
      accountRuntime.className = `proxy-pool-state ${account.running ? 'on' : 'off'}`;
      accountRuntime.textContent = account.running ? '运行中' : '已停止';
      const runtimeCell = addCell(row, '账号后台', accountRuntime);
      const accountState = stateLabels.get(String(account.state || '').toLowerCase());
      if (accountState) {
        const meta = document.createElement('small');
        meta.className = 'proxy-pool-meta';
        meta.textContent = accountState;
        runtimeCell.append(meta);
      }
      const application = document.createElement('span');
      application.className = `proxy-pool-state ${account.applied ? 'on' : 'off'}`;
      application.textContent = account.applied ? '已应用' : '未应用';
      const applicationCell = addCell(row, '代理应用', application);
      const accountMessage = safeServerMessage(account.message);
      if (accountMessage) {
        const message = document.createElement('small');
        message.className = 'proxy-pool-message';
        message.textContent = accountMessage;
        applicationCell.append(message);
      }
      body.append(row);
    }
  }

  function render(value) {
    status = value;
    const configured = !!value.configured;
    const enabled = !!value.enabled;
    if (value.applying) {
      setBadge('applying', '正在应用');
      $('proxyPoolSummary').textContent = '正在应用代理池到账号；节点、设置和删除操作暂不可用。状态会自动刷新。';
    } else if (!configured) {
      setBadge('unconfigured', '未配置');
      $('proxyPoolSummary').textContent = '尚未配置。添加节点后，服务端会测试真实出口 IP；保存节点不会自动启用代理池。';
    } else if (!enabled) {
      setBadge('disabled', '未启用');
      $('proxyPoolSummary').textContent = '代理池已配置但未启用。应用后会停止旧后台，再恢复账号已保存的会话。';
    } else {
      setBadge('enabled', '已启用');
      $('proxyPoolSummary').textContent = '代理池已启用。节点列表和账号应用状态来自服务端当前状态。';
    }
    if (!settingsDirty) $('proxyPoolMaxAccounts').value = String(value.max_accounts_per_exit || 1);
    renderNodes();
    renderAccounts();
    syncButtons();
    scheduleStatusPoll();
  }

  function safeServerMessage(value) {
    if (typeof value !== 'string') return '';
    const message = value.trim();
    if (!message || message.length > 180 || /(?:https?|socks5h?):\/\/|@|[\u0000-\u001f]|\b(?:password|passwd|token|secret|credential)\b/i.test(message)) return '';
    return message;
  }

  function clearStatusPoll() {
    if (statusPollTimer !== null) window.clearTimeout(statusPollTimer);
    statusPollTimer = null;
  }

  function scheduleStatusPoll() {
    clearStatusPoll();
    if (window.location.hash !== '#proxy-pool' || pageHidden || document.visibilityState === 'hidden' || busy || statusLoading) return;
    statusPollTimer = window.setTimeout(async () => {
      statusPollTimer = null;
      if (window.location.hash === '#proxy-pool' && !pageHidden && document.visibilityState !== 'hidden' && !busy && !statusLoading) await loadStatus({ silent: true });
    }, 2500);
  }

  async function readPayload(response, failureMessage) {
    if (!response?.ok) {
      if (response?.status === 403) throw new Error('面板令牌已失效，请刷新页面后重试。');
      throw new Error(failureMessage);
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error(failureMessage);
    }
    if (!payload || payload.ok !== true) {
      const error = new Error(safeServerMessage(payload?.message) || failureMessage);
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async function loadStatus({ silent = false } = {}) {
    const sequence = ++statusSequence;
    statusLoading = true;
    if (!silent) {
      if (status) setBadge('loading', '正在刷新');
      $('proxyPoolSummary').textContent = status ? '正在刷新代理池状态…' : '正在读取代理池状态…';
    }
    syncButtons();
    try {
      const response = await fetch('/api/proxy-pool/status', {
        method: 'GET',
        headers: { 'X-App-Token': token },
        cache: 'no-store',
      });
      const payload = await readPayload(response, '读取代理池状态失败，请检查服务运行状态后重试。');
      if (sequence !== statusSequence) return false;
      render(payload);
      return true;
    } catch (error) {
      if (sequence !== statusSequence) return false;
      if (!silent || !status) {
        setBadge('error', '读取失败');
        $('proxyPoolSummary').textContent = error.message || '读取代理池状态失败，请稍后重试。';
      }
      if (!status) {
        emptyRow($('proxyPoolNodes'), 6, '状态读取失败。请刷新重试。');
        emptyRow($('proxyPoolAccounts'), 5, '状态读取失败。请刷新重试。');
      }
      return false;
    } finally {
      if (sequence === statusSequence) {
        statusLoading = false;
        syncButtons();
        scheduleStatusPoll();
      }
    }
  }

  function beginEdit(node) {
    if (busy || status?.applying) return;
    editingID = String(node.id || '');
    $('proxyPoolNodeId').value = editingID;
    $('proxyPoolNodeId').readOnly = true;
    $('proxyPoolNodeURL').value = '';
    $('proxyPoolNodeEnabled').checked = !!node.enabled;
    $('proxyPoolFormTitle').textContent = '编辑代理节点';
    $('proxyPoolNodeSubmit').textContent = '测试并保存';
    setFeedback('编辑时不会显示已保存的 URL。留空保留原凭据，并重新测试真实出口 IP。');
    $('proxyPoolNodeId').focus();
  }

  function resetNodeForm() {
    editingID = '';
    $('proxyPoolNodeForm').reset();
    $('proxyPoolNodeId').readOnly = false;
    $('proxyPoolFormTitle').textContent = '添加代理节点';
    $('proxyPoolNodeSubmit').textContent = '测试并保存';
  }

  function validateProxyURL(value, isEditing) {
    if (!value) return isEditing ? '' : '请填写代理 URL。';
    const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(value);
    if (!schemeMatch || !supportedSchemes.has(schemeMatch[1].toLowerCase())) {
      return '仅支持 http、https、socks5、socks5h 代理 URL；订阅、SS 和 VLESS 暂不支持。';
    }
    try {
      const parsed = new URL(value);
      if (!parsed.hostname || (parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
      return '代理 URL 需要填写主机与端口，不能包含路径、查询参数或片段。';
      }
      if (parsed.username && !parsed.password) return '填写了用户名时，也需要填写代理密码。';
    } catch {
      return '代理 URL 格式无效，请检查协议、主机和端口。';
    }
    return '';
  }

  function acceptMutationStatus(payload) {
    if (Array.isArray(payload.nodes)) render(payload);
    else if (payload.status && Array.isArray(payload.status.nodes)) render(payload.status);
  }

  function acceptErrorStatus(error) {
    if (error?.payload) acceptMutationStatus(error.payload);
  }

  async function submitNode() {
    if (busy) return false;
    if (status?.applying) {
      setFeedback('代理池正在应用到账号，请等待状态刷新完成。', 'error');
      return false;
    }
    const id = $('proxyPoolNodeId').value.trim();
    const url = $('proxyPoolNodeURL').value.trim();
    const enabled = !!$('proxyPoolNodeEnabled').checked;
    if (!id || new TextEncoder().encode(id).length > 128 || /[\u0000-\u001f\u007f]/.test(id)) {
      setFeedback('请填写有效的节点名称（UTF-8 最多 128 字节）。', 'error');
      $('proxyPoolNodeId').focus();
      return false;
    }
    if (editingID && id !== editingID) {
      setFeedback('节点名称保存后固定，无法修改。', 'error');
      $('proxyPoolNodeId').focus();
      return false;
    }
    if (!editingID && (status?.nodes || []).some(node => node.id === id)) {
      setFeedback('这个节点名称已存在，请编辑现有节点。', 'error');
      $('proxyPoolNodeId').focus();
      return false;
    }
    const urlError = validateProxyURL(url, !!editingID);
    if (urlError) {
      setFeedback(urlError, 'error');
      $('proxyPoolNodeURL').focus();
      return false;
    }

    invalidatePendingStatus();
    busy = true;
    syncButtons();
    $('proxyPoolNodeSubmit').textContent = '正在测试并保存…';
    setFeedback('正在由服务端测试代理出口并保存节点…');
    let succeeded = false;
    try {
      const response = await fetch('/api/proxy-pool/node', {
        method: 'POST',
        headers: { 'X-App-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, url, enabled }),
        cache: 'no-store',
      });
      const payload = await readPayload(response, '节点测试或保存失败。请检查输入后重试；凭据仍留在输入框中。');
      $('proxyPoolNodeURL').value = '';
      resetNodeForm();
      setFeedback('节点已通过出口测试并保存；代理凭据已从输入框清除。');
      acceptMutationStatus(payload);
      succeeded = true;
      return true;
    } catch (error) {
      acceptErrorStatus(error);
      setFeedback(error.message || '节点测试或保存失败。凭据仍留在输入框中。', 'error');
      return false;
    } finally {
      busy = false;
      syncButtons();
      if (succeeded) await loadStatus({ silent: true });
      else scheduleStatusPoll();
    }
  }

  async function removeNode(id) {
    if (busy) return false;
    if (status?.applying) {
      setFeedback('代理池正在应用到账号，请等待状态刷新完成。', 'error');
      return false;
    }
    const assigned = nodeAssignedAccounts(id);
    if (assigned.length) {
      setFeedback(`节点已绑定 ${assigned.length} 个账号，不能删除。`, 'error');
      return false;
    }
    invalidatePendingStatus();
    busy = true;
    syncButtons();
    setFeedback('正在删除未绑定节点…');
    let succeeded = false;
    try {
      const response = await fetch('/api/proxy-pool/remove', {
        method: 'POST',
        headers: { 'X-App-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
        cache: 'no-store',
      });
      const payload = await readPayload(response, '删除失败；节点可能已绑定账号或状态已变化。刷新状态后重试。');
      acceptMutationStatus(payload);
      setFeedback('代理节点已删除。');
      succeeded = true;
      return true;
    } catch (error) {
      acceptErrorStatus(error);
      setFeedback(error.message || '删除失败；请刷新状态后重试。', 'error');
      return false;
    } finally {
      busy = false;
      syncButtons();
      if (succeeded) await loadStatus({ silent: true });
      else scheduleStatusPoll();
    }
  }

  async function saveSettings() {
    if (busy) return false;
    if (status?.applying) {
      setFeedback('代理池正在应用到账号，请等待状态刷新完成。', 'error');
      return false;
    }
    const value = Number($('proxyPoolMaxAccounts').value);
    if (!Number.isInteger(value) || value < 1 || value > 50000) {
      setFeedback('每出口账号上限必须是 1 到 50000 之间的整数。', 'error');
      $('proxyPoolMaxAccounts').focus();
      return false;
    }
    invalidatePendingStatus();
    busy = true;
    syncButtons();
    setFeedback('正在保存出口容量…');
    let succeeded = false;
    try {
      const response = await fetch('/api/proxy-pool/settings', {
        method: 'POST',
        headers: { 'X-App-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_accounts_per_exit: value }),
        cache: 'no-store',
      });
      const payload = await readPayload(response, '保存出口容量失败，请稍后重试。');
      acceptMutationStatus(payload);
      settingsDirty = false;
      $('proxyPoolMaxAccounts').value = String(value);
      setFeedback('出口容量已保存。');
      succeeded = true;
      return true;
    } catch (error) {
      acceptErrorStatus(error);
      setFeedback(error.message || '保存出口容量失败，请稍后重试。', 'error');
      return false;
    } finally {
      busy = false;
      syncButtons();
      if (succeeded) await loadStatus({ silent: true });
      else scheduleStatusPoll();
    }
  }

  async function applyPool() {
    if (busy) return false;
    if (status?.applying) {
      setFeedback('代理池正在应用到账号，请等待状态刷新完成。', 'error');
      return false;
    }
    if (!canApply()) {
      setFeedback('请先保存并启用至少一个节点，再应用到账号。', 'error');
      return false;
    }
    invalidatePendingStatus();
    busy = true;
    syncButtons();
    $('proxyPoolApply').textContent = '正在启用并应用…';
    setFeedback('正在启用代理池并应用到账号…');
    let succeeded = false;
    try {
      const response = await fetch('/api/proxy-pool/apply', {
        method: 'POST',
        headers: { 'X-App-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
        cache: 'no-store',
      });
      const payload = await readPayload(response, '应用失败，请刷新状态后重试。');
      acceptMutationStatus(payload);
      if (Array.isArray(payload.accounts)) {
        status = { ...(status || {}), ...payload, accounts: payload.accounts, configured: true, enabled: true };
        render(status);
      }
      setFeedback(safeServerMessage(payload.message) || '代理池已启用并发起恢复；实际应用状态见下方。');
      succeeded = true;
      return true;
    } catch (error) {
      acceptErrorStatus(error);
      setFeedback(error.message || '应用失败，请刷新状态后重试。', 'error');
      return false;
    } finally {
      busy = false;
      $('proxyPoolApply').textContent = '启用并应用到账号';
      syncButtons();
      if (succeeded) await loadStatus({ silent: true });
      else scheduleStatusPoll();
    }
  }

  $('proxyPoolNodeForm').addEventListener('submit', event => {
    event.preventDefault();
    submitNode();
  });
  $('proxyPoolSettingsForm').addEventListener('submit', event => {
    event.preventDefault();
    saveSettings();
  });
  $('proxyPoolMaxAccounts').addEventListener('input', () => { settingsDirty = true; });
  $('proxyPoolRefresh').addEventListener('click', loadStatus);
  $('proxyPoolApply').addEventListener('click', applyPool);
  window.addEventListener('hashchange', () => {
    if (window.location.hash === '#proxy-pool') loadStatus();
    else clearStatusPoll();
  });
  window.addEventListener('pagehide', () => {
    pageHidden = true;
    clearStatusPoll();
  });
  window.addEventListener('pageshow', () => {
    pageHidden = false;
    scheduleStatusPoll();
  });
  document.addEventListener?.('visibilitychange', () => {
    if (document.visibilityState === 'hidden') clearStatusPoll();
    else scheduleStatusPoll();
  });

  window.proxyPoolController = { loadStatus, beginEdit, submitNode, removeNode, saveSettings, applyPool };
  if (window.location.hash === '#proxy-pool') loadStatus();
})();
