const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

function chips(target, values, empty = '暂无') {
  const items = Array.isArray(values) ? values : [];
  target.innerHTML = items.length ? items.map((value) => `<span class="chip">${esc(value)}</span>`).join('') : `<span class="empty">${empty}</span>`;
}

function stateClass(state) {
  return String(state || 'STARTING').toLowerCase().replace(/[^a-z_]/g, '-');
}

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString('zh-CN', {hour12: false});
}

const JEV_TEST_ENDPOINT = '/api/jev/test';
const LOGIN_ENDPOINT = '/api/login';
const JEV_KEY_ENDPOINT = '/api/jev/key';
const JEV_KEY_CLEAR_ENDPOINT = '/api/jev/key/clear';
const EXPERIMENT_SAMPLES_ENDPOINT = '/api/experiments/samples';
const EXPERIMENT_REPLAY_ENDPOINT = '/api/experiments/replay';
const RESEARCH_ENDPOINT = '/api/research/suite';
const MAX_SAMPLE_BYTES = 64 * 1024;
const MAX_SAMPLE_CHARS = 4096;
let authenticated = false;
let jevKeySaved = false;
let protectionSamples = [];
let protectionSample = null;
let protectionSampleMeta = null;

function showLogin(message = '本地实验账号：admin / admin') {
  authenticated = false;
  jevKeySaved = false;
  updateJevKeyStatus(false);
  $('app-shell').hidden = true;
  $('auth-gate').hidden = false;
  $('login-feedback').textContent = message;
  $('login-feedback').className = message.includes('错误') ? 'auth-feedback error' : 'auth-feedback';
  $('login-password').value = '';
  $('login-password').focus();
}

function showApp() {
  authenticated = true;
  $('auth-gate').hidden = true;
  $('app-shell').hidden = false;
}

function updateJevKeyStatus(saved) {
  const status = $('jev-key-status');
  const forget = $('jev-forget-key');
  if (!status || !forget) return;
  status.textContent = saved ? '已永久保存到本机（留空即可复用）' : '未保存';
  forget.disabled = !saved;
}

function protectionClass(value) {
  return String(value || '').toLowerCase().replace(/[^a-z_]/g, '-');
}

function setProtectionFeedback(message, kind = '') {
  const target = $('protection-feedback');
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

function renderIndustrialCase(meta) {
  const card = $('protection-industrial');
  if (!card) return;
  const visible = Boolean(meta && meta.id === 'warehouse_amr');
  card.hidden = !visible;
  if (!visible) return;
  $('protection-industrial-description').textContent = meta.description || '—';
  $('protection-industrial-mission').textContent = meta.mission || `${meta.robot || '—'} · —`;
  $('protection-industrial-phase').textContent = meta.phase || '—';
  $('protection-industrial-topics').textContent = Array.isArray(meta.topics) ? meta.topics.join('、') : '—';
  $('protection-industrial-threats').textContent = Array.isArray(meta.threats) ? meta.threats.join('、') : '—';
  $('protection-jev-summary').textContent = meta.jev_context?.summary || '暂无 Jev 摘要';
}

function setProtectionSample(sample, label = '样例已载入', metadata = null) {
  protectionSample = sample;
  protectionSampleMeta = metadata;
  renderIndustrialCase(metadata);
  $('protection-run').disabled = !sample;
  $('protection-result').hidden = true;
  setProtectionFeedback(label, sample ? 'success' : '');
}

function renderProtectionSamples(payload) {
  protectionSamples = Array.isArray(payload?.samples) ? payload.samples : [];
  const select = $('protection-sample-select');
  select.innerHTML = protectionSamples.length
    ? protectionSamples.map((item) => `<option value="${esc(item.id)}">${esc(item.title)} · ${esc(item.expected)}</option>`).join('')
    : '<option value="">暂无内置样例</option>';
  if (protectionSamples.length) setProtectionSample(null, '请选择“导入内置样例”或上传 JSON');
  else setProtectionFeedback('内置样例读取失败，请上传 guardian-replay/v1 JSON。', 'error');
}

async function loadProtectionSamples() {
  try {
    const response = await fetch(EXPERIMENT_SAMPLES_ENDPOINT, {cache: 'no-store'});
    const payload = await parseJsonResponse(response);
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    renderProtectionSamples(payload);
  } catch (error) {
    setProtectionFeedback(`无法读取内置防护样例：${redactJevMessage(error.message)}`, 'error');
  }
}

function loadSelectedProtectionSample() {
  const id = $('protection-sample-select').value;
  const entry = protectionSamples.find((item) => item.id === id);
  if (!entry) return setProtectionSample(null, '没有可导入的内置样例');
  setProtectionSample(entry.sample, `已导入：${entry.title} · ${entry.expected}`, entry);
}

async function loadProtectionFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > MAX_SAMPLE_BYTES) return setProtectionFeedback('样例文件不能超过 64 KiB。', 'error');
  try {
    const sample = JSON.parse(await file.text());
    if (!sample || sample.schema !== 'guardian-replay/v1') throw new Error('schema');
    setProtectionSample(sample, `已导入文件：${file.name} · 点击“执行防护判断”`);
  } catch (_error) {
    setProtectionSample(null, '样例必须是有效的 guardian-replay/v1 JSON 文件');
    setProtectionFeedback('样例必须是有效的 guardian-replay/v1 JSON 文件。', 'error');
  }
}

function loadIndustrialJevContext() {
  const summary = protectionSampleMeta?.jev_context?.summary;
  if (!summary) return setProtectionFeedback('当前样例没有可带入 Jev 的语义摘要。', 'error');
  $('jev-state').value = summary;
  setWorkspacePanel('jev');
  setJevStatus('idle', '未测试');
  setJevFeedback('已从仓储 AMR 案例带入摘要；请检查后再测试连接。');
}

function renderProtectionReport(report) {
  const final = report.final || {};
  const summary = report.summary || {};
  const safety = final.safety || {};
  const plan = final.plan || {};
  $('protection-summary').innerHTML = [
    `<span>最终状态 <strong>${esc(safety.state || '—')}</strong></span>`,
    `<span>任务 <strong>${safety.mission_allowed ? '允许' : '锁定'}</strong></span>`,
    `<span>动作 <strong>${esc(plan.action || '—')}</strong></span>`,
    `<span>速度上限 <strong>${Number(safety.speed_limit || 0).toFixed(2)} m/s</strong></span>`,
    `<span>接受/拒绝 <strong>${Number(summary.accepted || 0)} / ${Number(summary.rejected || 0)}</strong></span>`,
  ].join('');
  $('protection-steps').innerHTML = (Array.isArray(report.steps) ? report.steps : []).map((step) => {
    const verification = step.verification || {};
    const risk = step.risk || {};
    const rowSafety = step.safety || {};
    const rowPlan = step.plan || {};
    const code = verification.code || '—';
    return `<tr><td>${Number(step.at || 0).toFixed(2)} s</td><td class="${protectionClass(code)}">${esc(code)}</td><td>${(Number(risk.risk || 0) * 100).toFixed(1)} / ${esc(risk.reason || '—')}</td><td>${esc(rowPlan.action || '—')}</td><td class="${protectionClass(rowSafety.state)}">${esc(rowSafety.state || '—')}</td><td>${Number(rowSafety.speed_limit || 0).toFixed(2)} m/s</td></tr>`;
  }).join('');
  $('protection-result').hidden = false;
}

async function runProtectionReplay() {
  if (!protectionSample) return setProtectionFeedback('请先导入一个防护样例。', 'error');
  $('protection-run').disabled = true;
  setProtectionFeedback('正在运行离线防护判断…');
  try {
    const response = await fetch(EXPERIMENT_REPLAY_ENDPOINT, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store', body: JSON.stringify(protectionSample),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || payload?.status !== 'OK' || !payload.report) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    renderProtectionReport(payload.report);
    setProtectionFeedback('防护判断完成：结果来自同一套校验、风险、缓解和安全监督逻辑。', 'success');
  } catch (error) {
    setProtectionFeedback(`防护判断失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    $('protection-run').disabled = !protectionSample;
  }
}

async function loadJevKeyStatus() {
  try {
    const response = await fetch(JEV_KEY_ENDPOINT, {cache: 'no-store'});
    if (!response.ok) {
      jevKeySaved = false;
      updateJevKeyStatus(false);
      return;
    }
    const payload = await parseJsonResponse(response);
    jevKeySaved = payload?.saved === true;
    updateJevKeyStatus(jevKeySaved);
  } catch (_error) {
    jevKeySaved = false;
    updateJevKeyStatus(false);
  }
}

async function saveJevKey(apiKey) {
  const response = await fetch(JEV_KEY_ENDPOINT, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    cache: 'no-store',
    body: JSON.stringify({api_key: apiKey}),
  });
  const payload = await parseJsonResponse(response);
  if (!response.ok || !payload || payload.saved !== true) {
    if (response.status === 404) throw new Error('保存接口未部署，请重启 guardian-dashboard.service');
    throw new Error(redactJevMessage(payload?.error?.message || `保存失败（HTTP ${response.status}）`));
  }
  jevKeySaved = true;
  updateJevKeyStatus(true);
}

async function saveJevKeyFromInput() {
  const key = $('jev-api-key').value.trim();
  if (!key) {
    setJevFeedback('请输入要保存或更新的 Jev Key', 'error');
    $('jev-api-key').focus();
    return;
  }
  try {
    await saveJevKey(key);
    setJevFeedback('Jev Key 已保存到本机；刷新、退出或服务重启后仍可复用。', 'success');
  } catch (error) {
    setJevFeedback(`保存失败：${redactJevMessage(error.message)}`, 'error');
  }
}

async function forgetJevKey() {
  try {
    const response = await fetch(JEV_KEY_CLEAR_ENDPOINT, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store', body: '{}',
    });
    if (!response.ok) throw new Error('clear failed');
    jevKeySaved = false;
    updateJevKeyStatus(false);
    $('jev-api-key').value = '';
    setJevFeedback('已清除本机保存的 Jev Key；如需继续调用，请重新输入并保存。');
  } catch (_error) {
    setJevFeedback('清除 Jev Key 失败', 'error');
  }
}

async function loadSampleFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > MAX_SAMPLE_BYTES) {
    $('jev-sample-feedback').textContent = '样例文件不能超过 64 KiB';
    return;
  }
  try {
    let sample = await file.text();
    if (file.name.toLowerCase().endsWith('.json')) {
      const parsed = JSON.parse(sample);
      if (typeof parsed === 'string') sample = parsed;
      else if (parsed && typeof parsed.state === 'string') sample = parsed.state;
      else if (parsed && typeof parsed.summary === 'string') sample = parsed.summary;
      else sample = JSON.stringify(parsed, null, 2);
    }
    if (!sample.trim()) throw new Error('empty');
    if (sample.length > MAX_SAMPLE_CHARS) {
      $('jev-sample-feedback').textContent = '样例内容超过 4096 个字符，请先缩短';
      return;
    }
    $('jev-state').value = sample;
    $('jev-sample-feedback').textContent = `已加载样例：${file.name}`;
    setJevFeedback('样例已载入，点击“测试连接”发送');
  } catch (_error) {
    $('jev-sample-feedback').textContent = '无法读取样例文件，请使用 TXT、LOG、CSV 或 JSON';
  }
}

async function login(event) {
  event.preventDefault();
  const username = $('login-username').value.trim();
  const password = $('login-password').value;
  if (!username || !password) {
    showLogin('请输入用户名和密码');
    return;
  }
  const response = await fetch(LOGIN_ENDPOINT, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store',
    body: JSON.stringify({username, password}),
  });
  const payload = await parseJsonResponse(response);
  if (!response.ok || !payload || payload.authenticated !== true) {
    showLogin('用户名或密码错误');
    return;
  }
  showApp();
  await loadJevKeyStatus();
  await loadProtectionSamples();
  refresh();
}

async function logout() {
  await fetch('/api/logout', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}', cache: 'no-store'});
  showLogin();
}

async function setupAuth() {
  $('login-form').addEventListener('submit', login);
  $('logout').addEventListener('click', logout);
  try {
    const response = await fetch('/api/session', {cache: 'no-store'});
    if (response.ok) {
      showApp();
      await loadJevKeyStatus();
      await loadProtectionSamples();
      refresh();
    } else {
      showLogin();
    }
  } catch (_error) {
    showLogin('无法连接本地服务');
  }
}

function finiteNumber(value, fallback = 0) {
  if (value === null || value === undefined || value === '') return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function formatJevNumber(value) {
  const number = finiteNumber(value, NaN);
  return Number.isFinite(number) ? number.toFixed(3) : '—';
}

function redactJevMessage(value) {
  return String(value || 'Jev 请求失败')
    .replace(/(api[_ -]?key|authorization|credential|password|secret|token)\s*[:=]\s*[^\s,;]+/gi, '$1=<redacted>')
    .slice(0, 320);
}

function setJevStatus(kind, label) {
  const status = $('jev-status');
  status.className = `pill jev-status ${kind}`;
  status.textContent = label;
}

function setJevFeedback(message, kind = '') {
  const feedback = $('jev-feedback');
  feedback.className = `jev-feedback muted ${kind}`.trim();
  feedback.textContent = message;
}

function setJevBusy(busy) {
  $('jev-test').disabled = busy;
  $('jev-clear').disabled = busy;
  $('jev-form').setAttribute('aria-busy', String(busy));
}

function resetJevResult() {
  $('jev-result').hidden = true;
  $('jev-label').textContent = '—';
  $('jev-impact').textContent = '—';
  $('jev-score').textContent = '—';
  $('jev-confidence').textContent = '—';
  $('jev-review').textContent = '—';
  $('jev-model').textContent = '—';
  $('jev-reason').textContent = '—';
}

function renderJevAssessment(payload) {
  const assessment = payload.assessment || {};
  const latency = finiteNumber(payload.latency_ms, NaN);
  const model = String(assessment.model || '—');
  $('jev-label').textContent = String(assessment.label || 'UNKNOWN');
  $('jev-impact').textContent = String(assessment.mission_impact || 'unknown');
  $('jev-score').textContent = formatJevNumber(assessment.score);
  $('jev-confidence').textContent = formatJevNumber(assessment.confidence);
  $('jev-review').textContent = assessment.needs_human_review === true ? '是' : '否';
  $('jev-model').textContent = Number.isFinite(latency) ? `${model} · ${latency.toFixed(0)} ms` : model;
  $('jev-reason').textContent = String(assessment.reason || '—');
  $('jev-result').hidden = false;
}

function jevErrorMessage(payload, response) {
  const error = payload && typeof payload.error === 'object' ? payload.error : {};
  const code = String(error.code || '').trim();
  const message = redactJevMessage(error.message || `Jev 请求失败（HTTP ${response.status}）`);
  return code ? `${code}: ${message}` : message;
}

async function parseJsonResponse(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

async function testJev(event) {
  event.preventDefault();
  const typedApiKey = $('jev-api-key').value.trim();
  const useSavedKey = !typedApiKey && jevKeySaved;
  const state = $('jev-state').value.trim();
  resetJevResult();

  if (!typedApiKey && !useSavedKey) {
    setJevStatus('error', '缺少 API Key');
    setJevFeedback('请输入 API Key 后再测试', 'error');
    $('jev-api-key').focus();
    return;
  }
  if (!state) {
    setJevStatus('error', '缺少测试状态');
    setJevFeedback('请输入一段测试状态', 'error');
    $('jev-state').focus();
    return;
  }

  setJevBusy(true);
  setJevStatus('loading', '请求中');
  setJevFeedback('正在验证 Jev 连接…');
  const startedAt = performance.now();

  try {
    const requestBody = {state};
    if (typedApiKey) requestBody.api_key = typedApiKey;
    else requestBody.use_saved_key = true;
    const response = await fetch(JEV_TEST_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify(requestBody),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || !payload || payload.status !== 'OK' || payload.connected !== true || !payload.assessment) {
      throw new Error(jevErrorMessage(payload, response));
    }

    renderJevAssessment(payload);
    const latency = finiteNumber(payload.latency_ms, performance.now() - startedAt);
    let saveSuffix = '';
    if (typedApiKey) {
      try {
        await saveJevKey(typedApiKey);
      } catch (error) {
        const detail = error instanceof Error ? error.message : '保存接口不可用';
        saveSuffix = `（本次调用成功，但持久保存失败：${detail}）`;
      }
    }
    setJevStatus('success', '已连接');
    setJevFeedback(`Jev 调用成功 · ${latency.toFixed(0)} ms${saveSuffix}`, saveSuffix ? 'error' : 'success');
  } catch (error) {
    setJevStatus('error', '连接失败');
    const message = error instanceof Error ? error.message : '无法连接本地 Jev 接口';
    setJevFeedback(redactJevMessage(message), 'error');
  } finally {
    setJevBusy(false);
  }
}

function clearJev() {
  $('jev-api-key').value = '';
  $('jev-state').value = '';
  resetJevResult();
  setJevStatus('idle', '未测试');
  setJevFeedback('输入 API Key 后开始测试');
  $('jev-api-key').focus();
}

function setupJev() {
  const form = $('jev-form');
  if (!form) return;
  form.addEventListener('submit', testJev);
  $('jev-clear').addEventListener('click', clearJev);
  $('jev-save-key-now').addEventListener('click', saveJevKeyFromInput);
  $('jev-forget-key').addEventListener('click', forgetJevKey);
  $('jev-sample-file').addEventListener('change', loadSampleFile);
}

function setupProtection() {
  const select = $('protection-sample-select');
  if (!select) return;
  $('protection-load').addEventListener('click', loadSelectedProtectionSample);
  $('protection-file').addEventListener('change', loadProtectionFile);
  $('protection-run').addEventListener('click', runProtectionReplay);
  $('protection-jev-load').addEventListener('click', loadIndustrialJevContext);
}

function setWorkspacePanel(panel) {
  const allowed = new Set(['realtime', 'protection', 'jev', 'research']);
  const selected = allowed.has(panel) ? panel : 'realtime';
  document.querySelectorAll('.workspace-tab').forEach((tab) => {
    const active = tab.dataset.panel === selected;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[data-panel-section]').forEach((section) => {
    section.hidden = section.dataset.panelSection !== selected;
    section.classList.toggle('active', section.dataset.panelSection === selected);
  });
  if (window.location.hash !== `#${selected}`) history.replaceState(null, '', `#${selected}`);
}

function setupWorkspace() {
  document.querySelectorAll('.workspace-tab').forEach((tab) => tab.addEventListener('click', () => setWorkspacePanel(tab.dataset.panel)));
  setWorkspacePanel(window.location.hash.slice(1) || 'realtime');
}

function researchRouteConclusion(item) {
  const conclusions = {
    duplicates: '12 条重复事件只产生 1 次远程调用', low_risk: '低风险由本地规则立即处理', critical: '关键风险本地强制，不等待语义服务',
    unverified: '来源未验证，Jev 调用数保持 0', timeout: '服务不可用仍保留本地安全结果', session: '会话滞回复用软证据', expired_parent: '父证据失效时前置阻断',
  };
  return conclusions[item.id] || '边界通过';
}

function renderResearchReport(report) {
  $('research-mode').textContent = report.mode === 'offline_stub' ? '离线 stub（0 次真实 API）' : String(report.mode || '—');
  $('research-calls').textContent = `${Number(report.real_api_calls || 0)} 次真实 API`;
  $('research-cases').innerHTML = (report.cases || []).map((item) => {
    const routes = Array.isArray(item.routes) ? item.routes.join(' → ') : '—';
    const calls = item.efficient_calls === undefined ? '—' : `${item.efficient_calls}${item.baseline_calls !== undefined ? ` / 基线 ${item.baseline_calls}` : ''}`;
    return `<tr><td>${esc(item.title)}</td><td class="route-cell">${esc(routes)}</td><td>${esc(calls)}</td><td class="${item.passed ? 'pass' : 'fail'}">${item.passed ? 'PASS' : 'FAIL'}</td><td>${esc(researchRouteConclusion(item))}</td></tr>`;
  }).join('');
  $('research-protection').innerHTML = (report.protection_cases || []).map((item) => `<tr><td>${esc(item.title)}</td><td class="${protectionClass(item.state)}">${esc(item.state)}</td><td>${esc(item.action)}</td><td>${Number(item.speed_limit || 0).toFixed(2)} m/s</td><td>${item.passed ? '符合预期：' : '未通过：'}${esc(item.expected)}</td></tr>`).join('');
}

async function runResearchSuite() {
  const button = $('research-run');
  button.disabled = true;
  $('research-feedback').textContent = '正在运行本地生产代码对照…';
  try {
    const response = await fetch(RESEARCH_ENDPOINT, {cache: 'no-store'});
    const payload = await parseJsonResponse(response);
    if (!response.ok || !payload || !Array.isArray(payload.cases)) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    renderResearchReport(payload);
    const passed = payload.cases.filter((item) => item.passed).length;
    $('research-feedback').textContent = `研究套件完成：${passed}/${payload.cases.length} 个 Jev 调度案例通过；未调用真实 API，未产生执行器动作。`;
    $('research-feedback').className = 'muted success';
  } catch (error) {
    $('research-feedback').textContent = `研究套件失败：${redactJevMessage(error.message)}`;
    $('research-feedback').className = 'muted error';
  } finally {
    button.disabled = false;
  }
}

function setupResearch() {
  $('research-run').addEventListener('click', runResearchSuite);
}

function render(data) {
  const risk = data.risk || {};
  const mitigation = data.mitigation || {};
  const safety = data.safety || {};
  const riskValue = Math.max(0, Math.min(100, Number(risk.risk || 0) * 100));
  const safetyState = safety.state || 'STARTING';
  $('state-card').className = `card state-card ${stateClass(safetyState)}`;
  $('safety-state').textContent = safetyState;
  $('risk-state').textContent = risk.state || 'STARTING';
  $('safety-reason').textContent = safety.reason || '—';
  $('risk-reason').textContent = risk.reason || '—';
  $('speed-limit').textContent = Number(safety.speed_limit || 0).toFixed(2);
  $('mission-badge').textContent = safety.mission_allowed ? '任务允许' : '任务锁定';
  $('mission-badge').className = `badge ${safety.mission_allowed ? 'allowed' : 'blocked'}`;
  $('risk-score').textContent = riskValue.toFixed(1);
  $('risk-meter').style.width = `${riskValue}%`;
  $('risk-meter').className = riskValue >= 80 ? 'danger' : riskValue >= 50 ? 'warning' : '';
  $('psi').textContent = Number(risk.psi || 0).toFixed(3);
  $('delta').textContent = Boolean(risk.delta);
  $('gamma').textContent = Boolean(risk.gamma);
  chips($('active-components'), risk.active_components);
  chips($('critical-components'), risk.critical_components);
  $('plan-id').textContent = mitigation.plan_id || '—';
  $('mitigation-action').textContent = mitigation.action || 'NONE';
  $('mitigation-reason').textContent = mitigation.reason || '—';
  chips($('mitigation-components'), mitigation.components);
  $('last-updated').textContent = data.updated_at ? `最近更新 ${formatTime(data.updated_at)}` : '尚无更新';
  const timeline = Array.isArray(data.timeline) ? data.timeline : [];
  $('timeline').innerHTML = timeline.length ? timeline.slice(0, 30).map((item) => {
    const label = item.category === 'risk' ? '风险评估' : item.category === 'mitigation' ? '缓解规划' : '安全监督';
    const summary = item.category === 'risk' ? `${esc(item.state)} · 风险 ${(Number(item.risk || 0) * 100).toFixed(1)}` : item.category === 'mitigation' ? esc(item.action) : `${esc(item.state)} · ${Number(item.speed_limit || 0).toFixed(2)} m/s`;
    return `<div class="timeline-item"><span class="dot ${stateClass(item.state)}"></span><div><b>${label}</b><span class="timeline-summary">${summary}</span><small>${formatTime(item.timestamp)} · ${esc(item.reason || '')}</small></div></div>`;
  }).join('') : '<div class="empty">等待 ROS 2 消息</div>';
}

async function refresh() {
  if (!authenticated) return;
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
    if (response.status === 401) { showLogin('登录已过期，请重新登录'); return; }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    $('connection').textContent = 'ROS 2 已连接';
    $('connection').className = 'connection connected';
  } catch (error) {
    $('connection').textContent = '等待后端';
    $('connection').className = 'connection pending';
  }
}

setupJev();
setupProtection();
setupWorkspace();
setupResearch();
setupAuth();
setInterval(refresh, 1000);
