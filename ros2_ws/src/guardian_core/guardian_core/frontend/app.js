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
  const apiKey = $('jev-api-key').value.trim();
  const state = $('jev-state').value.trim();
  resetJevResult();

  if (!apiKey) {
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
    const response = await fetch(JEV_TEST_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify({api_key: apiKey, state}),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || !payload || payload.status !== 'OK' || payload.connected !== true || !payload.assessment) {
      throw new Error(jevErrorMessage(payload, response));
    }

    renderJevAssessment(payload);
    const latency = finiteNumber(payload.latency_ms, performance.now() - startedAt);
    setJevStatus('success', '已连接');
    setJevFeedback(`Jev 调用成功 · ${latency.toFixed(0)} ms`, 'success');
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
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
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
refresh();
setInterval(refresh, 1000);
