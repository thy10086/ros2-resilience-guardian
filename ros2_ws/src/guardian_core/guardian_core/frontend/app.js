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

refresh();
setInterval(refresh, 1000);
