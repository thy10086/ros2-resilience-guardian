/* Read-only recovery inspection and a recorded evaluation snapshot. */
(() => {
  const modeNames = {unguided: '无引导', guided: '旧覆盖反馈', boundary: '完整边界反馈',
    ttl: '仅 TTL 反馈', context_repair: '上下文 / 修复反馈'};
  const targetNames = {recovery_semantic_coverage: '恢复状态与转移覆盖',
    permit_ttl_diversity: '许可时效多样性', permit_expiry_proximity: '到期临界接近度',
    permit_context_diversity: '消费上下文多样性', repair_transition_diversity: '修复转移多样性'};
  const violationNames = {expired_proof: '消费过期或尚未生效的许可', context_mismatch: '许可消费上下文错配',
    proof_reuse: '一次性许可被重复消费', unsafe_motion: '缺少健康证据却允许运动',
    missing_proof: '恢复时缺少有效签发许可', unsafe_candidate: '候选许可缺少健康停车证据',
    unsafe_resume: '恢复时缺少零速停车确认', unauthorized_continuation: '运动未关联到授权上下文',
    candidate_binding_mismatch: '签发许可绑定错配', invalid_issuance_time: '许可签发时间不一致',
    invalid_clock: '轨迹时间倒退或无效', invalid_speed_limit: '发布速度上限无效',
    recovery_stalled: '连续健康停车仍未恢复'};
  let samples = [], frames = null, inputName = '', generation = 0, inspecting = false;

  function updateControls() {
    $('recovery-inspect').disabled = inspecting || !frames;
    $('recovery-to-agents').disabled = inspecting || !frames;
    $('recovery-load-sample').disabled = inspecting || !samples.length;
    $('recovery-trace-file').disabled = inspecting;
    $('recovery-sample-select').disabled = inspecting || !samples.length;
  }

  function status(text, error = false) {
    $('recovery-input-status').textContent = text;
    $('recovery-input-status').className = `muted ${error ? 'error' : ''}`;
  }

  function clearTrace() {
    frames = null;
    updateControls();
    $('recovery-check-result').hidden = true;
    $('recovery-verdict').textContent = '等待轨迹';
    $('recovery-verdict').className = 'pill';
  }

  function acceptTrace(rows, name) {
    if (!Array.isArray(rows) || !rows.length || rows.length > 2000 || rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))) {
      throw new Error('需提供 1–2000 帧恢复审计对象。');
    }
    if (new TextEncoder().encode(JSON.stringify({frames: rows})).length > 2 * 1024 * 1024) {
      throw new Error('轨迹请求不能超过 2 MiB。');
    }
    frames = rows;
    inputName = name;
    updateControls();
    status(`${name} · ${rows.length} 帧已加载，尚未检测。`);
  }

  function parseTrace(text) {
    const clean = text.replace(/^\uFEFF/, '').trim();
    let value;
    try { value = JSON.parse(clean); }
    catch (_) { value = clean.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line)); }
    let rows = Array.isArray(value) ? value : Array.isArray(value?.frames) ? value.frames : value?.kind === 'recovery_trace' ? [value] : null;
    if (!rows) throw new Error('文件中没有恢复审计帧；请选择帧数组、含 frames 的报告或 recovery_trace 日志。');
    if (rows.some(row => row?.kind !== undefined)) {
      if (rows.some(row => !row || typeof row.kind !== 'string')) throw new Error('审计行格式不一致。');
      rows = rows.filter(row => row.kind === 'recovery_trace').map(({kind, ...frame}) => frame);
    }
    return rows;
  }

  async function loadFile() {
    if (inspecting) return;
    const current = ++generation;
    clearTrace();
    const file = $('recovery-trace-file').files?.[0];
    if (!file) { status('未选择文件。'); return; }
    status(`正在读取 ${file.name}…`);
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('文件不能超过 2 MiB。');
      const text = await file.text();
      if (current !== generation) return;
      acceptTrace(parseTrace(text), file.name);
    } catch (error) { if (current === generation) status(`无法导入：${error.message}`, true); }
  }

  function loadSample() {
    if (inspecting) return;
    ++generation;
    clearTrace();
    $('recovery-trace-file').value = '';
    const sample = samples.find(item => item.id === $('recovery-sample-select').value);
    if (!sample) { status('请选择恢复轨迹样例。', true); return; }
    try { acceptTrace(sample.frames, `${sample.title}（${sample.kind}）`); }
    catch (error) { status(`样例格式无效：${error.message}`, true); }
  }

  function renderInspection(report) {
    const violated = report.violation_count > 0;
    $('recovery-verdict').textContent = violated ? '发现断言违规' : '本轨迹未发现违规';
    $('recovery-verdict').className = `pill ${violated ? 'error' : 'success'}`;
    $('recovery-frame-count').textContent = report.frame_count;
    $('recovery-violation-count').textContent = report.violation_count;
    $('recovery-trace-coverage').textContent = `${report.coverage.states} / ${report.coverage.transitions}`;
    $('recovery-gap-count').textContent = report.liveness_gaps;
    const codes = report.violation_codes.map(code => violationNames[code] || code).join('；');
    $('recovery-check-summary').textContent = violated ? `检测到：${codes}。` : '所提交轨迹未触发恢复安全断言；这不代表安全认证。';
    $('recovery-findings').innerHTML = report.violations.length ? report.violations.map(v =>
      `<tr><td>第 ${v.frame_index + 1} 帧<br>${Number(v.now).toFixed(3)} s</td><td><strong>${esc(violationNames[v.code] || v.code)}</strong><small class="code-security-raw">${esc(v.code)}</small></td><td>${esc(v.recovery_phase)}</td><td class="recovery-binding">图：${esc(v.graph_fingerprint)}<br>策略：${esc(v.policy_fingerprint)}<br>账本：${esc(v.ledger_anchor)}<br>消费许可：${esc(v.consumed_proof_id || '—')}</td></tr>`).join('') :
      '<tr><td colspan="4" class="empty">所提交帧未触发断言违规。</td></tr>';
    $('recovery-check-limitations').textContent = `${report.limitations} 检测采用 ${report.oracle_config.liveness_sec} 秒活性窗口；${report.liveness_gaps} 个超过 ${report.oracle_config.max_frame_gap_sec} 秒的采样空窗不用于推断连续健康，授权检查继续执行。${report.violations_truncated ? '仅展示前 100 条违规，计数包含全部。' : ''}`;
    $('recovery-check-result').hidden = false;
  }

  async function inspectTrace() {
    if (!frames || inspecting) return;
    const submittedGeneration = generation, submittedName = inputName;
    inspecting = true;
    updateControls();
    $('recovery-check-result').hidden = true;
    status('正在逐帧检查恢复许可与绑定上下文…');
    try {
      const response = await fetch('/api/recovery/inspect', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({frames})});
      if (response.status === 401) { showLogin('登录已过期，请重新登录'); throw new Error('请重新登录后检测。'); }
      const payload = await parseJsonResponse(response);
      if (submittedGeneration !== generation) return;
      if (!response.ok || !payload?.report) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      renderInspection(payload.report);
      status(`${submittedName} · 检测完成；只检查日志，未产生执行器动作。`);
    } catch (error) {
      if (submittedGeneration !== generation) return;
      $('recovery-verdict').textContent = '检测未完成';
      $('recovery-verdict').className = 'pill error';
      status(`检测失败：${error.message}`, true);
    } finally { inspecting = false; updateControls(); }
  }

  function renderEvaluation(report) {
    if (report.schema !== 'guardian-recovery-evaluation/v1') throw new Error('实验快照格式不支持。');
    $('recovery-evaluation-executions').textContent = Number(report.generated_executions).toLocaleString('zh-CN');
    $('recovery-evaluation-violations').textContent = report.full_mechanism_violations;
    $('recovery-evaluation-replays').textContent = `${report.replay_verification.counterexamples} / ${report.replay_verification.corpora}`;
    $('recovery-evaluation-budget').textContent = `${report.budget} / ${report.seeds.length}`;
    $('recovery-evaluation-conclusion').textContent = report.interpretation;
    $('recovery-comparison').innerHTML = report.modes.map(mode => {
      const g = report.aggregate.groups[mode], ttl = g.defect_detection.no_proof_ttl;
      return `<tr><td><strong>${esc(modeNames[mode] || mode)}</strong></td><td>${ttl.detected_runs} / ${ttl.total_runs}</td><td>${ttl.restricted_first_test_index.median}</td><td>${g.transitions.median}</td><td>${Number(g.elapsed_sec.median).toFixed(2)}</td></tr>`;
    }).join('');
    $('recovery-targets').innerHTML = report.modes.map(mode => {
      const labels = report.protocol.target_labels_by_mode[mode].map(label => targetNames[label] || label).join('、') || '无优化目标';
      const d = report.aggregate.groups[mode].defect_detection;
      return `<tr><td>${esc(modeNames[mode] || mode)}</td><td>${esc(labels)}</td><td>${['no_context_binding', 'accept_proof_replay', 'no_independent_observation'].map(k => `${d[k].detected_runs}/${d[k].total_runs}`).join(' · ')}</td></tr>`;
    }).join('');
    const pairs = report.aggregate.paired_comparisons;
    $('recovery-paired-summary').textContent = `相对无引导，完整边界反馈 TTL 截尾首次索引配对差中位 ${pairs.boundary_vs_unguided.defect_detection.no_proof_ttl.restricted_first_index_delta_median}，TTL 族为 ${pairs.ttl_vs_unguided.defect_detection.no_proof_ttl.restricted_first_index_delta_median}（负值有利）。完整边界反馈转移差中位 ${pairs.boundary_vs_unguided.transition_delta_median}，十个种子覆盖全部下降。`;
    $('recovery-raw-note').textContent = report.raw_batch_note;
    $('recovery-evaluation-source').textContent = `报告：${report.source_report} · Python ${report.protocol.python} / Hypothesis ${report.protocol.hypothesis} · seeds ${report.seeds.join(', ')} · SHA-256 ${report.source_summary_sha256}`;
    $('recovery-evaluation-status').textContent = '第六轮修正批次快照；点击轨迹检测不会重新执行这批实验。';
    $('recovery-evaluation-result').hidden = false;
  }

  async function load() {
    await Promise.allSettled([
      (async () => {
        try {
          const response = await fetch('recovery-evaluation.json', {cache: 'no-store'});
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          renderEvaluation(await response.json());
        } catch (error) {
          $('recovery-evaluation-result').hidden = true;
          $('recovery-evaluation-status').textContent = `实验快照不可用：${error.message}`;
        }
      })(),
      (async () => {
        try {
          const response = await fetch('recovery-samples.json', {cache: 'no-store'});
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const loadedSamples = (await response.json()).samples;
          if (!Array.isArray(loadedSamples) || !loadedSamples.length || loadedSamples.length > 32 ||
              loadedSamples.some(s => !s || typeof s.id !== 'string' || !s.id || typeof s.title !== 'string' ||
                typeof s.kind !== 'string' || !Array.isArray(s.frames) || !s.frames.length || s.frames.length > 2000) ||
              new Set(loadedSamples.map(s => s.id)).size !== loadedSamples.length) {
            throw new Error('没有有效的样例目录');
          }
          samples = loadedSamples;
          $('recovery-sample-select').innerHTML = samples.map(s => `<option value="${esc(s.id)}">${esc(s.title)} · ${esc(s.kind)}</option>`).join('');
          updateControls();
        } catch (error) {
          updateControls();
          if (!inspecting) status(`恢复样例不可用：${error.message}。仍可导入自己的轨迹。`, true);
        }
      })(),
    ]);
  }

  function setup() {
    $('protection-open-recovery').addEventListener('click', () => {
      setWorkspacePanel('research');
      window.scrollTo({top: 0});
    });
    $('recovery-load-sample').addEventListener('click', loadSample);
    $('recovery-trace-file').addEventListener('change', loadFile);
    $('recovery-inspect').addEventListener('click', inspectTrace);
    $('recovery-to-agents').addEventListener('click', () => {
      if (!frames || inspecting) return;
      if (window.AgentReviewDashboard.useInput({frames}, `轨迹检测 · ${inputName} · ${frames.length} 帧`)) {
        setWorkspacePanel('research/agents');
        window.scrollTo({top: 0});
      } else status('多智能体任务正在运行，请先完成或取消该任务再带入轨迹。', true);
    });
    updateControls();
  }
  window.RecoveryDashboard = {setup, load};
})();
