/* Model content is rendered as text. Credentials never enter browser storage. */
(() => {
  'use strict';
  const el = (name) => document.getElementById(`agents-${name}`);
  const sample = '{"sample":"guardian_recovery_virtual_model"}';
  let inputRaw = sample;
  let jobId = null;
  let report = null;
  let reportId = null;
  let timer = null;
  let generation = 0;
  let inputVersion = 0;
  let busy = false;
  let controller = new AbortController();

  function feedback(text) { el('feedback').textContent = text; }
  function clearResult() {
    report = reportId = null;
    el('result').hidden = true;
    el('download').disabled = true;
    el('status').textContent = '尚未运行';
  }
  function setBusy(value) {
    busy = value;
    ['url', 'key', 'model', 'read-models', 'input-kind', 'run'].forEach((name) => { el(name).disabled = value; });
    el('file').disabled = value || el('input-kind').value !== 'upload';
    el('cancel').disabled = !value || !jobId;
  }
  async function api(path, payload) {
    const response = await fetch(path, {
      method: payload === undefined ? 'GET' : 'POST', cache: 'no-store', signal: controller.signal,
      ...(payload === undefined ? {} : {headers: {'Content-Type': 'application/json'},
        body: typeof payload === 'string' ? payload : JSON.stringify(payload)}),
    });
    if (response.status === 401) {
      showLogin('登录已过期，请重新登录');
      throw new Error('登录已过期');
    }
    const body = await response.json();
    if (!response.ok) throw new Error(body.error?.message || `请求失败（HTTP ${response.status}）`);
    return body;
  }
  function config() {
    const value = {base_url: el('url').value.trim(), api_key: el('key').value.trim(), model: el('model').value.trim()};
    if (!value.base_url || !value.api_key) throw new Error('请填写 API URL 与 API Key');
    return value;
  }
  function rows(name, records, columns) {
    const target = el(name);
    target.replaceChildren();
    if (!records.length) records = [null];
    records.forEach((record) => {
      const tr = document.createElement('tr');
      columns.forEach((column) => {
        const td = document.createElement('td');
        td.textContent = record === null ? '暂无记录' : String(column(record) ?? '—');
        tr.append(td);
      });
      target.append(tr);
    });
  }
  const targetNames = {guardian_recovery_virtual_model: '自有 Guardian 虚拟恢复模型',
    submitted_source_static: '用户上传源码（未执行）', submitted_recovery_trace: '用户上传原始轨迹'};
  const roleNames = {goals: '目标分析', planner: '测试规划', worker: '固定工具执行', reviewer: '独立复核'};
  function render(value) {
    report = value;
    reportId = jobId;
    el('result').hidden = false;
    el('download').disabled = false;
    el('mode').textContent = `${value.provider_mode || 'llm'} / ${value.execution_status || '—'}`;
    el('overall').textContent = value.detection || 'NOT_RUN';
    el('model-verdict').textContent = value.model_detection || 'NOT_RUN';
    el('static-verdict').textContent = value.static_detection || '未提交源码';
    el('reason').textContent = value.reason || '各目标按证据分别判断；模型解释不能覆盖本地安全断言。';
    const targets = value.targets || (value.target ? [{...value.target, detection: value.detection}] : []);
    rows('targets', targets, [(row) => targetNames[row.kind] || row.kind, (row) => row.detection,
      (row) => row.kind === 'submitted_source_static' ? '静态分析；源码未执行' : row.kind === 'submitted_recovery_trace' ? '原始轨迹复核；未重新触发' : '固定虚拟模型执行；非物理验证']);
    rows('roles', Array.isArray(value.role_events) ? value.role_events : [],
      [(row) => row.ordinal, (row) => roleNames[row.role] || row.role, (row) => `${row.mode || 'llm'} / ${row.status || '已调用'}`]);
    rows('tests', Array.isArray(value.executions) ? value.executions : [],
      [(row) => row.test_id, (row) => row.validity, (row) => row.assertion_result]);
    el('limitations').textContent = [...(value.limitations || []), '协议接通不代表实际模型质量；未证明上传程序行为或物理安全。'].join(' ');
  }
  async function poll(epoch) {
    if (epoch !== generation || !jobId) return;
    try {
      const job = await api(`/api/agents/job?id=${encodeURIComponent(jobId)}`);
      if (epoch !== generation) return;
      el('status').textContent = `llm / ${job.status}`;
      if (['RUNNING', 'CANCELLING'].includes(job.status)) {
        feedback(job.status === 'CANCELLING' ? '正在取消并回收执行进程…' : '分析运行中；可取消，最长 180 秒。');
        timer = setTimeout(() => poll(epoch), 1000);
      } else {
        if (job.report) render(job.report);
        feedback(job.error?.message || (job.status === 'COMPLETED' ? '分析已完成，请分别查看各目标结论。' : `分析状态：${job.status}；请查看报告中的原因。`));
        jobId = null;
        setBusy(false);
      }
    } catch (error) {
      if (epoch !== generation) return;
      feedback(error.message);
      // A temporary polling failure must not hide the ability to cancel the job.
      timer = setTimeout(() => poll(epoch), 1000);
    }
  }
  el('form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const epoch = generation;
    try {
      const connection = config();
      if (!connection.model) throw new Error('请先读取或填写模型名');
      if (el('input-kind').value === 'upload' && !inputRaw) throw new Error('请选择 files / frames JSON 文件');
      // Preserve uploaded JSON bytes so the server can reject duplicate object keys.
      const body = JSON.stringify(connection).slice(0, -1) + ',"input":' + inputRaw + '}';
      if (new TextEncoder().encode(body).length > 2 * 1024 * 1024) throw new Error('含连接配置的完整请求不能超过 2 MiB');
      setBusy(true);
      el('status').textContent = 'llm / CONNECTING';
      report = null;
      reportId = null;
      el('result').hidden = true;
      el('download').disabled = true;
      feedback('正在连接并提交分析…');
      const job = await api('/api/agents/jobs', body);
      if (epoch !== generation) return;
      jobId = job.job_id;
      el('cancel').disabled = false;
      poll(epoch);
    } catch (error) {
      if (epoch === generation) {
        if (busy) el('status').textContent = 'llm / FAILED';
        feedback(error.message);
        setBusy(false);
      }
    }
  });
  el('read-models').addEventListener('click', async () => {
    if (busy) return;
    const epoch = generation;
    try {
      const {base_url, api_key} = config();
      setBusy(true);
      feedback('正在读取模型列表…');
      const result = await api('/api/agents/models', {base_url, api_key});
      if (epoch !== generation) return;
      el('models').replaceChildren();
      result.models.forEach((name) => {
        const option = document.createElement('option');
        option.value = name;
        el('models').append(option);
      });
      if (!el('model').value && result.models.length) el('model').value = result.models[0];
      feedback(`已读取 ${result.models.length} 个模型；选择或手动填写后直接运行。协议接通不代表模型质量。`);
    } catch (error) {
      if (epoch === generation) feedback(error.message);
    } finally { if (epoch === generation) setBusy(false); }
  });
  el('cancel').addEventListener('click', async () => {
    const epoch = generation;
    if (!jobId) return;
    el('cancel').disabled = true;
    try {
      await api('/api/agents/cancel', {job_id: jobId});
      if (epoch === generation) feedback('已请求取消，正在回收执行进程…');
    } catch (error) {
      if (epoch === generation) { feedback(error.message); el('cancel').disabled = false; }
    }
  });
  el('input-kind').addEventListener('change', () => {
    inputVersion += 1;
    inputRaw = el('input-kind').value === 'sample' ? sample : null;
    el('file').value = '';
    clearResult();
    el('input-summary').textContent = inputRaw ? '当前输入：自有 Guardian 虚拟恢复模型' : '当前输入：等待上传 files / frames JSON';
    setBusy(false);
    feedback(inputRaw ? '将测试自有 Guardian 虚拟恢复模型。' : '请选择仅含 files 或 frames 的严格 JSON。');
  });
  el('file').addEventListener('change', async () => {
    inputVersion += 1;
    inputRaw = null;
    clearResult();
    el('input-summary').textContent = '当前输入：正在读取上传文件';
    const file = el('file').files[0];
    const epoch = generation;
    const version = inputVersion;
    if (!file) { el('input-summary').textContent = '当前输入：未选择文件'; return; }
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('文件不能超过 2 MiB');
      const raw = await file.text();
      const parsed = JSON.parse(raw);
      if (!parsed || Array.isArray(parsed) || Object.keys(parsed).length !== 1 || !['files', 'frames'].includes(Object.keys(parsed)[0])) throw new Error('JSON 顶层仅允许 files 或 frames');
      if (epoch !== generation || version !== inputVersion || el('input-kind').value !== 'upload') return;
      inputRaw = raw;
      el('input-summary').textContent = `当前输入：${file.name} · ${Object.keys(parsed)[0] === 'files' ? '源码静态分析' : '原始轨迹复核'}`;
      feedback(`已读取 ${file.name}；仅作为分析数据，不执行上传源码。`);
    } catch (error) { if (epoch === generation && version === inputVersion) {
      el('input-summary').textContent = '当前输入：文件无效，请重新选择';
      feedback(error.message);
    } }
  });
  el('download').addEventListener('click', async () => {
    if (!report || !reportId) return;
    const epoch = generation, id = reportId;
    el('download').disabled = true;
    try {
      const response = await fetch(`/api/agents/report?id=${encodeURIComponent(id)}`,
        {cache: 'no-store', signal: controller.signal});
      if (response.status === 401) { showLogin('登录已过期，请重新登录'); return; }
      if (!response.ok) throw new Error('报告已不可用，请重新运行分析');
      // Keep server number tokens intact for canonical hash verification.
      const raw = await response.text();
      if (epoch !== generation || id !== reportId) return;
      const url = URL.createObjectURL(new Blob([raw], {type: 'application/json'}));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'guardian-agent-review.json';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      if (epoch === generation) feedback(error.message);
    } finally {
      if (epoch === generation) el('download').disabled = !report;
    }
  });
  window.AgentReviewDashboard = {useInput(value, label) {
    // Explicit user handoff only. Never submit, replace an active job, or copy credentials.
    if (busy) return false;
    inputVersion += 1;
    inputRaw = JSON.stringify(value);
    el('input-kind').value = 'upload';
    el('file').value = '';
    clearResult();
    el('input-summary').textContent = `当前输入：${label} · ${value.files ? '源码静态分析' : '原始轨迹复核'}`;
    feedback('已带入当前输入。确认接口和模型后，点击“连接并运行分析”；尚未调用模型。');
    setBusy(false);
    return true;
  }, reset() {
    generation += 1;
    inputVersion += 1;
    clearTimeout(timer);
    controller.abort();
    controller = new AbortController();
    jobId = report = null;
    reportId = null;
    inputRaw = sample;
    el('form').reset();
    el('models').replaceChildren();
    el('result').hidden = true;
    el('download').disabled = true;
    el('status').textContent = '尚未运行';
    el('input-summary').textContent = '当前输入：自有 Guardian 虚拟恢复模型';
    feedback('Key 不保存到磁盘或浏览器存储；协议接通不代表实际模型质量。');
    setBusy(false);
  }};
})();
