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
const EXPERIMENT_JEV_ENDPOINT = '/api/experiments/jev-evaluate';
const CODE_SECURITY_SAMPLES_ENDPOINT = '/api/code-security/samples';
const CODE_SECURITY_INSPECT_ENDPOINT = '/api/code-security/inspect';
const CODE_SECURITY_JEV_ENDPOINT = '/api/code-security/jev-evaluate';
const SANDBOX_SAMPLES_ENDPOINT = '/api/sandbox/samples';
const SANDBOX_RUN_ENDPOINT = '/api/sandbox/run';
const DATASET_SECURITY_SCAN_ENDPOINT = '/api/dataset-security/scan';
const RESEARCH_ENDPOINT = '/api/research/suite';
const SIMULATION_CONTROL_ENDPOINT = '/api/simulation/control';
const PROTECTION_RECENT_RESULT_KEY = 'guardian.protection.recent-result.v1';
const MAX_SAMPLE_BYTES = 64 * 1024;
const MAX_SAMPLE_CHARS = 4096;
let authenticated = false;
let jevKeySaved = false;
let protectionSamples = [];
let protectionSample = null;
let protectionSampleMeta = null;
let protectionReport = null;
let codeSecuritySamples = [];
let codeSecuritySource = '';
let codeSecurityFilename = 'dashboard-input.py';
let codeSecurityReport = null;
let sandboxSamples = [];
let sandboxSource = '';
let sandboxFilename = 'dashboard-sandbox.py';
let sandboxKind = 'python';
let sandboxReport = null;
let datasetReport = null;
let datasetUploadFiles = [];
let datasetUploadGeneration = 0;
let datasetUploadBusy = false;
let protectionImportedFile = null;
let simulationCommandBusy = false;

function showLogin(message = '本地实验账号：admin / admin') {
  authenticated = false;
  jevKeySaved = false;
  updateJevKeyStatus(false);
  $('app-shell').hidden = true;
  $('auth-gate').hidden = false;
  $('login-feedback').textContent = message;
  $('login-feedback').className = /错误|未启动|无法/.test(message) ? 'auth-feedback error' : 'auth-feedback';
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

const CODE_SECURITY_SEVERITY_LABELS = {
  critical: '必须阻断',
  high: '高风险',
  medium: '待整改',
  low: '低风险',
};

const CODE_SECURITY_GUARDIAN_LABELS = {
  SAFE_STOP: '立即停车（SAFE_STOP）',
  ISOLATE_COMPONENT: '隔离组件（ISOLATE_COMPONENT）',
  REVIEW_REQUIRED: '人工复核（REVIEW_REQUIRED）',
  NONE: '无需额外动作',
};

const CODE_SECURITY_STATIC_LIMITATION = '只完成 Python AST 和有限文本规则检查，未启动 ROS 2/Gazebo。';

function codeSecurityVerdictLabel(verdict) {
  return {
    BLOCKED: '禁止上线',
    REVIEW: '整改后复核',
    PASS: '可以进入下一步测试',
  }[String(verdict || '').toUpperCase()] || '需要复核';
}

function codeSecurityNextStep(report) {
  const summary = report?.summary || {};
  if (Number(summary.critical || 0) > 0) {
    return `发现 ${summary.critical} 个必须阻断的问题：先修复关键风险，再重新执行检查。当前不建议部署或连接真实机器人。`;
  }
  if (Number(summary.high || 0) > 0) {
    return `发现 ${summary.high} 个高风险问题：完成整改后，由工程师复核并重新执行检查。`;
  }
  if (Number(summary.medium || 0) > 0) {
    return `发现 ${summary.medium} 个需要关注的问题：建议在上线前完成复核并保留整改记录。`;
  }
  return '当前规则没有发现明显风险，可以进入仿真验证和人工上线评审。';
}

function datasetSecurityVerdictLabel(verdict) {
  return {
    BLOCKED: '禁止直接使用',
    REVIEW: '复核后再使用',
    PASS: '可以进入下一步验证',
  }[String(verdict || '').toUpperCase()] || '需要复核';
}

function datasetSecurityNextStep(report) {
  const summary = report?.summary || {};
  const formats = report?.format_checks || {};
  const hashes = report?.manifest_hashes || {};
  if (Number(summary.critical || 0) > 0) {
    return `发现 ${summary.critical} 条必须阻断证据：先隔离数据集并复核对应文件，当前不要启动其中的代码、训练或仿真。`;
  }
  if (Number(formats.invalid || 0) > 0 || hashes.all_checked_match === false) {
    return '存在格式或来源校验问题：先确认文件完整性和来源，再进入隔离仿真。';
  }
  if (Number(summary.high || 0) > 0 || Number(summary.medium || 0) > 0) {
    return '存在需要工程师复核的代码或配置风险：完成整改、隔离仿真和人工评审后再使用。';
  }
  return '当前规则没有发现明显风险，可以进入隔离仿真和人工上线评审。';
}

function setDatasetSecurityFeedback(message, kind = '') {
  const target = $('dataset-security-feedback');
  if (!target) return;
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

function renderDatasetSecurity(report) {
  const catalog = report?.dataset || {};
  const classes = catalog.classes || {};
  const summary = report?.summary || {};
  const source = report?.source_scan || {};
  const formats = report?.format_checks || {};
  const hashes = report?.manifest_hashes || {};
  const runtime = report?.runtime || {};
  datasetReport = report;

  $('dataset-security-name').textContent = catalog.root_name || '本次上传批次';
  $('dataset-security-decision').textContent = datasetSecurityVerdictLabel(summary.verdict);
  $('dataset-security-verdict').textContent = datasetSecurityVerdictLabel(summary.verdict);
  $('dataset-security-verdict').className = `pill protection-pill ${protectionClass(summary.verdict)}`;
  $('dataset-security-next-step').textContent = datasetSecurityNextStep(report);
  $('dataset-security-files').textContent = String(catalog.files_total || 0);
  $('dataset-security-code').textContent = String(classes.code || 0);
  $('dataset-security-critical').textContent = String(summary.critical || 0);
  $('dataset-security-high').textContent = String(summary.high || 0);
  $('dataset-security-medium').textContent = String(summary.medium || 0);
  $('dataset-security-python').textContent = `${Number(source.scanned_files || 0)} / ${Number(source.candidate_files || 0)} 个代码文件；Python ${Number(source.python_scanned_files || 0)} / ${Number(source.python_candidate_files || 0)} 个；版本兼容待复核 ${Number(source.python_version_compatibility || 0)} 个；语法错误 ${Number(source.python_syntax_errors || 0)} 个`;
  $('dataset-security-formats').textContent = `${Number(formats.valid || 0)} / ${Number(formats.checked || 0)} 有效；${Number(formats.invalid || 0)} 个无效`;
  $('dataset-security-hashes').textContent = hashes.declared
    ? `${Number(hashes.matched || 0)} / ${Number(hashes.declared || 0)} 个匹配`
    : '未声明 manifest 文件';
  $('dataset-security-executed').textContent = `${Number(runtime.executed_files || 0)} / ${runtime.training_started ? '训练已启动' : '训练未启动'} / ${runtime.simulation_started ? '仿真已启动' : '仿真未启动'}`;
  const invalidFormats = (Array.isArray(formats.items) ? formats.items : [])
    .filter((item) => item.valid !== true)
    .slice(0, 10)
    .map((item) => `${item.path || '未知文件'}（${item.format || '未知格式'}）`)
    .join('；');
  $('dataset-security-format-items').textContent = invalidFormats || '没有无效格式文件';
  const hashProblems = [
    ...(Array.isArray(hashes.missing) ? hashes.missing.map((item) => `缺失：${item}`) : []),
    ...(Array.isArray(hashes.mismatched) ? hashes.mismatched.map((item) => `不匹配：${item}`) : []),
  ];
  $('dataset-security-manifest-detail').textContent = `声明 ${Number(hashes.declared || 0)} 个；检查 ${Number(hashes.checked || 0)} 个；匹配 ${Number(hashes.matched || 0)} 个。${hashProblems.length ? ` ${hashProblems.join('；')}` : '未发现缺失或不匹配。'}`;
  $('dataset-security-summary').textContent = `结论：${datasetSecurityVerdictLabel(summary.verdict)}。共发现 ${Number(summary.total || 0)} 条证据，其中必须阻断 ${Number(summary.critical || 0)} 条、高风险 ${Number(summary.high || 0)} 条、待复核 ${Number(summary.medium || 0)} 条。`;
  $('dataset-security-limitations').textContent = `边界：${Array.isArray(report?.limitations) ? report.limitations.join('；') : '只完成当前规则覆盖的静态审计。'}`;

  const findings = Array.isArray(report?.findings) ? report.findings.slice(0, 20) : [];
  $('dataset-security-findings').innerHTML = findings.length
    ? findings.map((item) => `<tr><td class="${protectionClass(item.severity)}"><strong>${esc(CODE_SECURITY_SEVERITY_LABELS[item.severity] || item.severity || '—')}</strong><small class="code-security-raw">${esc(item.rule_id || '')}</small></td><td class="mono">${esc(item.path || '—')}</td><td>${esc(item.title || '—')}</td><td>第 ${Number(item.line || 0)} 行</td><td class="code-security-evidence">${esc(item.evidence || '—')}</td><td>${esc(item.recommendation || '—')}</td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">没有发现当前规则覆盖的风险证据。</td></tr>';
  $('dataset-security-result').hidden = false;
}

function formatDatasetBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function clearDatasetSecurityResult() {
  datasetReport = null;
  const result = $('dataset-security-result');
  if (result) result.hidden = true;
}

function setDatasetSecurityInputsDisabled(disabled) {
  ['dataset-security-files-input', 'dataset-security-folder-input', 'dataset-security-zip-input']
    .forEach((id) => { if ($(id)) $(id).disabled = disabled; });
}

function setDatasetSecurityProgress(value, visible = true) {
  const progress = $('dataset-security-upload-progress');
  if (!progress) return;
  progress.value = Math.max(0, Math.min(100, Number(value) || 0));
  progress.hidden = !visible;
}

function renderDatasetUploadSelection(files) {
  datasetUploadFiles = files;
  datasetUploadGeneration += 1;
  clearDatasetSecurityResult();
  const button = $('dataset-security-run');
  const summary = $('dataset-security-upload-summary');
  const list = $('dataset-security-file-list');
  if (!files.length) {
    $('dataset-security-name').textContent = '未选择文件';
    summary.textContent = '尚未选择文件';
    list.innerHTML = '<li class="empty">选择后将在这里显示文件数量、大小和相对路径。</li>';
    setDatasetSecurityFeedback('请选择要审计的本地文件、文件夹或 ZIP。');
    button.disabled = true;
    setDatasetSecurityProgress(0, false);
    return;
  }
  const totalBytes = files.reduce((total, file) => total + Number(file.size || 0), 0);
  const paths = files.map((file) => file.webkitRelativePath || file.name);
  const firstPath = paths[0] || '上传批次';
  $('dataset-security-name').textContent = files.length === 1 ? firstPath : '本次上传批次';
  summary.textContent = `${files.length} 个文件 · ${formatDatasetBytes(totalBytes)} · 选择完成，等待审计`;
  const preview = paths.slice(0, 60).map((path, index) => `<li>${esc(path)} <span>(${formatDatasetBytes(files[index].size)})</span></li>`);
  if (paths.length > 60) preview.push(`<li class="empty">其余 ${paths.length - 60} 个文件将在上传时一并处理。</li>`);
  list.innerHTML = preview.join('');
  setDatasetSecurityFeedback('已生成本次待审计清单。点击“开始安全审计”后才会上传到本地 Dashboard。', 'success');
  button.disabled = false;
  setDatasetSecurityProgress(0, false);
}

function handleDatasetUploadSelection(event) {
  if (datasetUploadBusy) return;
  const input = event.currentTarget;
  const files = Array.from(input.files || []);
  document.querySelectorAll('#panel-dataset-security input[type="file"]').forEach((other) => {
    if (other !== input) other.value = '';
  });
  renderDatasetUploadSelection(files);
}

async function datasetUploadTransportError() {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch('/api/health', {
      cache: 'no-store',
      signal: controller.signal,
    });
    if (response.ok) {
      return new Error('上传连接已中断：本地 Dashboard 仍在运行，请重试本批审计。');
    }
    return new Error(`本地 Dashboard 返回异常（HTTP ${response.status}），请检查服务日志后重试。`);
  } catch (_error) {
    return new Error('本地 Dashboard 未运行：请保持 WSL 实例和 ROS 2 Dashboard 运行后重试。');
  } finally {
    window.clearTimeout(timer);
  }
}

function uploadDatasetBatch(files, generation) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    const form = new FormData();
    files.forEach((file) => {
      form.append('files', file, file.webkitRelativePath || file.name);
    });
    request.open('POST', DATASET_SECURITY_SCAN_ENDPOINT, true);
    request.responseType = 'json';
    request.upload.addEventListener('progress', (event) => {
      if (generation !== datasetUploadGeneration) return;
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        setDatasetSecurityProgress(percent, true);
        setDatasetSecurityFeedback(percent >= 100 ? '上传完成，正在扫描：请保持页面打开…' : `正在上传：${percent}%`);
      } else {
        setDatasetSecurityFeedback('正在上传：进度由浏览器计算中…');
      }
    });
    request.addEventListener('load', () => {
      let payload = request.response;
      if (!payload) {
        try { payload = JSON.parse(request.responseText || '{}'); } catch (_error) { payload = {}; }
      }
      if (request.status === 401) {
        showLogin('登录已过期，请重新登录');
        reject(new Error('登录已过期'));
        return;
      }
      if (request.status < 200 || request.status >= 300 || payload?.status !== 'OK' || !payload.report) {
        const error = new Error(payload?.error?.message || `HTTP ${request.status}`);
        error.status = request.status;
        reject(error);
        return;
      }
      resolve(payload);
    });
    request.addEventListener('error', async () => reject(await datasetUploadTransportError()));
    request.addEventListener('abort', () => reject(new Error('上传已取消')));
    request.send(form);
  });
}

async function runDatasetSecurityScan() {
  const button = $('dataset-security-run');
  if (!datasetUploadFiles.length || datasetUploadBusy) {
    setDatasetSecurityFeedback('请先选择至少一个文件或文件夹。', 'error');
    return;
  }
  const generation = datasetUploadGeneration;
  datasetUploadBusy = true;
  button.disabled = true;
  setDatasetSecurityInputsDisabled(true);
  setDatasetSecurityProgress(0, true);
  setDatasetSecurityFeedback('正在上传并执行只读扫描：不会执行源码、训练模型或启动仿真。');
  clearDatasetSecurityResult();
  try {
    const payload = await uploadDatasetBatch(datasetUploadFiles, generation);
    if (generation !== datasetUploadGeneration) return;
    renderDatasetSecurity(payload.report);
    const verdict = payload.report.summary?.verdict || 'REVIEW';
    const upload = payload.upload || {};
    $('dataset-security-upload-summary').textContent = `${Number(upload.files_total || datasetUploadFiles.length)} 个文件 · ${formatDatasetBytes(upload.bytes_total)} · 本批审计完成`;
    setDatasetSecurityProgress(100, true);
    setDatasetSecurityFeedback(`审计完成：${datasetSecurityVerdictLabel(verdict)}；实际执行文件为 0。`, verdict === 'PASS' ? 'success' : 'error');
  } catch (error) {
    clearDatasetSecurityResult();
    setDatasetSecurityProgress(0, false);
    setDatasetSecurityFeedback(`审计失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    datasetUploadBusy = false;
    setDatasetSecurityInputsDisabled(false);
    button.disabled = !datasetUploadFiles.length;
  }
}

function codeSecurityJevDecision(assessment) {
  const score = finiteNumber(assessment?.score, 0);
  const confidence = finiteNumber(assessment?.confidence, 0);
  const impact = String(assessment?.mission_impact || '').toLowerCase();
  if (impact === 'critical' || score >= 0.75) {
    return confidence < 0.7
      ? 'Jev 倾向于判定为高风险，但需要人工确认'
      : 'Jev 倾向于判定为高风险，建议保持阻断';
  }
  if (score >= 0.45) return 'Jev 认为存在一定风险，建议整改后复核';
  return 'Jev 未发现明显语义风险，但仍以本地规则为准';
}

function codeSecurityJevExplanation(assessment) {
  const label = String(assessment?.label || '').replace(/_/g, ' ');
  const impact = String(assessment?.mission_impact || 'unknown');
  const review = assessment?.needs_human_review === true ? '需要工程师确认' : '暂不要求额外人工确认';
  if (!label && impact === 'unknown') return 'Jev 未返回可解释的语义判断。';
  return `语义标签：${label || 'unknown'}；任务影响：${impact}；${review}。这只是辅助意见，不会覆盖 Guardian 的本地结论。`;
}

function setProtectionFeedback(message, kind = '') {
  const target = $('protection-feedback');
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

function setProtectionFileName(message, kind = '') {
  const target = $('protection-file-name');
  if (!target) return;
  target.textContent = message;
  target.className = `file-input-name${kind ? ` ${kind}` : ''}`;
}

function protectionFileKind(filename, source = '') {
  const lower = String(filename || '').toLowerCase();
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.py')) return 'python';
  if (lower.endsWith('.sdf') || lower.endsWith('.world')) return 'sdf';
  if (lower.endsWith('.urdf')) return 'urdf';
  if (lower.endsWith('.xml')) {
    if (/<\s*sdf(?:\s|>)/i.test(source)) return 'sdf';
    if (/<\s*robot(?:\s|>)/i.test(source)) return 'urdf';
    return 'xml';
  }
  return 'unknown';
}

function protectionFileTypeLabel(kind) {
  return {
    json: 'Guardian 回放 JSON',
    python: 'ROS 2 Python',
    xml: 'XML 配置',
    sdf: 'Gazebo SDF / World',
    urdf: '机器人 URDF',
    unknown: '未知类型',
  }[kind] || '未知类型';
}

function protectionFileEntities(source, kind) {
  const text = String(source || '');
  const entities = [];
  if (kind === 'python') {
    const nodeNames = [...text.matchAll(/(?:super\(\).__init__|Node\([^)]*node_name\s*=\s*|create_node\([^,]+,\s*['"])(['"]?)([A-Za-z0-9_.-]+)\1/gi)].map((match) => match[2]);
    const topics = [...text.matchAll(/(?:create_publisher|create_subscription|publish)\([^,]+,\s*['"]([^'"]+)['"]/gi)].map((match) => match[1]);
    if (nodeNames.length) entities.push(`节点：${[...new Set(nodeNames)].join('、')}`);
    if (topics.length) entities.push(`主题：${[...new Set(topics)].join('、')}`);
  } else if (kind === 'sdf' || kind === 'urdf' || kind === 'xml') {
    const models = [...text.matchAll(/<model[^>]*name=["']([^"']+)["']/gi)].map((match) => match[1]);
    const robots = [...text.matchAll(/<robot[^>]*name=["']([^"']+)["']/gi)].map((match) => match[1]);
    const plugins = [...text.matchAll(/<plugin[^>]*filename=["']([^"']+)["']/gi)].map((match) => match[1]);
    if (models.length) entities.push(`模型：${[...new Set(models)].join('、')}`);
    if (robots.length) entities.push(`机器人：${[...new Set(robots)].join('、')}`);
    if (plugins.length) entities.push(`插件：${[...new Set(plugins)].join('、')}`);
  }
  return entities.length ? entities.join('；') : '未识别到明确实体，需进入对应检查模块继续分析';
}

function clearProtectionFilePreview() {
  const preview = $('protection-file-preview');
  if (!preview) return;
  preview.hidden = true;
  $('protection-preview-status').textContent = '—';
  $('protection-preview-name').textContent = '—';
  $('protection-preview-type').textContent = '—';
  $('protection-preview-size').textContent = '—';
  $('protection-preview-parser').textContent = '—';
  $('protection-preview-entities').textContent = '—';
  $('protection-preview-source').textContent = '';
  const route = $('protection-forward-check');
  if (route) route.hidden = true;
}

function parseProtectionFilePreview(file, source, parserStatus = '已解析') {
  const kind = protectionFileKind(file.name, source);
  const lines = String(source || '').split(/\r?\n/).slice(0, 20).join('\n');
  const empty = $('protection-recent-empty');
  if (empty) empty.hidden = true;
  const readyForReplay = kind === 'json' && !String(parserStatus).includes('失败');
  $('protection-preview-status').textContent = readyForReplay ? '可执行防护回放' : '已解析，待进入对应检查';
  $('protection-preview-status').className = `pill ${readyForReplay ? 'success' : 'warning'}`;
  $('protection-preview-name').textContent = file.name;
  $('protection-preview-type').textContent = protectionFileTypeLabel(kind);
  $('protection-preview-size').textContent = `${(file.size / 1024).toFixed(1)} KiB`;
  $('protection-preview-parser').textContent = parserStatus;
  $('protection-preview-entities').textContent = protectionFileEntities(source, kind);
  $('protection-preview-source').textContent = lines || '文件为空';
  $('protection-file-preview').hidden = false;
  const route = $('protection-forward-check');
  if (route) {
    route.hidden = kind === 'json' || readyForReplay;
    route.textContent = kind === 'python' ? '转到工业代码安全检查' : '转到代码沙箱仿真';
  }
  protectionImportedFile = {name: file.name, source, kind};
  return kind;
}

function protectionRecentMetadata(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const keys = ['id', 'title', 'expected', 'description', 'mission', 'robot', 'phase', 'topics', 'threats', 'jev_context'];
  return Object.fromEntries(keys.filter((key) => meta[key] !== undefined).map((key) => [key, meta[key]]));
}

function protectionRiskLevel(value) {
  const risk = finiteNumber(value, NaN);
  if (!Number.isFinite(risk)) return '证据不足';
  if (risk >= 0.8) return '高风险';
  if (risk >= 0.5) return '需复核';
  return '当前可控';
}

function protectionSafetyScore(value) {
  const risk = finiteNumber(value, NaN);
  return Number.isFinite(risk) ? `${Math.max(0, Math.min(100, (1 - risk) * 100)).toFixed(0)} / 100` : '—';
}

function protectionDecisionText(safety) {
  if (!safety || typeof safety !== 'object') return '等待检查';
  if (safety.state === 'SAFE_STOP') return '高风险，任务已锁定';
  if (safety.state === 'CONTAINING') return '需要复核，已进入隔离';
  if (safety.mission_allowed === true) return '当前可继续验证';
  return '需要复核，任务未获许可';
}

function protectionCheckTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', {hour12: false});
}

function renderRecentProtectionResult(entry) {
  const recent = $('protection-recent-result');
  const empty = $('protection-recent-empty');
  if (!recent || !empty) return;
  if (!entry?.report) {
    recent.hidden = true;
    empty.hidden = false;
    return;
  }
  const report = entry.report || {};
  const final = report.final || {};
  const safety = final.safety || {};
  const risk = final.risk || {};
  $('protection-recent-state').textContent = safety.state || '—';
  $('protection-recent-state').className = `pill protection-pill ${protectionClass(safety.state)}`;
  $('protection-recent-decision').textContent = protectionDecisionText(safety);
  $('protection-recent-level').textContent = protectionRiskLevel(risk.risk);
  $('protection-recent-safety-score').textContent = protectionSafetyScore(risk.risk);
  $('protection-recent-time').textContent = protectionCheckTime(entry.saved_at);
  $('protection-recent-reason').textContent = safety.reason || final.plan?.reason || '已保存上次 Guardian 判定。';
  $('protection-recent-name').textContent = `${report.name || entry.filename || '未命名样例'} · 可恢复完整证据`;
  recent.hidden = false;
  empty.hidden = true;
}

function loadRecentProtectionResult() {
  try {
    const raw = localStorage.getItem(PROTECTION_RECENT_RESULT_KEY);
    if (!raw) return renderRecentProtectionResult(null);
    const entry = JSON.parse(raw);
    if (!entry || typeof entry.report !== 'object') return renderRecentProtectionResult(null);
    renderRecentProtectionResult(entry);
  } catch (_error) {
    renderRecentProtectionResult(null);
  }
}

function saveRecentProtectionResult(report) {
  try {
    localStorage.setItem(PROTECTION_RECENT_RESULT_KEY, JSON.stringify({
      saved_at: new Date().toISOString(),
      filename: protectionImportedFile?.name || 'guardian-replay.json',
      report,
      sample: protectionSample,
      sampleMeta: protectionRecentMetadata(protectionSampleMeta),
    }));
  } catch (_error) {
    // Local history is optional; the current report remains available in memory.
  }
  loadRecentProtectionResult();
}

function openRecentProtectionResult() {
  let entry = null;
  try {
    entry = JSON.parse(localStorage.getItem(PROTECTION_RECENT_RESULT_KEY) || 'null');
  } catch (_error) {
    entry = null;
  }
  if (!entry?.report) return setProtectionFeedback('暂无可恢复的检查记录。', 'error');
  protectionSample = entry.sample || null;
  protectionSampleMeta = entry.sampleMeta || null;
  protectionReport = entry.report;
  $('protection-run').disabled = !protectionSample;
  $('protection-jev-run').disabled = !protectionReport;
  renderIndustrialCase(protectionSampleMeta);
  renderProtectionReport(entry.report);
  setProtectionFeedback('已打开最近一次检查结果；当前页面未重新执行仿真。', 'success');
  $('protection-result').scrollIntoView({behavior: 'smooth', block: 'start'});
}

function forwardProtectionFile() {
  if (!protectionImportedFile || protectionImportedFile.kind === 'json') return;
  const {name, source, kind} = protectionImportedFile;
  if (kind === 'python') {
    codeSecurityFilename = name;
    setCodeSecuritySource(source, `已从防护实验室带入：${name} · 点击“执行安全检查”`);
    setCodeSecurityFileName(`${name} · 已带入`, 'success');
    setWorkspacePanel('code-security');
    return;
  }
  setSandboxSource(source, name, kind === 'xml' ? (sandboxKindFromFile(name, source) || 'sdf') : kind, `已从防护实验室带入：${name} · 点击“运行沙箱仿真”`);
  setSandboxFileName(`${name} · 已带入`, 'success');
  setWorkspacePanel('sandbox');
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
  protectionImportedFile = null;
  protectionReport = null;
  renderIndustrialCase(metadata);
  $('protection-run').disabled = !sample;
  $('protection-jev-run').disabled = true;
  resetProtectionJevEvaluation();
  $('protection-result').hidden = true;
  if (sample && $('protection-recent-empty')) $('protection-recent-empty').hidden = true;
  clearProtectionFilePreview();
  setProtectionFeedback(label, sample ? 'success' : '');
}

function renderProtectionSamples(payload) {
  protectionSamples = Array.isArray(payload?.samples) ? payload.samples : [];
  const select = $('protection-sample-select');
  select.innerHTML = protectionSamples.length
    ? protectionSamples.map((item) => `<option value="${esc(item.id)}">${esc(item.title)} · ${esc(item.expected)}</option>`).join('')
    : '<option value="">暂无内置样例</option>';
  if (protectionSamples.length) setProtectionSample(null, '请选择内置样例，或上传 JSON/PY/XML/SDF/URDF 文件');
  else setProtectionFeedback('内置样例读取失败，请上传 JSON/PY/XML/SDF/URDF 文件。', 'error');
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
  setProtectionFileName('未选择文件');
  setProtectionSample(entry.sample, `已导入：${entry.title} · ${entry.expected}`, entry);
}

function protectionSampleError(sample) {
  if (!sample || typeof sample !== 'object' || Array.isArray(sample)) {
    return 'JSON 顶层必须是对象。';
  }
  if (sample.schema !== 'guardian-replay/v1') {
    return 'schema 必须为 guardian-replay/v1。';
  }
  if (!Array.isArray(sample.events) || sample.events.length > 64) {
    return 'events 必须是最多 64 条事件的数组。';
  }
  return '';
}

async function loadProtectionFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  setProtectionFileName(`${file.name} · ${(file.size / 1024).toFixed(1)} KiB`);
  if (file.size > MAX_SAMPLE_BYTES) {
    setProtectionFileName('文件过大', 'error');
    return setProtectionFeedback('样例文件不能超过 64 KiB。', 'error');
  }
  try {
    const source = await file.text();
    const kind = protectionFileKind(file.name, source);
    if (kind === 'json') {
      const sample = JSON.parse(source);
      const validationError = protectionSampleError(sample);
      if (validationError) throw new Error(validationError);
      setProtectionSample(sample, `已导入文件：${file.name} · 点击“开始安全检查”`);
      protectionImportedFile = {name: file.name, source, kind};
      parseProtectionFilePreview(file, source, 'guardian-replay/v1 已解析');
      setProtectionFileName(`${file.name} · 已解析`, 'success');
      return;
    }
    setProtectionSample(null, `已解析：${file.name} · 请查看预览并进入对应检查模块`);
    parseProtectionFilePreview(file, source);
    setProtectionFileName(`${file.name} · 已解析`, 'success');
    setProtectionFeedback(
      kind === 'python'
        ? 'Python 文件已完成预览；点击“转到工业代码安全检查”继续。'
        : '仿真文件已完成预览；点击“转到代码沙箱仿真”继续。',
      'success',
    );
  } catch (_error) {
    const source = await file.text().catch(() => '');
    setProtectionFileName(`${file.name} · 解析失败`, 'error');
    setProtectionSample(null, '文件解析失败，请检查文件内容和扩展名');
    parseProtectionFilePreview(file, source, `解析失败：${_error.message || '格式不正确'}`);
    setProtectionFeedback(`样例导入失败：${_error.message || '文件格式不正确。'}`, 'error');
  }
}

function setCodeSecurityFeedback(message, kind = '') {
  const target = $('code-security-feedback');
  if (!target) return;
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

function setCodeSecurityFileName(message, kind = '') {
  const target = $('code-security-file-name');
  if (!target) return;
  target.textContent = message;
  target.className = `file-input-name${kind ? ` ${kind}` : ''}`;
}

function setCodeSecuritySource(source, label = '代码已载入') {
  codeSecuritySource = String(source || '');
  codeSecurityReport = null;
  $('code-security-source').value = codeSecuritySource;
  $('code-security-run').disabled = !codeSecuritySource.trim();
  $('code-security-jev-run').disabled = true;
  resetCodeSecurityJevEvaluation();
  $('code-security-result').hidden = true;
  setCodeSecurityFeedback(label, codeSecuritySource ? 'success' : '');
}

function renderCodeSecuritySamples(payload) {
  codeSecuritySamples = Array.isArray(payload?.samples) ? payload.samples : [];
  const select = $('code-security-sample-select');
  select.innerHTML = codeSecuritySamples.length
    ? codeSecuritySamples.map((item) => `<option value="${esc(item.id)}">${esc(item.title)}</option>`).join('')
    : '<option value="">暂无内置工业样例</option>';
  if (codeSecuritySamples.length) setCodeSecuritySource('', '请选择“导入内置样例”或上传 Python 文件');
  else setCodeSecurityFeedback('内置工业样例读取失败，请上传 Python 文件。', 'error');
}

async function loadCodeSecuritySamples() {
  try {
    const response = await fetch(CODE_SECURITY_SAMPLES_ENDPOINT, {cache: 'no-store'});
    const payload = await parseJsonResponse(response);
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    renderCodeSecuritySamples(payload);
  } catch (error) {
    setCodeSecurityFeedback(`无法读取工业代码样例：${redactJevMessage(error.message)}`, 'error');
  }
}

function loadSelectedCodeSecuritySample() {
  const id = $('code-security-sample-select').value;
  const entry = codeSecuritySamples.find((item) => item.id === id);
  if (!entry) return setCodeSecuritySource('', '没有可导入的工业代码样例');
  setCodeSecurityFileName('未选择文件');
  codeSecurityFilename = `${entry.id}.py`;
  setCodeSecuritySource(entry.source, `已导入：${entry.title} · 点击“执行安全检查”`);
}

async function loadCodeSecurityFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  setCodeSecurityFileName(`${file.name} · ${(file.size / 1024).toFixed(1)} KiB`);
  if (file.size > MAX_SAMPLE_BYTES) {
    setCodeSecurityFileName('文件过大', 'error');
    setCodeSecuritySource('', '代码文件不能超过 64 KiB。');
    return setCodeSecurityFeedback('代码文件不能超过 64 KiB。', 'error');
  }
  try {
    codeSecurityFilename = file.name;
    setCodeSecuritySource(await file.text(), `已加载：${file.name} · 点击“执行安全检查”`);
    setCodeSecurityFileName(`${file.name} · 已解析`, 'success');
  } catch (_error) {
    setCodeSecurityFileName(`${file.name} · 读取失败`, 'error');
    setCodeSecuritySource('', '无法读取代码文件。');
    setCodeSecurityFeedback('无法读取代码文件，请使用 UTF-8 编码的 Python 文件。', 'error');
  }
}

function renderCodeSecurityReport(report) {
  const summary = report.summary || {};
  const mapping = report.guardian_mapping || {};
  const assurance = report.assurance || {};
  const verdict = String(summary.verdict || '—');
  $('code-security-verdict').textContent = codeSecurityVerdictLabel(verdict);
  $('code-security-decision').textContent = codeSecurityVerdictLabel(verdict);
  $('code-security-next-step').textContent = codeSecurityNextStep(report);
  $('code-security-total').textContent = String(summary.total || 0);
  $('code-security-critical').textContent = String(summary.critical || 0);
  $('code-security-high').textContent = String(summary.high || 0);
  $('code-security-medium').textContent = String(summary.medium || 0);
  $('code-security-topics').textContent = Array.isArray(report.topics) && report.topics.length ? report.topics.join('、') : '无';
  $('code-security-mapping').textContent = CODE_SECURITY_GUARDIAN_LABELS[mapping.action] || mapping.action || '—';
  $('code-security-assurance-mode').textContent = assurance.mode === 'STATIC_ONLY' ? '静态分析（未执行源码）' : assurance.mode || '—';
  $('code-security-coverage').textContent = Number.isFinite(Number(assurance.coverage_score))
    ? `${Number(assurance.coverage_score).toFixed(1)} / 100`
    : '证据不足';
  $('code-security-runtime').textContent = assurance.runtime_verified === true ? '已验证' : '未验证';
  $('code-security-executed').textContent = assurance.source_executed === true ? '是' : '否';
  const missingControls = Array.isArray(assurance.missing_controls) && assurance.missing_controls.length
    ? assurance.missing_controls.join('、')
    : '当前静态检查项均满足';
  const limitations = Array.isArray(assurance.limitations) && assurance.limitations.length
    ? assurance.limitations.join('；')
    : CODE_SECURITY_STATIC_LIMITATION;
  $('code-security-missing-controls').textContent = `缺失或未验证控制项：${missingControls}`;
  $('code-security-assurance-limitations').textContent = `限制：${limitations}`;
  $('code-security-findings').innerHTML = (Array.isArray(report.findings) ? report.findings : []).map((item) => (
    `<tr><td class="${protectionClass(item.severity)}"><strong>${esc(CODE_SECURITY_SEVERITY_LABELS[item.severity] || item.severity || '—')}</strong><small class="code-security-raw">${esc(item.severity || '')}</small></td><td><span class="code-security-rule-id">${esc(item.rule_id || '—')}</span> · ${esc(item.title || '—')}</td><td>第 ${Number(item.line || 0)} 行</td><td class="code-security-evidence">${esc(item.evidence || '—')}</td><td>${esc(item.recommendation || '—')}</td><td>${esc(CODE_SECURITY_GUARDIAN_LABELS[item.guardian_action] || item.guardian_action || '—')}</td></tr>`
  )).join('') || '<tr><td colspan="6" class="empty">未发现当前规则覆盖的风险。</td></tr>';
  $('code-security-boundary').textContent = `为什么这样判定：${mapping.reason || '—'} 代码执行状态：${report.execution || '—'}。检查结果只用于上线前复核，不会自动修改代码或控制机器人。`;
  codeSecurityReport = report;
  $('code-security-jev-run').disabled = false;
  $('code-security-result').hidden = false;
}

function resetCodeSecurityJevEvaluation() {
  const result = $('code-security-jev-result');
  if (!result) return;
  result.hidden = true;
  $('code-security-jev-status').textContent = '未运行';
  $('code-security-jev-status').className = 'pill';
  $('code-security-jev-decision').textContent = '—';
  $('code-security-jev-explanation').textContent = '—';
  $('code-security-jev-label').textContent = '—';
  $('code-security-jev-score').textContent = '—';
  $('code-security-jev-confidence').textContent = '—';
  $('code-security-jev-impact').textContent = '—';
  $('code-security-jev-review').textContent = '—';
  $('code-security-jev-reason').textContent = '—';
}

function codeSecurityJevRatio(value) {
  const number = finiteNumber(value, NaN);
  return Number.isFinite(number) ? `${(number * 100).toFixed(1)} / 100` : '—';
}

function renderCodeSecurityJevEvaluation(payload) {
  const jev = payload.jev || {};
  const assessment = jev.assessment || {};
  const status = jev.status || 'LOCAL_ONLY';
  const connected = jev.connected === true && status === 'OK';
  $('code-security-jev-status').textContent = connected ? '已连接' : status;
  $('code-security-jev-status').className = `pill ${connected ? 'success' : 'warning'}`;
  $('code-security-jev-decision').textContent = codeSecurityJevDecision(assessment);
  $('code-security-jev-explanation').textContent = codeSecurityJevExplanation(assessment);
  $('code-security-jev-label').textContent = assessment.label || '—';
  $('code-security-jev-score').textContent = codeSecurityJevRatio(assessment.score);
  $('code-security-jev-confidence').textContent = codeSecurityJevRatio(assessment.confidence);
  $('code-security-jev-impact').textContent = assessment.mission_impact || '—';
  $('code-security-jev-review').textContent = assessment.needs_human_review === true ? '需要' : assessment.needs_human_review === false ? '不需要' : '—';
  $('code-security-jev-reason').textContent = assessment.reason || jev.error?.message || 'Jev 未返回语义判断。';
  $('code-security-jev-result').hidden = false;
}

async function runCodeSecurityInspection() {
  const source = $('code-security-source').value;
  if (!source.trim()) return setCodeSecurityFeedback('请先导入或粘贴 ROS 2 Python 控制代码。', 'error');
  const button = $('code-security-run');
  button.disabled = true;
  setCodeSecurityFeedback('正在进行只读安全检查…');
  try {
    const response = await fetch(CODE_SECURITY_INSPECT_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify({source, filename: codeSecurityFilename, profile: 'conveyor_robot_arm'}),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || payload?.status !== 'OK' || !payload.report) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    codeSecuritySource = source;
    renderCodeSecurityReport(payload.report);
    const verdict = payload.report.summary?.verdict || 'REVIEW';
    setCodeSecurityFeedback(`安全检查完成：${verdict}。已生成 Guardian 防护映射。`, verdict === 'PASS' ? 'success' : 'error');
  } catch (error) {
    setCodeSecurityFeedback(`安全检查失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    button.disabled = false;
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
  const policy = report.policy || {};
  const safety = final.safety || {};
  const plan = final.plan || {};
  const risk = final.risk || {};
  const assurance = report.assurance || {};
  const steps = Array.isArray(report.steps) ? report.steps : [];
  const reason = safety.reason || plan.reason || risk.reason || 'Guardian 已完成确定性安全判定。';
  const trustedSources = Array.isArray(policy.trusted_sources) && policy.trusted_sources.length
    ? policy.trusted_sources.join('、')
    : '—';
  const mitigatableDevices = Array.isArray(policy.mitigatable_devices) && policy.mitigatable_devices.length
    ? policy.mitigatable_devices.join('、')
    : '—';
  const formatLimit = (value) => Number.isFinite(Number(value)) ? `${Number(value).toFixed(2)} s` : '—';
  const formatThreshold = (value) => Number.isFinite(Number(value)) ? Number(value).toFixed(2) : '—';

  protectionReport = report;
  resetProtectionJevEvaluation();
  $('protection-verdict-state').textContent = safety.state || '—';
  $('protection-verdict-state').className = `pill protection-pill ${protectionClass(safety.state)}`;
  $('protection-verdict-name').textContent = report.name || '—';
  $('protection-verdict-profile').textContent = report.profile || '—';
  $('protection-verdict-mission').textContent = safety.mission_allowed ? '允许' : '锁定';
  $('protection-verdict-action').textContent = plan.action || '—';
  $('protection-verdict-speed').textContent = `${Number(safety.speed_limit || 0).toFixed(2)} m/s`;
  $('protection-verdict-total').textContent = String(Number(summary.total || steps.length));
  $('protection-verdict-counts').textContent = `${Number(summary.accepted || 0)} / ${Number(summary.rejected || 0)}`;
  $('protection-verdict-reason').textContent = `Guardian 判定依据：${reason}`;
  $('protection-assurance-mode').textContent = assurance.mode === 'OFFLINE_REPLAY' ? '离线事件回放' : assurance.mode || '—';
  const offlineLogicScore = assurance.offline_logic_check_score ?? assurance.coverage_score;
  $('protection-assurance-coverage').textContent = Number.isFinite(Number(offlineLogicScore))
    ? `${Number(offlineLogicScore).toFixed(1)} / 100`
    : '证据不足';
  $('protection-assurance-runtime').textContent = assurance.runtime_verified === true ? '已验证' : '未验证';
  $('protection-assurance-actuation').textContent = assurance.actuation === 'none' ? '未执行' : assurance.actuation || '—';
  const assuranceLimitations = Array.isArray(assurance.limitations) && assurance.limitations.length
    ? assurance.limitations.join('；')
    : '—';
  $('protection-assurance-limitations').textContent = `限制：${assuranceLimitations}`;

  $('protection-evidence').innerHTML = steps.map((step) => {
    const event = step.event || {};
    const verification = step.verification || {};
    const sequence = step.event ? step.event.sequence : '—';
    const confidence = step.event ? step.event.confidence : null;
    const confidenceText = Number.isFinite(Number(confidence)) ? `${(Number(confidence) * 100).toFixed(0)}%` : '—';
    const code = verification.code || '未校验';
    return `<tr><td>${Number(step.at || event.timestamp || 0).toFixed(2)} s</td><td class="mono">${esc(event.event_id || '—')}</td><td>${esc(event.source || '—')}</td><td>${esc(event.component || '—')}</td><td>${esc(event.attack_type || '—')}</td><td class="mono">${esc(sequence)}</td><td>${confidenceText}</td><td class="${protectionClass(code)}">${esc(code)}</td></tr>`;
  }).join('') || '<tr><td colspan="8" class="empty">没有可展示的事件证据。</td></tr>';

  $('protection-steps').innerHTML = steps.map((step) => {
    const verification = step.verification || {};
    const risk = step.risk || {};
    const rowSafety = step.safety || {};
    const rowPlan = step.plan || {};
    const code = verification.code || '—';
    return `<tr><td>${Number(step.at || 0).toFixed(2)} s</td><td class="${protectionClass(code)}">${esc(code)}</td><td>${(Number(risk.risk || 0) * 100).toFixed(1)} / ${esc(risk.reason || '—')}</td><td>${esc(rowPlan.action || '—')}</td><td class="${protectionClass(rowSafety.state)}">${esc(rowSafety.state || '—')}</td><td>${Number(rowSafety.speed_limit || 0).toFixed(2)} m/s</td></tr>`;
  }).join('');

  $('protection-policy-sources').textContent = trustedSources;
  $('protection-policy-window').textContent = `事件年龄 ≤ ${formatLimit(policy.max_event_age_sec)}；未来偏移 ≤ ${formatLimit(policy.max_future_skew_sec)}`;
  $('protection-policy-thresholds').textContent = `关键 ${formatThreshold(policy.theta_crit)} / 基础 ${formatThreshold(policy.theta_base)}；α 关键 ${formatThreshold(policy.alpha_crit)} / 基础 ${formatThreshold(policy.alpha_base)}`;
  $('protection-policy-devices').textContent = mitigatableDevices;
  $('protection-boundary-result').textContent = `最终结果：${safety.state || '—'}；任务${safety.mission_allowed ? '允许' : '锁定'}；${plan.action || '无缓解动作'}；速度上限 ${Number(safety.speed_limit || 0).toFixed(2)} m/s。`;
  $('protection-jev-run').disabled = false;
  $('protection-result').hidden = false;
  const technicalDetails = $('protection-technical-details');
  if (technicalDetails) technicalDetails.open = false;
}

function resetProtectionJevEvaluation() {
  const result = $('protection-jev-result');
  if (!result) return;
  result.hidden = true;
  $('protection-jev-status').textContent = '未运行';
  $('protection-jev-status').className = 'pill protection-pill';
  $('protection-jev-risk-score').textContent = '—';
  $('protection-jev-safety-score').textContent = '—';
  $('protection-jev-level').textContent = '—';
  $('protection-jev-calls').textContent = '0';
  $('protection-jev-method').textContent = '—';
  $('protection-jev-events').innerHTML = '';
  $('protection-jev-basis').textContent = '—';
  $('protection-summary-state').textContent = '—';
  $('protection-summary-decision').textContent = '—';
  $('protection-summary-evidence').textContent = '—';
  $('protection-summary-limitations').textContent = '—';
}

function protectionScoreText(value) {
  const number = finiteNumber(value, NaN);
  return Number.isFinite(number) ? `${number.toFixed(1)} / 100` : '—';
}

function protectionRatioText(value) {
  const number = finiteNumber(value, NaN);
  return Number.isFinite(number) ? `${(number * 100).toFixed(1)} / 100` : '—';
}

function protectionActionSafety(scoring, compositeRisk) {
  const rawScore = finiteNumber(scoring?.safety_score, NaN);
  const score = Number.isFinite(rawScore) ? rawScore : Number.isFinite(compositeRisk) ? (1 - compositeRisk) * 100 : NaN;
  if (!Number.isFinite(score)) return {label: '证据不足', className: 'unverified-event'};
  if (score >= 80) return {label: `安全（${score.toFixed(0)} / 100）`, className: 'safe'};
  if (score >= 60) return {label: `需注意（${score.toFixed(0)} / 100）`, className: 'caution'};
  return {label: `高风险（${score.toFixed(0)} / 100）`, className: 'critical'};
}

function protectionEvaluationStatusLabel(status) {
  return {
    OK: 'Jev 评价完成',
    PARTIAL: '部分事件完成，需复核',
    LOCAL_ONLY: '本地校验结果，未调用 Jev',
    INSUFFICIENT_EVIDENCE: '证据不足，不能判定为安全',
  }[String(status || '').toUpperCase()] || status || '—';
}

function renderProtectionJevEvaluation(report) {
  const evaluation = report.jev_evaluation || {};
  const aggregate = evaluation.aggregate || {};
  const safetySummary = report.safety_summary || {};
  const evidenceSummary = safetySummary.evidence || {};
  const level = aggregate.level || '—';
  $('protection-jev-status').textContent = protectionEvaluationStatusLabel(evaluation.status);
  $('protection-jev-status').className = `pill protection-pill ${protectionClass(level)}`;
  $('protection-jev-risk-score').textContent = protectionScoreText(aggregate.risk_score);
  $('protection-jev-safety-score').textContent = protectionScoreText(aggregate.safety_score);
  $('protection-jev-level').textContent = level;
  $('protection-jev-calls').textContent = String(Number(evaluation.calls || 0));
  const method = evaluation.method === 'guardian_60_percent_plus_jev_40_percent'
    ? 'Guardian 60% + Jev 40%；Jev 置信度低于 70 分时采用保守融合'
    : evaluation.method || '—';
  $('protection-jev-method').textContent = `${method}；最高事件风险 ${protectionScoreText(aggregate.max_event_risk)}；平均事件风险 ${protectionScoreText(aggregate.mean_event_risk)}`;
  const events = Array.isArray(evaluation.events) ? evaluation.events : [];
  $('protection-jev-events').innerHTML = events.map((item) => {
    const event = item.event || {};
    const guardian = item.guardian || {};
    const jev = item.jev || {};
    const scoring = item.scoring || {};
    const compositeRisk = finiteNumber(scoring.composite_risk, NaN);
    const compositeScore = Number.isFinite(compositeRisk) ? compositeRisk * 100 : scoring.risk_score;
    const basis = Array.isArray(scoring.basis_zh) ? scoring.basis_zh.join('；') : Array.isArray(scoring.basis) ? scoring.basis.join('；') : '—';
    const actionSafety = protectionActionSafety(scoring, compositeRisk);
    return `<tr><td>${Number(item.at || 0).toFixed(2)} s</td><td class="mono">${esc(event.event_id || event.action || '—')}</td><td class="${protectionClass(guardian.verification_code)}">${esc(guardian.verification_code || '—')}</td><td>${esc(jev.label || jev.status || '—')}</td><td>${protectionRatioText(jev.risk)}</td><td>${protectionRatioText(jev.confidence)}</td><td class="${protectionClass(scoring.level)}">${protectionScoreText(compositeScore)}</td><td class="${actionSafety.className}">${esc(actionSafety.label)}</td><td class="protection-jev-evidence">${esc(basis)}</td></tr>`;
  }).join('') || '<tr><td colspan="9" class="empty">没有可展示的 Jev 事件评价。</td></tr>';
  $('protection-jev-basis').textContent = Array.isArray(aggregate.basis) ? aggregate.basis.join('；') : '—';
  $('protection-summary-state').textContent = safetySummary.state || '—';
  $('protection-summary-state').className = `pill protection-pill ${protectionClass(safetySummary.state)}`;
  $('protection-summary-decision').textContent = safetySummary.decision || '证据不足，不能判定为安全';
  $('protection-summary-evidence').textContent = `事件 ${Number(evidenceSummary.total_events || 0)} 条；Guardian 接受 ${Number(evidenceSummary.accepted_events || 0)} 条；本地拒绝 ${Number(evidenceSummary.locally_rejected || 0)} 条；Jev 成功 ${Number(evidenceSummary.jev_successes || 0)} 条；低置信度 ${Number(evidenceSummary.low_confidence_events || 0)} 条。`;
  $('protection-summary-limitations').textContent = `边界：${safetySummary.limitations || '未验证真实执行器动作。'}`;
  $('protection-jev-result').hidden = false;
  const technicalDetails = $('protection-technical-details');
  if (technicalDetails) technicalDetails.open = true;
}

async function runProtectionJevEvaluation() {
  if (!protectionSample || !protectionReport) {
    return setProtectionFeedback('请先导入样例并执行 Guardian 防护判断。', 'error');
  }
  const typedApiKey = $('jev-api-key').value.trim();
  if (!typedApiKey && !jevKeySaved) {
    setProtectionFeedback('请先在 Jev 页面保存 API Key，再运行逐事件综合评价。', 'error');
    return;
  }
  const button = $('protection-jev-run');
  button.disabled = true;
  setProtectionFeedback('正在逐事件调用 Jev 并计算综合风险…');
  try {
    const requestBody = {sample: protectionSample};
    if (typedApiKey) requestBody.api_key = typedApiKey;
    const response = await fetch(EXPERIMENT_JEV_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify(requestBody),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || payload?.status !== 'OK' || !payload.report?.jev_evaluation) {
      throw new Error(jevErrorMessage(payload, response));
    }
    renderProtectionJevEvaluation(payload.report);
    if (typedApiKey) {
      try {
        await saveJevKey(typedApiKey);
      } catch (_error) {
        setProtectionFeedback('Jev 综合评价完成，但 API Key 持久保存失败。', 'error');
        return;
      }
    }
    const aggregate = payload.report.jev_evaluation.aggregate || {};
    setProtectionFeedback(`Jev 综合评价完成：${aggregate.risk_score ?? '—'} / 100，${aggregate.level || '—'}。Guardian 硬安全状态保持不变。`, 'success');
  } catch (error) {
    setProtectionFeedback(`Jev 综合评价失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    button.disabled = !protectionReport;
  }
}

async function runCodeSecurityJevEvaluation() {
  if (!codeSecuritySource.trim() || !codeSecurityReport) {
    return setCodeSecurityFeedback('请先执行一次本地静态安全检查。', 'error');
  }
  const typedApiKey = $('code-security-jev-key').value.trim();
  if (!typedApiKey && !jevKeySaved) {
    return setCodeSecurityFeedback('请先在 Jev 页面保存 API Key，或在此处输入本次使用的 Key。', 'error');
  }
  const button = $('code-security-jev-run');
  button.disabled = true;
  setCodeSecurityFeedback('正在调用 Jev 复核工业代码风险置信度…');
  try {
    const requestBody = {
      source: codeSecuritySource,
      filename: codeSecurityFilename,
      profile: 'conveyor_robot_arm',
    };
    if (typedApiKey) requestBody.api_key = typedApiKey;
    const response = await fetch(CODE_SECURITY_JEV_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify(requestBody),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || payload?.status !== 'OK' || !payload.report || !payload.jev) {
      throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    }
    renderCodeSecurityReport(payload.report);
    renderCodeSecurityJevEvaluation(payload);
    if (typedApiKey) {
      try {
        await saveJevKey(typedApiKey);
      } catch (_error) {
        setCodeSecurityFeedback('Jev 复核完成，但 API Key 持久保存失败。', 'error');
        return;
      }
    }
    const jev = payload.jev || {};
    const assessment = jev.assessment || {};
    const status = jev.status === 'OK' ? '已连接' : 'LOCAL_ONLY';
    setCodeSecurityFeedback(`Jev 置信度复核完成：${status}；置信度 ${codeSecurityJevRatio(assessment.confidence)}。本地结论保持 ${payload.report.summary?.verdict || 'REVIEW'}。`, 'success');
  } catch (error) {
    setCodeSecurityFeedback(`Jev 置信度复核失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    button.disabled = !codeSecurityReport;
  }
}

function setSandboxFeedback(message, kind = '') {
  const target = $('sandbox-feedback');
  if (!target) return;
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

function setSandboxFileName(message, kind = '') {
  const target = $('sandbox-file-name');
  if (!target) return;
  target.textContent = message;
  target.className = `file-input-name${kind ? ` ${kind}` : ''}`;
}

function setSandboxSource(source, filename, kind, label = '文件已载入') {
  sandboxSource = String(source || '');
  sandboxFilename = String(filename || 'dashboard-sandbox.py');
  sandboxKind = String(kind || 'python');
  sandboxReport = null;
  $('sandbox-source').value = sandboxSource;
  $('sandbox-run').disabled = !sandboxSource.trim();
  $('sandbox-result').hidden = true;
  setSandboxFeedback(label, sandboxSource ? 'success' : '');
}

function renderSandboxSamples(payload) {
  sandboxSamples = Array.isArray(payload?.samples) ? payload.samples : [];
  const runtime = payload?.runtime || {};
  const boundary = $('sandbox-runtime-boundary');
  if (boundary) {
    boundary.textContent = runtime.available === true
      ? `${runtime.provider || '隔离执行器'} 可用；${runtime.boundary || '运行时受限'}`
      : runtime.reason || '隔离执行器不可用；上传代码不会执行。';
  }
  const select = $('sandbox-sample-select');
  select.innerHTML = sandboxSamples.length
    ? sandboxSamples.map((item) => `<option value="${esc(item.id)}">${esc(item.title)} · ${esc(item.kind)}</option>`).join('')
    : '<option value="">暂无内置沙箱样例</option>';
  if (sandboxSamples.length) setSandboxSource('', 'dashboard-sandbox.py', 'python', '请选择“导入内置样例”或上传本地文件');
  else setSandboxFeedback('内置沙箱样例读取失败，请上传 .py、.sdf 或 .urdf 文件。', 'error');
}

async function loadSandboxSamples() {
  try {
    const response = await fetch(SANDBOX_SAMPLES_ENDPOINT, {cache: 'no-store'});
    const payload = await parseJsonResponse(response);
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    renderSandboxSamples(payload);
  } catch (error) {
    setSandboxFeedback(`无法读取沙箱样例：${redactJevMessage(error.message)}`, 'error');
  }
}

function loadSelectedSandboxSample() {
  const id = $('sandbox-sample-select').value;
  const entry = sandboxSamples.find((item) => item.id === id);
  if (!entry) return setSandboxSource('', 'dashboard-sandbox.py', 'python', '没有可导入的沙箱样例');
  setSandboxFileName('未选择文件');
  setSandboxSource(entry.source, entry.filename, entry.kind, `已导入：${entry.title} · 点击“运行沙箱仿真”`);
}

function sandboxKindFromFile(fileName, source) {
  const lower = String(fileName || '').toLowerCase();
  if (lower.endsWith('.py')) return 'python';
  if (lower.endsWith('.sdf') || lower.endsWith('.world')) return 'sdf';
  if (lower.endsWith('.urdf')) return 'urdf';
  if (lower.endsWith('.xml')) {
    if (/<\s*sdf(?:\s|>)/i.test(source)) return 'sdf';
    if (/<\s*robot(?:\s|>)/i.test(source)) return 'urdf';
  }
  return '';
}

async function loadSandboxFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  setSandboxFileName(`${file.name} · ${(file.size / 1024).toFixed(1)} KiB`);
  if (file.size > 128 * 1024) {
    setSandboxFileName('文件过大', 'error');
    return setSandboxFeedback('沙箱文件不能超过 128 KiB。', 'error');
  }
  try {
    const source = await file.text();
    const kind = sandboxKindFromFile(file.name, source);
    if (!kind) throw new Error('无法根据扩展名或 XML 根节点识别 Python、SDF 或 URDF');
    setSandboxSource(source, file.name, kind, `已加载：${file.name} · 点击“运行沙箱仿真”`);
    setSandboxFileName(`${file.name} · 已解析`, 'success');
  } catch (error) {
    setSandboxFileName(`${file.name} · 解析失败`, 'error');
    setSandboxSource('', file.name, '', '文件未载入');
    setSandboxFeedback(`沙箱文件导入失败：${error.message || '文件格式不支持'}`, 'error');
  }
}

function sandboxScoreText(value) {
  const number = finiteNumber(value, NaN);
  return Number.isFinite(number) ? `${number.toFixed(0)} / 100` : '—';
}

function sandboxVerdictLabel(value) {
  return {PASS: '当前场景通过', REVIEW: '需要整改复核', BLOCKED: '必须阻断', UNAVAILABLE: '未执行'}[String(value || '').toUpperCase()] || '需要复核';
}

function sandboxSeverityLabel(value) {
  return {critical: '必须阻断', high: '高风险', medium: '待复核', low: '低风险'}[String(value || '').toLowerCase()] || value || '—';
}

function renderSandboxCanvas(trace) {
  const canvas = $('sandbox-canvas');
  if (!canvas) return;
  const context = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  context.clearRect(0, 0, width, height);
  context.fillStyle = '#0d1319';
  context.fillRect(0, 0, width, height);
  context.strokeStyle = '#344451';
  context.lineWidth = 1;
  context.beginPath();
  context.moveTo(42, height - 32);
  context.lineTo(width - 20, height - 32);
  context.moveTo(42, 20);
  context.lineTo(42, height - 32);
  context.stroke();
  if (!Array.isArray(trace) || trace.length === 0) {
    context.fillStyle = '#93a4b0';
    context.font = '14px sans-serif';
    context.fillText('没有可绘制的轨迹', 56, 48);
    return;
  }
  const maxX = Math.max(1, ...trace.map((item) => finiteNumber(item.x)));
  const plotWidth = width - 72;
  const plotHeight = height - 62;
  const point = (item) => [42 + finiteNumber(item.x) / maxX * plotWidth, height - 32 - Math.min(1, Math.max(0, finiteNumber(item.y) + 0.5)) * plotHeight];
  context.strokeStyle = '#54b8ff';
  context.lineWidth = 3;
  context.beginPath();
  trace.forEach((item, index) => {
    const [x, y] = point(item);
    if (index === 0) context.moveTo(x, y);
    else context.lineTo(x, y);
  });
  context.stroke();
  trace.filter((item) => item.collision === true).forEach((item) => {
    const [x, y] = point(item);
    context.fillStyle = '#ff6b6b';
    context.beginPath();
    context.arc(x, y, 5, 0, Math.PI * 2);
    context.fill();
  });
  context.fillStyle = '#93a4b0';
  context.font = '12px sans-serif';
  context.fillText(`x 0–${maxX.toFixed(2)} m`, 48, height - 10);
  context.fillText('实际轨迹', 52, 18);
}

function renderSandboxJev(report) {
  const result = $('sandbox-jev-result');
  const jev = report?.jev || {};
  const assessment = jev.assessment || {};
  const connected = jev.connected === true && jev.status === 'OK';
  $('sandbox-jev-status').textContent = connected ? '已连接' : jev.status === 'LOCAL_ONLY' ? '未调用' : jev.status || '不可用';
  $('sandbox-jev-status').className = `pill ${connected ? 'success' : 'warning'}`;
  $('sandbox-jev-label').textContent = assessment.label || '—';
  $('sandbox-jev-score').textContent = assessment.score === undefined ? '—' : protectionRatioText(assessment.score);
  $('sandbox-jev-confidence').textContent = assessment.confidence === undefined ? '—' : protectionRatioText(assessment.confidence);
  $('sandbox-jev-impact').textContent = assessment.mission_impact || '—';
  $('sandbox-jev-review').textContent = assessment.needs_human_review === true ? '需要' : assessment.needs_human_review === false ? '不需要' : '—';
  $('sandbox-jev-explanation').textContent = assessment.reason || jev.error?.message || '未调用 Jev；以上结论来自本地仿真证据。';
  result.hidden = false;
}

function renderSandboxReport(report) {
  const metrics = report.metrics || {};
  const sandbox = report.sandbox || {};
  sandboxReport = report;
  $('sandbox-verdict').textContent = sandboxVerdictLabel(report.verdict);
  $('sandbox-verdict').className = `pill sandbox-pill ${protectionClass(report.verdict)}`;
  $('sandbox-risk-score').textContent = sandboxScoreText(report.risk_score);
  $('sandbox-safety-score').textContent = sandboxScoreText(report.safety_score);
  $('sandbox-engine').textContent = report.engine || '—';
  $('sandbox-isolation').textContent = sandbox.isolated === true ? `${sandbox.provider || '已隔离'} · 网络关闭` : '未使用源码沙箱';
  $('sandbox-executed').textContent = report.source_executed === true ? '是' : '否';
  $('sandbox-hash').textContent = String(report.source_sha256 || '—').slice(0, 16);
  const validation = report.validation || {};
  const validationText = validation.checked === true
    ? `SDF 引擎校验：${validation.passed === true ? '通过' : '未通过'}${validation.message ? `（${validation.message}）` : ''}。`
    : '';
  $('sandbox-summary').textContent = [report.summary_zh, validationText].filter(Boolean).join(' ');
  $('sandbox-metric-steps').textContent = `${Number(metrics.steps || 0)} 个周期`;
  $('sandbox-metric-requested').textContent = `${finiteNumber(metrics.max_requested_speed).toFixed(2)} m/s`;
  $('sandbox-metric-applied').textContent = `${finiteNumber(metrics.max_applied_speed).toFixed(2)} m/s`;
  $('sandbox-metric-limit').textContent = `${finiteNumber(metrics.safety_limit, 0.35).toFixed(2)} m/s`;
  $('sandbox-metric-overspeed').textContent = `${Number(metrics.overspeed_steps || 0)} 个`;
  $('sandbox-metric-collision').textContent = `${Number(metrics.collision_steps || 0)} 个`;
  $('sandbox-metric-distance').textContent = metrics.min_obstacle_distance === null || metrics.min_obstacle_distance === undefined ? '无障碍' : `${finiteNumber(metrics.min_obstacle_distance).toFixed(3)} m`;
  const events = Array.isArray(report.events) ? report.events : [];
  $('sandbox-event-count').textContent = `${events.length} 个事件`;
  $('sandbox-events').innerHTML = events.map((item) => `<tr><td>${finiteNumber(item.at).toFixed(2)} s</td><td class="${protectionClass(item.severity)}">${esc(sandboxSeverityLabel(item.severity))}</td><td>${esc(item.title || item.type || '—')}</td><td>${esc(item.evidence || '—')}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">没有观察到风险事件。</td></tr>';
  renderSandboxCanvas(report.trace);
  renderSandboxJev(report);
  $('sandbox-summary-state').textContent = sandboxVerdictLabel(report.verdict);
  $('sandbox-summary-state').className = `pill sandbox-pill ${protectionClass(report.verdict)}`;
  $('sandbox-safety-summary').textContent = report.summary_zh || '—';
  const limitations = [report.engine_description, sandbox.boundary, '结果只覆盖当前固定场景和执行时长，不代表真实机器人认证。'].filter(Boolean);
  $('sandbox-limitations').textContent = `边界：${limitations.join('；')}`;
  $('sandbox-result').hidden = false;
}

async function runSandboxSimulation() {
  const source = $('sandbox-source').value;
  if (!source.trim()) return setSandboxFeedback('请先导入 Python、SDF 或 URDF 文件。', 'error');
  const button = $('sandbox-run');
  button.disabled = true;
  setSandboxFeedback('正在启动受限执行器并生成运动证据…');
  try {
    const requestBody = {
      source,
      filename: sandboxFilename,
      kind: sandboxKind,
      duration_sec: Math.max(0.2, Math.min(8, finiteNumber($('sandbox-duration').value, 4))),
    };
    const key = $('sandbox-jev-key').value.trim();
    if (key) requestBody.api_key = key;
    const response = await fetch(SANDBOX_RUN_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      cache: 'no-store',
      body: JSON.stringify(requestBody),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || payload?.status !== 'OK' || !payload.report) throw new Error(jevErrorMessage(payload, response));
    renderSandboxReport(payload.report);
    if (key) {
      try {
        await saveJevKey(key);
      } catch (_error) {
        setSandboxFeedback('仿真已完成，但 Jev Key 持久保存失败。', 'error');
        return;
      }
    }
    const jev = payload.report.jev || {};
    const jevText = jev.connected ? '，Jev 已复核仿真证据' : '，未调用 Jev，保留本地证据';
    setSandboxFeedback(`沙箱仿真完成：${sandboxVerdictLabel(payload.report.verdict)}${jevText}。`, payload.report.verdict === 'PASS' ? 'success' : 'error');
  } catch (error) {
    setSandboxFeedback(`沙箱仿真失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    button.disabled = !sandboxSource.trim();
  }
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
    saveRecentProtectionResult(payload.report);
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
  try {
    const response = await fetch(LOGIN_ENDPOINT, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store',
      body: JSON.stringify({username, password}),
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok || !payload || payload.authenticated !== true) {
      if (response.status === 401) {
        showLogin('用户名或密码错误');
      } else if (response.status === 404 || response.status === 405 || response.status === 501) {
        showLogin('登录服务未启动：请先启动 ROS 2 Dashboard 后再登录');
      } else {
        showLogin(`登录服务异常（HTTP ${response.status}）`);
      }
      return;
    }
    showApp();
    await loadJevKeyStatus();
    await loadProtectionSamples();
    await loadCodeSecuritySamples();
    await loadSandboxSamples();
    refresh();
  } catch (_error) {
    showLogin('无法连接本地服务：请先启动 ROS 2 Dashboard');
  }
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
      await loadCodeSecuritySamples();
      await loadSandboxSamples();
      refresh();
    } else {
      if (response.status === 404 || response.status === 405 || response.status === 501) {
        showLogin('登录服务未启动：请先启动 ROS 2 Dashboard 后再登录');
      } else {
        showLogin();
      }
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
  loadRecentProtectionResult();
  $('protection-open-recent').addEventListener('click', openRecentProtectionResult);
  $('protection-forward-check').addEventListener('click', forwardProtectionFile);
  $('protection-load').addEventListener('click', loadSelectedProtectionSample);
  $('protection-file').addEventListener('click', () => {
    setProtectionFileName('正在等待选择 JSON/PY/XML/SDF/URDF 文件…');
    setProtectionFeedback('选择文件后会先显示文件信息和前 20 行预览，不会立即执行。');
  });
  $('protection-file').addEventListener('change', loadProtectionFile);
  $('protection-file').addEventListener('cancel', () => {
    setProtectionFileName('未选择文件');
    setProtectionFeedback('未选择新文件，当前样例保持不变。');
  });
  $('protection-run').addEventListener('click', runProtectionReplay);
  $('protection-jev-run').addEventListener('click', runProtectionJevEvaluation);
  $('protection-jev-load').addEventListener('click', loadIndustrialJevContext);
}

function setupCodeSecurity() {
  const select = $('code-security-sample-select');
  if (!select) return;
  $('code-security-load').addEventListener('click', loadSelectedCodeSecuritySample);
  $('code-security-file').addEventListener('click', () => {
    setCodeSecurityFileName('正在等待选择 Python 文件…');
    setCodeSecurityFeedback('请选择本地 .py 文件；取消选择不会改变当前代码。');
  });
  $('code-security-file').addEventListener('change', loadCodeSecurityFile);
  $('code-security-file').addEventListener('cancel', () => {
    setCodeSecurityFileName('未选择文件');
    setCodeSecurityFeedback('未选择新文件，当前代码保持不变。');
  });
  $('code-security-run').addEventListener('click', runCodeSecurityInspection);
  $('code-security-jev-run').addEventListener('click', runCodeSecurityJevEvaluation);
  $('code-security-source').addEventListener('input', () => {
    codeSecuritySource = $('code-security-source').value;
    $('code-security-run').disabled = !codeSecuritySource.trim();
  });
}

function setupSandbox() {
  const select = $('sandbox-sample-select');
  if (!select) return;
  $('sandbox-load').addEventListener('click', loadSelectedSandboxSample);
  $('sandbox-file').addEventListener('click', () => {
    setSandboxFileName('正在等待选择 Python / SDF / URDF 文件…');
    setSandboxFeedback('请选择本地文件；取消选择不会改变当前源码。');
  });
  $('sandbox-file').addEventListener('change', loadSandboxFile);
  $('sandbox-file').addEventListener('cancel', () => {
    setSandboxFileName('未选择文件');
    setSandboxFeedback('未选择新文件，当前源码保持不变。');
  });
  $('sandbox-run').addEventListener('click', runSandboxSimulation);
  $('sandbox-source').addEventListener('input', () => {
    sandboxSource = $('sandbox-source').value;
    $('sandbox-run').disabled = !sandboxSource.trim();
  });
}

function setupDatasetSecurity() {
  const button = $('dataset-security-run');
  if (!button) return;
  ['dataset-security-files-input', 'dataset-security-folder-input', 'dataset-security-zip-input']
    .forEach((id) => {
      const input = $(id);
      input.addEventListener('change', handleDatasetUploadSelection);
      input.addEventListener('cancel', () => {
        if (!datasetUploadBusy) setDatasetSecurityFeedback('未选择新文件，本次待审计清单保持不变。');
      });
    });
  button.addEventListener('click', runDatasetSecurityScan);
}

function simulationFeedback(message, kind = '') {
  const target = $('simulation-feedback');
  if (!target) return;
  target.textContent = message;
  target.className = `muted${kind ? ` ${kind}` : ''}`;
}

async function sendSimulationControl(action, type = null) {
  if (simulationCommandBusy) return;
  simulationCommandBusy = true;
  document.querySelectorAll('#panel-simulation .simulation-controls .button').forEach((button) => { button.disabled = true; });
  const labels = {start: '正在启动托盘运输任务…', stop: '正在停止仿真任务…', reset: '正在重置仿真场景…', speed_abuse: '正在注入超速指令…', replay: '正在注入序列重放…', gripper_fault: '正在注入抓取器语义故障…'};
  simulationFeedback(labels[type || action] || '正在发送仿真控制…');
  try {
    const body = {action};
    if (action === 'attack') body.type = type;
    const response = await fetch(SIMULATION_CONTROL_ENDPOINT, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store', body: JSON.stringify(body),
    });
    const payload = await parseJsonResponse(response);
    if (response.status === 401) { showLogin('登录已过期，请重新登录'); return; }
    if (!response.ok || payload?.status !== 'SENT') throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    const detail = action === 'reset'
      ? '场景已重置；Guardian 会在已登记事件的 TTL 到期后恢复 NORMAL。'
      : `已发送：${action === 'attack' ? `攻击 / ${type}` : action}。请观察下方实际速度和 Guardian 状态变化。`;
    simulationFeedback(detail, 'success');
    await refresh();
  } catch (error) {
    simulationFeedback(`仿真控制失败：${redactJevMessage(error.message)}`, 'error');
  } finally {
    simulationCommandBusy = false;
    document.querySelectorAll('#panel-simulation .simulation-controls .button').forEach((button) => { button.disabled = false; });
  }
}

function renderSimulation(simulation) {
  const data = simulation || {};
  const phase = String(data.phase || 'SIMULATOR_OFFLINE');
  const state = String(data.safety_state || 'STARTING');
  const connected = phase !== 'SIMULATOR_OFFLINE';
  const connection = $('simulation-connection');
  if (connection) {
    connection.textContent = connected ? '仿真节点在线' : '等待仿真节点';
    connection.className = `pill ${connected ? 'simulation-online' : 'simulation-offline'}`;
  }
  const values = {
    'simulation-phase': phase,
    'simulation-safety-state': state,
    'simulation-pose': `${finiteNumber(data.x).toFixed(2)} m / ${finiteNumber(data.y).toFixed(2)} m`,
    'simulation-requested-speed': `${finiteNumber(data.requested_speed).toFixed(2)} m/s`,
    'simulation-actual-speed': `${finiteNumber(data.actual_speed).toFixed(2)} m/s`,
    'simulation-speed-limit': `${finiteNumber(data.speed_limit).toFixed(2)} m/s`,
    'simulation-pallet': `${data.pallet_loaded === true ? '已装载' : '未装载'} · ${finiteNumber(data.grip_force).toFixed(1)} N`,
    'simulation-attack-mode': data.attack_mode ? String(data.attack_mode) : '无',
    'simulation-mitigation': data.mitigation_action ? String(data.mitigation_action) : 'NONE',
  };
  Object.entries(values).forEach(([id, value]) => { const target = $(id); if (target) target.textContent = value; });
  const stateTarget = $('simulation-safety-state');
  if (stateTarget) stateTarget.className = stateClass(state);
}

function setWorkspacePanel(panel) {
  const allowed = new Set(['realtime', 'protection', 'simulation', 'code-security', 'dataset-security', 'sandbox', 'jev', 'research']);
  const selected = allowed.has(panel) ? panel : 'protection';
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
  setWorkspacePanel(window.location.hash.slice(1) || 'protection');
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
    $('research-feedback').textContent = `测试套件完成：${passed}/${payload.cases.length} 个 Jev 调度案例通过；未调用真实 API，未产生执行器动作。`;
    $('research-feedback').className = 'muted success';
  } catch (error) {
    $('research-feedback').textContent = `测试套件失败：${redactJevMessage(error.message)}`;
    $('research-feedback').className = 'muted error';
  } finally {
    button.disabled = false;
  }
}

function setupResearch() {
  $('research-run').addEventListener('click', runResearchSuite);
}

function setupSimulation() {
  if (!$('simulation-start')) return;
  $('simulation-start').addEventListener('click', () => sendSimulationControl('start'));
  $('simulation-stop').addEventListener('click', () => sendSimulationControl('stop'));
  $('simulation-reset').addEventListener('click', () => sendSimulationControl('reset'));
  $('simulation-attack-speed').addEventListener('click', () => sendSimulationControl('attack', 'speed_abuse'));
  $('simulation-attack-replay').addEventListener('click', () => sendSimulationControl('attack', 'replay'));
  $('simulation-attack-gripper').addEventListener('click', () => sendSimulationControl('attack', 'gripper_fault'));
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
  renderSimulation(data.simulation);
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
setupCodeSecurity();
setupSandbox();
setupDatasetSecurity();
setupSimulation();
setupWorkspace();
setupResearch();
setupAuth();
setInterval(refresh, 1000);
