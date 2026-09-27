from pathlib import Path
import re


FRONTEND = (
    Path(__file__).resolve().parents[1]
    / "ros2_ws"
    / "src"
    / "guardian_core"
    / "guardian_core"
    / "frontend"
)


def test_protection_lab_is_the_default_first_workspace():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    nav_start = html.index('<nav class="workspace-nav"')
    nav_end = html.index("</nav>", nav_start)
    nav = html[nav_start:nav_end]
    tab_panels = [
        panel
        for panel in ("protection", "simulation", "jev", "realtime", "code-security", "dataset-security", "sandbox", "research")
        if f'data-panel="{panel}"' in nav
    ]

    assert tab_panels == ["protection", "simulation", "jev", "realtime", "code-security", "dataset-security", "sandbox", "research"]
    assert 'data-panel-section="protection"' in html
    assert 'id="panel-realtime"' in html
    assert "window.location.hash.slice(1) || 'protection'" in script
    assert "allowed.has(panel) ? panel : 'protection'" in script


def test_protection_report_exposes_complete_evidence_and_verdict_sections():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'class="protection-verdict"' in html
    assert 'id="protection-evidence"' in html
    assert 'class="protection-evidence-table"' in html
    assert 'id="protection-policy"' in html
    assert "report.steps" in script
    assert "step.event" in script
    assert "step.verification" in script
    assert "step.event.sequence" in script
    assert "step.event.confidence" in script


def test_protection_lab_prioritizes_recent_result_and_has_first_use_empty_state():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="protection-recent-result"' in html
    assert 'id="protection-recent-empty"' in html
    assert 'id="protection-open-recent"' in html
    assert "PROTECTION_RECENT_RESULT_KEY" in script
    assert "loadRecentProtectionResult" in script
    assert "saveRecentProtectionResult" in script
    assert "renderRecentProtectionResult" in script


def test_protection_import_supports_industrial_files_and_shows_parse_preview():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'accept=".json,.py,.xml,.sdf,.world,.urdf' in html
    assert 'id="protection-file-preview"' in html
    assert 'id="protection-preview-name"' in html
    assert 'id="protection-preview-type"' in html
    assert 'id="protection-preview-size"' in html
    assert 'id="protection-preview-parser"' in html
    assert 'id="protection-preview-entities"' in html
    assert 'id="protection-preview-source"' in html
    assert "parseProtectionFilePreview" in script
    assert "python" in script
    assert "sdf" in script
    assert "urdf" in script
    assert "xml" in script


def test_protection_details_are_collapsed_until_user_opens_technical_evidence():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert '<details id="protection-technical-details"' in html
    assert "查看技术详情" in html
    assert "protection-technical-details" in script
    assert "technicalDetails.open = true" in script
    assert "逐动作" in html


def test_frontend_uses_content_first_grayscale_workspace_visuals():
    css = (FRONTEND / "styles.css").read_text(encoding="utf-8")

    assert "--bg: #f7f7f5" in css
    assert "--text: #1f2328" in css
    assert "background: radial-gradient" not in css
    box_shadow_values = re.findall(r"box-shadow\s*:\s*([^;{}]+)", css)
    assert all(value.strip().startswith("none") for value in box_shadow_values)
    assert "background: linear-gradient" not in css
    assert ".button:focus-visible" in css
    assert ".workspace-tab:focus-visible" in css
    assert ".protection-status-critical" in css


def test_protection_json_import_uses_visible_native_input_and_file_feedback():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="protection-file" class="file-input-visible" type="file"' in html
    assert 'id="protection-file-name"' in html
    assert 'id="protection-file-trigger"' not in html
    assert "protection-file-trigger" not in script
    assert "addEventListener('change', loadProtectionFile)" in script
    assert "guardian-replay/v1" in script
    assert "protection-file-name" in script


def test_code_security_python_import_uses_visible_native_input_and_file_feedback():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="code-security-file" class="file-input-visible" type="file"' in html
    assert 'id="code-security-file-name"' in html
    assert 'id="code-security-file-trigger"' not in html
    assert "code-security-file-trigger" not in script
    assert "addEventListener('change', loadCodeSecurityFile)" in script
    assert "code-security-file-name" in script


def test_file_import_controls_are_visible_with_picker_feedback():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="protection-file" class="file-input-visible"' in html
    assert 'id="code-security-file" class="file-input-visible"' in html
    assert 'id="protection-file" class="file-input-visible" type="file"' in html
    assert 'id="code-security-file" class="file-input-visible" type="file"' in html
    assert 'id="protection-file-trigger"' not in html
    assert 'id="code-security-file-trigger"' not in html
    assert "正在等待选择 JSON/PY/XML/SDF/URDF 文件" in script
    assert "正在等待选择 Python 文件" in script
    assert "addEventListener('cancel'" in script


def test_code_security_results_lead_with_plain_language_decision():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="code-security-decision"' in html
    assert 'id="code-security-next-step"' in html
    assert 'id="code-security-technical-details"' in html
    assert "查看技术证据" in html
    assert "codeSecurityVerdictLabel" in script
    assert "codeSecurityNextStep" in script


def test_frontend_explains_static_assurance_and_replay_evidence_boundaries():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'id="code-security-assurance"' in html
    assert 'id="code-security-coverage"' in html
    assert 'id="code-security-missing-controls"' in html
    assert 'id="protection-assurance"' in html
    assert 'id="protection-assurance-limitations"' in html
    assert "report.assurance" in script
    assert "静态分析" in html
    assert "未启动 ROS 2/Gazebo" in script


def test_code_security_jev_metrics_explain_their_meaning():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")

    assert "风险倾向（0-100）" in html
    assert "判断把握（0-100）" in html
    assert "对机器人任务的影响" in html
    assert "是否需要人工确认" in html


def test_frontend_translates_local_only_jev_status_for_operators():
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert "LOCAL_ONLY" in script
    assert "本地校验结果，未调用 Jev" in script


def test_login_distinguishes_invalid_credentials_from_missing_dashboard_backend():
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert "response.status === 401" in script
    assert "response.status === 404 || response.status === 405 || response.status === 501" in script
    assert "登录服务未启动" in script
    assert "无法连接本地服务" in script


def test_realtime_risk_metrics_use_plain_language_labels():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")

    assert "安全余量（ψ）" in html
    assert "关键组件完整性（δ）" in html
    assert "风险阈值是否通过（γ）" in html


def test_sandbox_workspace_exposes_runtime_evidence_and_local_import():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert 'data-panel="sandbox"' in html
    assert 'id="panel-sandbox"' in html
    assert 'id="sandbox-file" class="file-input-visible"' in html
    assert 'id="sandbox-canvas"' in html
    assert 'id="sandbox-events"' in html
    assert 'id="sandbox-jev-result"' in html
    assert "SANDBOX_RUN_ENDPOINT" in script
    assert "loadSandboxFile" in script
    assert "renderSandboxCanvas" in script
    assert "source_sent_to_jev" not in script


def test_dataset_security_workspace_exposes_static_audit_evidence():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert 'data-panel="dataset-security"' in html
    assert 'id="panel-dataset-security"' in html
    assert 'id="dataset-security-files-input" class="file-input-visible"' in html
    assert 'id="dataset-security-folder-input" class="file-input-visible"' in html
    assert 'id="dataset-security-zip-input" class="file-input-visible"' in html
    assert 'webkitdirectory' in html
    assert 'id="dataset-security-upload-progress"' in html
    assert 'id="dataset-security-file-list"' in html
    assert 'id="dataset-security-run"' in html
    assert 'id="dataset-security-files"' in html
    assert 'id="dataset-security-findings"' in html
    assert 'id="dataset-security-executed"' in html
    assert 'id="dataset-security-hashes"' in html
    assert 'id="dataset-security-format-items"' in html
    assert 'id="dataset-security-manifest-detail"' in html
    assert "/api/dataset-security/scan" in script
    assert "FormData" in script
    assert "XMLHttpRequest" in script
    assert "upload.addEventListener('progress'" in script
    assert "dataset-security-files-input" in script
    assert "dataset-security-folder-input" in script
    assert "dataset-security-zip-input" in script
    assert "loadDatasetCatalog" not in script
    assert "dataset-security" in script


def test_dataset_security_distinguishes_dashboard_outage_from_upload_disconnect():
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert "datasetUploadTransportError" in script
    assert "本地 Dashboard 未运行" in script
    assert "上传连接已中断" in script
    assert "上传完成，正在扫描" in script
