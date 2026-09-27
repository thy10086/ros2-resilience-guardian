"""Read-only security audit for mixed robotics code and data corpora.

The auditor treats downloaded projects, model files, datasets and media as
untrusted input. It never imports, executes, trains, renders or launches them.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

from .dashboard_code_security import CodeSecurityError, inspect_source


DATASET_SECURITY_SCHEMA = "guardian-dataset-security/v1"
MAX_SOURCE_BYTES = 64 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_FINDINGS = 500

SKIP_DIRECTORIES = frozenset({".git", "__pycache__", ".pytest_cache", "node_modules", "build", "dist"})
CODE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs",
    ".js", ".mjs", ".ts", ".sh", ".bash", ".cmake", ".mm",
})
ROBOT_CONFIG_EXTENSIONS = frozenset({
    ".xml", ".xsd", ".yaml", ".yml", ".urdf", ".sdf", ".world", ".mjcf", ".mjz",
})
SCAN_EXTENSIONS = CODE_EXTENSIONS | ROBOT_CONFIG_EXTENSIONS
METADATA_EXTENSIONS = frozenset({
    ".json", ".toml", ".ini", ".cfg", ".txt", ".md", ".rst",
})
DATA_EXTENSIONS = frozenset({
    ".h5", ".hdf5", ".parquet", ".mp4", ".avi", ".mov", ".bag", ".safetensors",
    ".npy", ".npz", ".mat", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".obj",
    ".stl", ".msh", ".gz", ".zip", ".tar",
})
ARCHIVE_EXTENSIONS = frozenset({".gz", ".zip", ".tar", ".tgz", ".bz2", ".xz"})

_TEXT_RULES = (
    (
        "DYN-002",
        "high",
        re.compile(r"\b(?:eval|exec|system|popen)\s*\(|\bsubprocess(?:\.|\s)", re.IGNORECASE),
        "可能启动外部命令或执行动态输入",
        "将外部命令移出机器人控制路径，并使用固定参数的受限服务。",
        "ISOLATE_COMPONENT",
    ),
    (
        "SER-001",
        "high",
        re.compile(r"\b(?:pickle\.load|torch\.load|yaml\.load)\s*\(", re.IGNORECASE),
        "可能加载不可信序列化对象",
        "只使用安全数据格式和显式 schema，禁止从不可信来源直接反序列化对象。",
        "SAFE_STOP",
    ),
    (
        "SEC-001",
        "high",
        re.compile(r"\b(?:api[_-]?key|password|passwd|token|secret|credential)\s*=", re.IGNORECASE),
        "疑似硬编码凭据或访问令牌",
        "改用外部凭据存储，禁止把密钥写入控制代码和数据集。",
        "ISOLATE_COMPONENT",
    ),
    (
        "NET-001",
        "medium",
        re.compile(r"\b(?:requests|urllib|httpx|socket)\b|https?://", re.IGNORECASE),
        "源码存在网络访问路径",
        "为网络访问设置固定目的地、超时、认证和离线失败策略。",
        "REVIEW_REQUIRED",
    ),
    (
        "ACT-001",
        "medium",
        re.compile(r"/cmd_vel|joint[_/]trajectory|gripper/command", re.IGNORECASE),
        "源码涉及机器人执行器控制主题",
        "确认每条执行器发布路径都经过速度限幅、急停和 Guardian 安全许可。",
        "REVIEW_REQUIRED",
    ),
)

_PYTHON_312_SYNTAX_PATTERNS = (
    re.compile(r"(?m)^\s*type\s+[A-Za-z_]\w*(?:\s*\[[^\n=]+\])?\s*="),
    re.compile(r"(?m)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\[[^\n\]]+\]"),
    re.compile(r"(?m)^\s*class\s+[A-Za-z_]\w*\s*\[[^\n\]]+\]"),
)


class DatasetSecurityError(ValueError):
    """Raised when a dataset root or manifest cannot be safely inspected."""


def _root(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.exists() or not path.is_dir():
        raise DatasetSecurityError("数据集目录不存在或不是目录")
    resolved = path.resolve()
    if resolved.is_symlink():
        raise DatasetSecurityError("数据集根目录不能是符号链接")
    return resolved


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRECTORIES for part in relative_parts):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix().lower())


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _extension(path: Path) -> str:
    return path.suffix.lower()


def _file_class(path: Path) -> str:
    extension = _extension(path)
    if extension in CODE_EXTENSIONS:
        return "code"
    if extension in DATA_EXTENSIONS:
        return "data"
    if extension in {".json", ".yaml", ".yml", ".toml", ".md", ".txt", ".rst"}:
        return "metadata"
    return "other"


def _load_manifest(root: Path) -> tuple[dict[str, object] | None, str | None]:
    path = root / "manifest.json"
    if not path.is_file():
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"manifest.json 无法解析：{type(error).__name__}"
    return value if isinstance(value, dict) else None, None


def catalog_dataset(dataset_root: str | Path, *, display_name: str | None = None) -> dict[str, object]:
    """Inventory a dataset without opening executable or binary payloads."""

    root = _root(dataset_root)
    files = _iter_files(root)
    extensions: dict[str, int] = {}
    classes = {"code": 0, "data": 0, "metadata": 0, "other": 0}
    total_bytes = 0
    for path in files:
        extension = _extension(path) or "<none>"
        extensions[extension] = extensions.get(extension, 0) + 1
        classes[_file_class(path)] += 1
        total_bytes += path.stat().st_size

    manifest, manifest_error = _load_manifest(root)
    verification = manifest.get("verification", {}) if isinstance(manifest, dict) else {}
    return {
        "schema": DATASET_SECURITY_SCHEMA,
        "root_name": display_name or root.name,
        "files_total": len(files),
        "bytes_total": total_bytes,
        "extensions": dict(sorted(extensions.items())),
        "classes": classes,
        "manifest": {
            "present": manifest is not None,
            "error": manifest_error,
            "purpose": manifest.get("purpose") if isinstance(manifest, dict) else None,
            "declared_files": len(manifest.get("files", [])) if isinstance(manifest, dict) and isinstance(manifest.get("files"), list) else 0,
            "verification": verification if isinstance(verification, dict) else {},
        },
        "source_roots": sorted({
            relative.split("/", 1)[0]
            for relative in (_relative(root, path) for path in files)
            if "/" in relative
        }),
    }


def _line_number(source: str, match: re.Match[str]) -> int:
    return source.count("\n", 0, match.start()) + 1


def _text_findings(path: Path, source: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    lines = source.splitlines()
    for rule_id, severity, pattern, title, recommendation, action in _TEXT_RULES:
        for match in pattern.finditer(source):
            line = _line_number(source, match)
            evidence = lines[line - 1].strip()[:240] if line <= len(lines) else ""
            if not _text_finding_allowed(path, rule_id, evidence):
                continue
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "line": line,
                "evidence": evidence,
                "recommendation": recommendation,
                "guardian_action": action,
                "path": path.as_posix(),
                "confidence": "pattern_only",
            })
    return findings


def _looks_like_python_312_syntax(source: str) -> bool:
    return any(pattern.search(source) for pattern in _PYTHON_312_SYNTAX_PATTERNS)


def _text_finding_allowed(path: Path, rule_id: str, evidence: str) -> bool:
    if (
        rule_id == "DYN-002"
        and path.suffix.lower() in {".yaml", ".yml"}
        and re.match(r"^\s*(?:-\s*)?name\s*:", evidence, re.IGNORECASE)
    ):
        return False
    return True


def _classify_dataset_python_findings(
    findings: list[dict[str, object]],
    source: str,
) -> tuple[list[dict[str, object]], bool]:
    if not any(item.get("rule_id") == "PARSE-001" for item in findings):
        return findings, False
    if not _looks_like_python_312_syntax(source):
        return findings, False

    classified: list[dict[str, object]] = []
    for finding in findings:
        item = dict(finding)
        if item.get("rule_id") == "PARSE-001":
            item.update({
                "severity": "medium",
                "title": "Python 版本兼容性待复核",
                "recommendation": "当前 ROS 2 Humble Python 3.10 无法解析该 Python 3.12+ 语法；请固定运行时版本或改写为兼容语法后再进行工业部署检查。",
                "guardian_action": "REVIEW_REQUIRED",
                "confidence": "version_compatibility",
                "classification": "python_3_12_plus",
            })
        classified.append(item)
    return classified, True


def _format_check(path: Path) -> dict[str, object] | None:
    extension = _extension(path)
    try:
        with path.open("rb") as stream:
            head = stream.read(16)
            if extension in {".h5", ".hdf5"}:
                valid = head.startswith(b"\x89HDF\r\n\x1a\n")
                return {"path": path.as_posix(), "format": "HDF5", "valid": valid, "semantic_checked": False}
            if extension == ".parquet":
                stream.seek(-4, 2)
                tail = stream.read(4)
                valid = head[:4] == b"PAR1" and tail == b"PAR1"
                return {"path": path.as_posix(), "format": "Parquet", "valid": valid, "semantic_checked": False}
            if extension in {".mp4", ".mov", ".avi"}:
                valid = head[4:8] == b"ftyp" if extension in {".mp4", ".mov"} else head.startswith(b"RIFF")
                return {"path": path.as_posix(), "format": "video", "valid": valid, "semantic_checked": False}
    except OSError as error:
        return {"path": path.as_posix(), "format": extension.lstrip(".") or "unknown", "valid": False, "error": type(error).__name__}
    return None


def _hash_manifest_files(root: Path, manifest: dict[str, object] | None) -> dict[str, object]:
    declared = manifest.get("files", []) if isinstance(manifest, dict) else []
    checked = 0
    matched = 0
    missing: list[str] = []
    mismatched: list[str] = []
    if not isinstance(declared, list):
        declared = []
    for item in declared:
        if not isinstance(item, dict):
            continue
        relative = item.get("path")
        expected = item.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            continue
        target = (root / relative).resolve()
        if root != target and root not in target.parents:
            mismatched.append(relative)
            continue
        if not target.is_file():
            missing.append(relative)
            continue
        checked += 1
        digest = hashlib.sha256()
        try:
            with target.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            mismatched.append(relative)
            continue
        if digest.hexdigest().lower() == expected.lower():
            matched += 1
        else:
            mismatched.append(relative)
    return {
        "declared": len(declared),
        "checked": checked,
        "matched": matched,
        "missing": missing,
        "mismatched": mismatched,
        "all_checked_match": not missing and not mismatched and checked == len(declared),
    }


def _dedupe_findings(findings: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, ...]] = set()
    result: list[dict[str, object]] = []
    for finding in findings:
        key = (
            finding.get("path"),
            finding.get("rule_id"),
            finding.get("line"),
            finding.get("evidence"),
        )
        if key not in seen:
            result.append(finding)
            seen.add(key)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(result, key=lambda item: (
        severity_order.get(str(item.get("severity")), 9),
        str(item.get("path")),
        int(item.get("line", 0)),
    ))


def scan_dataset(
    dataset_root: str | Path,
    *,
    max_findings: int = MAX_FINDINGS,
    display_name: str | None = None,
) -> dict[str, object]:
    """Run bounded static and format checks over a mixed robotics corpus."""

    root = _root(dataset_root)
    files = _iter_files(root)
    manifest, manifest_error = _load_manifest(root)
    findings: list[dict[str, object]] = []
    source_candidates = [path for path in files if _extension(path) in CODE_EXTENSIONS]
    python_candidates = [path for path in source_candidates if _extension(path) == ".py"]
    source_scanned = 0
    source_skipped = 0
    source_parse_errors = 0
    source_version_compatibility = 0
    source_syntax_errors = 0
    python_scanned = 0
    format_checks: list[dict[str, object]] = []
    binary_candidates = 0

    for path in files:
        extension = _extension(path)
        size = path.stat().st_size
        relative = _relative(root, path)
        if extension in DATA_EXTENSIONS:
            binary_candidates += 1
            check = _format_check(path)
            if check is not None:
                check["path"] = relative
                format_checks.append(check)
                if check.get("valid") is not True:
                    findings.append({
                        "rule_id": "FMT-001",
                        "severity": "high",
                        "title": f"{check.get('format', '二进制')} 文件头校验失败",
                        "line": 1,
                        "evidence": relative,
                        "recommendation": "隔离损坏或类型伪装文件，确认来源和内容后再进入解析器。",
                        "guardian_action": "ISOLATE_COMPONENT",
                        "path": relative,
                        "confidence": "format_header",
                    })
        if extension not in SCAN_EXTENSIONS:
            continue
        if size > MAX_SOURCE_BYTES if extension == ".py" else size > MAX_TEXT_BYTES:
            source_skipped += 1
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            source_skipped += 1
            continue
        if extension in CODE_EXTENSIONS:
            source_scanned += 1
        if extension == ".py":
            python_scanned += 1
            try:
                report = inspect_source(source, filename=path.name)
            except CodeSecurityError:
                source_skipped += 1
                continue
            python_findings, version_compatibility = _classify_dataset_python_findings(
                [dict(item) for item in report.get("findings", []) if isinstance(item, dict)],
                source,
            )
            if version_compatibility:
                source_version_compatibility += 1
            elif any(item.get("rule_id") == "PARSE-001" for item in python_findings):
                source_syntax_errors += 1
            for finding in python_findings:
                item = dict(finding)
                item["path"] = relative
                item.setdefault("confidence", "ast_rule")
                findings.append(item)
            if any(item.get("rule_id") == "PARSE-001" for item in python_findings):
                source_parse_errors += 1
        else:
            findings.extend(_text_findings(Path(relative), source))

    hashes = _hash_manifest_files(root, manifest)
    if manifest_error:
        findings.append({
            "rule_id": "META-001",
            "severity": "medium",
            "title": "manifest.json 无法解析",
            "line": 1,
            "evidence": manifest_error,
            "recommendation": "修复清单后重新校验来源、版本和哈希。",
            "guardian_action": "REVIEW_REQUIRED",
            "path": "manifest.json",
            "confidence": "manifest",
        })
    if hashes["mismatched"] or hashes["missing"]:
        findings.append({
            "rule_id": "META-002",
            "severity": "high",
            "title": "manifest 声明文件哈希或路径不一致",
            "line": 1,
            "evidence": f"missing={len(hashes['missing'])}, mismatched={len(hashes['mismatched'])}",
            "recommendation": "停止使用不一致的文件，重新获取固定版本并核对 SHA-256。",
            "guardian_action": "SAFE_STOP",
            "path": "manifest.json",
            "confidence": "sha256",
        })

    findings = _dedupe_findings(findings)
    summary = {
        level: sum(item.get("severity") == level for item in findings)
        for level in ("critical", "high", "medium", "low")
    }
    summary["total"] = len(findings)
    summary["verdict"] = (
        "BLOCKED"
        if summary["critical"]
        else "REVIEW"
        if summary["high"] or summary["medium"] or source_skipped or not hashes["all_checked_match"]
        else "PASS"
    )
    valid_formats = sum(item.get("valid") is True for item in format_checks)
    invalid_formats = len(format_checks) - valid_formats
    return {
        "schema": DATASET_SECURITY_SCHEMA,
        "dataset": catalog_dataset(root, display_name=display_name),
        "summary": summary,
        "findings": findings[:max(1, min(int(max_findings), MAX_FINDINGS))],
        "finding_count": len(findings),
        "source_scan": {
            "candidate_files": len(source_candidates),
            "scanned_files": source_scanned,
            "python_candidate_files": len(python_candidates),
            "python_scanned_files": python_scanned,
            "skipped_files": source_skipped,
            "python_parse_errors": source_parse_errors,
            "python_version_compatibility": source_version_compatibility,
            "python_syntax_errors": source_syntax_errors,
            "executed_files": 0,
        },
        "format_checks": {
            "candidate_files": binary_candidates,
            "checked": len(format_checks),
            "valid": valid_formats,
            "invalid": invalid_formats,
            "semantic_checked": False,
            "items": format_checks[:200],
        },
        "manifest_hashes": hashes,
        "runtime": {
            "executed_files": 0,
            "simulation_started": False,
            "training_started": False,
            "network_used": False,
        },
        "limitations": [
            "这是只读静态审计，不执行数据集源码、模型、脚本、训练或仿真。",
            "HDF5、Parquet、视频只完成文件头级别检查，未进行完整语义解码。",
            "源码规则结果是风险线索，不等于漏洞确认；需要在隔离仿真和人工复核中确认。",
        ],
    }


__all__ = ["DATASET_SECURITY_SCHEMA", "DatasetSecurityError", "catalog_dataset", "scan_dataset"]
