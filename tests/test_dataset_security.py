import json
import io
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState
from guardian_core.dataset_security import catalog_dataset, scan_dataset


def _write_fixture(root: Path) -> None:
    (root / "code").mkdir()
    (root / "data").mkdir()
    (root / "code" / "unsafe_controller.py").write_text(
        """
import rclpy
from geometry_msgs.msg import Twist
from rclpy.node import Node

class UnsafeController(Node):
    def __init__(self):
        super().__init__("unsafe_controller")
        self.pub = self.create_publisher(Twist, "/cmd_vel", 10)

    def tick(self):
        eval("publish_untrusted_command()")
        self.pub.publish(Twist())

def main():
    rclpy.init()
    node = UnsafeController()
    rclpy.spin(node)
    rclpy.shutdown()
""".strip(),
        encoding="utf-8",
    )
    (root / "data" / "episode.hdf5").write_bytes(b"\x89HDF\r\n\x1a\nfixture")
    (root / "data" / "episode.parquet").write_bytes(b"PAR1fixturePAR1")
    (root / "data" / "camera.mp4").write_bytes(b"\x00\x00\x00\x18ftypisom")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "purpose": "test",
                "files": [],
                "verification": {"simulation_or_training_tested": False},
            }
        ),
        encoding="utf-8",
    )


def test_catalog_classifies_code_and_robotics_data(tmp_path):
    _write_fixture(tmp_path)

    report = catalog_dataset(tmp_path)

    assert report["schema"] == "guardian-dataset-security/v1"
    assert report["files_total"] == 5
    assert report["classes"]["code"] == 1
    assert report["classes"]["data"] == 3
    assert report["manifest"]["present"] is True


def test_scan_dataset_reports_static_risk_and_format_evidence(tmp_path):
    _write_fixture(tmp_path)

    report = scan_dataset(tmp_path)

    assert report["summary"]["critical"] >= 1
    assert report["summary"]["verdict"] == "BLOCKED"
    assert report["source_scan"]["scanned_files"] == 1
    assert report["format_checks"]["valid"] == 3
    assert report["runtime"]["executed_files"] == 0
    assert any(item["rule_id"] == "DYN-001" for item in report["findings"])


def test_documentation_and_metadata_are_not_treated_as_executable_risk(tmp_path):
    _write_fixture(tmp_path)
    (tmp_path / "README.md").write_text(
        "See https://example.com and the /cmd_vel documentation. password = demo",
        encoding="utf-8",
    )
    (tmp_path / "metadata.json").write_text(
        json.dumps({"source": "https://example.com", "topic": "/cmd_vel", "token": "metadata"}),
        encoding="utf-8",
    )
    (tmp_path / "robot.sdf").write_text(
        '<sdf version="1.9"><plugin filename="controller.so">/cmd_vel</plugin></sdf>',
        encoding="utf-8",
    )

    report = scan_dataset(tmp_path)
    finding_paths = {item["path"] for item in report["findings"]}

    assert "README.md" not in finding_paths
    assert "metadata.json" not in finding_paths
    assert "robot.sdf" in finding_paths


def test_python_312_syntax_is_classified_as_compatibility_review(tmp_path):
    (tmp_path / "controller.py").write_text(
        """
type FeatureDict = dict[str, float]

def build[T](value: T) -> T:
    return value
""".strip(),
        encoding="utf-8",
    )

    report = scan_dataset(tmp_path)
    parse_findings = [item for item in report["findings"] if item["rule_id"] == "PARSE-001"]

    assert len(parse_findings) == 1
    assert parse_findings[0]["severity"] == "medium"
    assert parse_findings[0]["confidence"] == "version_compatibility"
    assert parse_findings[0]["guardian_action"] == "REVIEW_REQUIRED"
    assert report["summary"]["critical"] == 0
    assert report["source_scan"]["python_version_compatibility"] == 1
    assert report["source_scan"]["python_syntax_errors"] == 0


def test_yaml_step_name_is_not_treated_as_a_dynamic_command(tmp_path):
    (tmp_path / "workflow.yml").write_text(
        """
name: Run smoke eval (1 episode)
jobs:
  check:
    steps:
      - name: Run smoke eval (1 episode)
        run: python3 -c "eval(untrusted_input)"
""".strip(),
        encoding="utf-8",
    )

    report = scan_dataset(tmp_path)
    findings = [item for item in report["findings"] if item["rule_id"] == "DYN-002"]

    assert len(findings) == 1
    assert findings[0]["line"] == 6


def _request_json(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None):
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, dict(response.headers), json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", errors="replace")}
        return error.code, dict(error.headers), payload


def _multipart(files: list[tuple[str, bytes, str | None]]) -> tuple[bytes, str]:
    boundary = "----guardian-dataset-test"
    chunks: list[bytes] = []
    for filename, content, content_type in files:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    'Content-Disposition: form-data; name="files"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type or 'application/octet-stream'}\r\n\r\n".encode(),
                content,
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def test_dataset_security_http_api_accepts_uploaded_batches_only(tmp_path):
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        Path(__file__).resolve().parents[1] / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend",
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        status, _, payload = _request_json(f"{base}/api/dataset-security/catalog")
        assert status == 404

        status, headers, _ = _request_json(
            f"{base}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        body, content_type = _multipart(
            [
                (
                    "controllers/unsafe_controller.py",
                    b"import subprocess\nsubprocess.run(['echo', 'unsafe'])\n",
                    "text/x-python",
                ),
                ("README.md", b"uploaded batch one", "text/markdown"),
            ]
        )
        status, _, payload = _request_json(
            f"{base}/api/dataset-security/scan",
            data=body,
            headers={"Cookie": cookie, "Content-Type": content_type},
        )
        assert status == 200, payload
        assert payload["status"] == "OK"
        assert payload["report"]["dataset"]["files_total"] == 2
        assert payload["report"]["runtime"]["executed_files"] == 0
        assert any(item["path"] == "controllers/unsafe_controller.py" for item in payload["report"]["findings"])
        assert str(tmp_path) not in json.dumps(payload, ensure_ascii=False)

        second_body, second_content_type = _multipart(
            [("safe_controller.py", b"def control(state):\n    return state\n", "text/x-python")]
        )
        status, _, payload = _request_json(
            f"{base}/api/dataset-security/scan",
            data=second_body,
            headers={"Cookie": cookie, "Content-Type": second_content_type},
        )
        assert status == 200
        assert payload["status"] == "OK"
        assert payload["report"]["dataset"]["files_total"] == 1
        assert all(item["path"] != "controllers/unsafe_controller.py" for item in payload["report"]["findings"])
        assert payload["report"]["runtime"]["executed_files"] == 0
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def test_dataset_security_upload_expands_a_safe_zip_without_executing_it(tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("controllers/unsafe_controller.py", "import os\nos.system('echo unsafe')\n")
        bundle.writestr("models/robot.sdf", '<sdf version="1.9"></sdf>')
    body, content_type = _multipart([("warehouse_case.zip", archive.getvalue(), "application/zip")])

    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        Path(__file__).resolve().parents[1] / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend",
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        _, headers, _ = _request_json(
            f"{base}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, payload = _request_json(
            f"{base}/api/dataset-security/scan",
            data=body,
            headers={"Cookie": cookie, "Content-Type": content_type},
        )
        assert status == 200
        assert payload["report"]["dataset"]["files_total"] == 2
        assert any(item["path"] == "controllers/unsafe_controller.py" for item in payload["report"]["findings"])
        assert payload["report"]["runtime"]["executed_files"] == 0
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def test_dataset_security_upload_rejects_empty_and_traversal_batches(tmp_path):
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        Path(__file__).resolve().parents[1] / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend",
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        _, headers, _ = _request_json(
            f"{base}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        empty_body, empty_content_type = _multipart([])
        status, _, payload = _request_json(
            f"{base}/api/dataset-security/scan",
            data=empty_body,
            headers={"Cookie": cookie, "Content-Type": empty_content_type},
        )
        assert status == 400
        assert payload["error"]["code"] == "empty_upload"

        traversal_body, traversal_content_type = _multipart(
            [("../escape.py", b"print('no')", "text/x-python")]
        )
        status, _, payload = _request_json(
            f"{base}/api/dataset-security/scan",
            data=traversal_body,
            headers={"Cookie": cookie, "Content-Type": traversal_content_type},
        )
        assert status == 400
        assert payload["error"]["code"] == "unsafe_filename"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
