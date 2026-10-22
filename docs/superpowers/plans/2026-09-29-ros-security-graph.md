# ROS Security Graph v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded, read-only ROS Security Graph v1 that turns multiple ROS 2 source/config files into traceable security paths and a Dashboard visualization without entering the Guardian runtime safety loop.

**Architecture:** A new pure-Python `ros_graph_security.py` module validates a bounded file batch, reuses the existing single-file AST inspector for Python findings, builds deterministic nodes/edges/path records, and maps findings to Guardian actions. Dashboard exposes authenticated sample and inspect endpoints. The existing frontend adds a native SVG graph workspace; no Graphify runtime dependency, CDN, code execution, or external semantic model is added.

**Tech Stack:** Python standard library (`ast`, `xml.etree`, `json`), existing `pytest`, ROS 2 Dashboard HTTP server, vanilla HTML/CSS/JavaScript/SVG.

**Spec:** `docs/superpowers/specs/2026-09-29-ros-security-graph-design.md`

## Global Constraints

- Output schema is exactly `ros-security-graph/v1`.
- Analysis treats source as data and never imports, executes, launches, or publishes submitted code.
- Request limits are 128 files, 64 KiB per file, and 512 KiB total UTF-8 source bytes.
- Absolute paths, path traversal, NUL characters, duplicate filenames, and malformed payloads are rejected.
- Unsupported non-Python control files remain visible and produce `UNSUPPORTED`/`GRAPH-PARSE-001` evidence; they cannot produce `PASS`.
- Graph analysis is offline and advisory; it cannot mutate `SafetyStatus`, `MitigationCommand`, `SAFE_STOP`, speed limits, or recovery state.
- Findings use only `NONE`, `REVIEW_REQUIRED`, `ISOLATE_COMPONENT`, and `SAFE_STOP`.
- No new runtime dependency or external CDN is introduced.

---

### Task 1: Build the bounded graph analyzer

**Files:**
- Create: `ros2_ws/src/guardian_core/guardian_core/ros_graph_security.py`
- Create: `tests/test_ros_graph_security.py`
- Test: `tests/test_ros_graph_security.py`

**Interfaces:**
- Consumes: `files: list[dict[str, str]]`, optional `profile: str`.
- Produces: `inspect_project(files, profile="ros2_generic") -> dict[str, object]`.
- Produces: `sample_catalog() -> list[dict[str, object]]`.
- Raises: `GraphSecurityError` for invalid input or bounds violations.

- [ ] **Step 1: Write failing core tests**

Add tests with hand-derived expectations for:

```python
def test_safe_python_controller_builds_publisher_and_guard_edges():
    report = inspect_project([{
        "filename": "controller.py",
        "source": SAFE_CONTROLLER,
    }])
    assert report["schema"] == "ros-security-graph/v1"
    assert "topic:/cmd_vel" in {item["id"] for item in report["nodes"]}
    assert any(edge["kind"] == "publishes" for edge in report["edges"])
    assert report["summary"]["verdict"] != "BLOCKED"


def test_unsafe_control_path_reports_dynamic_execution_and_unbounded_velocity():
    report = inspect_project([{
        "filename": "unsafe.py",
        "source": UNSAFE_CONTROLLER,
    }])
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "GRAPH-DYN-001" in rule_ids
    assert "GRAPH-ACT-002" in rule_ids
    assert report["summary"]["verdict"] == "BLOCKED"
    assert report["paths"]


def test_unsupported_cpp_is_visible_and_not_passed():
    report = inspect_project([{
        "filename": "controller.cpp",
        "source": "publisher_->publish(command);",
    }])
    assert report["unsupported_files"] == ["controller.cpp"]
    assert report["summary"]["verdict"] == "BLOCKED"


@pytest.mark.parametrize("files", [
    [{"filename": "../unsafe.py", "source": "x = 1"}],
    [{"filename": "/tmp/unsafe.py", "source": "x = 1"}],
    [{"filename": "unsafe.py\x00", "source": "x = 1"}],
])
def test_graph_input_rejects_unsafe_paths(files):
    with pytest.raises(GraphSecurityError):
        inspect_project(files)
```

- [ ] **Step 2: Run the focused tests and verify the expected RED state**

Run:

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
python3 -m pytest -q tests/test_ros_graph_security.py
```

Expected: collection or assertion failures because the new module and API do not exist.

- [ ] **Step 3: Implement input validation and deterministic graph primitives**

Implement:

```python
GRAPH_SCHEMA = "ros-security-graph/v1"
MAX_FILES = 128
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_PATHS = 64

class GraphSecurityError(ValueError):
    pass

def inspect_project(files, *, profile="ros2_generic"):
    ...
```

Validate exact payload keys, relative single-root paths, UTF-8 source strings,
file uniqueness, byte limits, and profile names. Sort files, nodes, edges and
findings before returning them so repeated analysis produces identical JSON.

- [ ] **Step 4: Implement Python extraction using the existing inspector**

For `.py`, `.pyi`, and `.launch.py` files:

1. Parse with `ast` without importing or executing.
2. Create file/module/class/function nodes.
3. Detect `create_publisher`, `create_subscription`, service/action creation,
   explicit control topics, and `rclpy.init/spin/shutdown`.
4. Call the existing `inspect_source()` as a bounded local rule engine.
5. Map existing findings to `GRAPH-*` rule IDs while retaining file and line
   evidence.
6. Create `publishes`, `subscribes`, `calls`, and `protected_by` edges.

Do not pass a multi-file batch to the existing single-file HTTP path; call the
pure function directly.

- [ ] **Step 5: Implement YAML/XML and unsupported-file handling**

For YAML/XML/package files, create file nodes and scan only bounded literal
resource references such as `/cmd_vel`, `/joint_trajectory`,
`/gripper/command`, `profile_id`, `adapter_id`, `mitigatable`, and permission
markers. Mark incomplete language understanding as `INFERRED` or
`UNSUPPORTED`; never infer that a file is safe.

- [ ] **Step 6: Implement findings and bounded dangerous paths**

Build a control-path adjacency graph from publisher/topic/controller/actuator
nodes. Use bounded BFS from suspicious source/function nodes to high-criticality
topics. Return at most 64 paths, each with node IDs, edge IDs, confidence,
provenance, and the finding that caused it.

Implement the eight rules in the spec, including deterministic severity/action
aggregation:

```text
SAFE_STOP > ISOLATE_COMPONENT > REVIEW_REQUIRED > NONE
```

- [ ] **Step 7: Run focused tests and refactor only after green**

Run the focused test file again. Confirm all graph fields are JSON serializable,
findings contain evidence locations, and no source text is executed.

### Task 2: Add authenticated Dashboard graph APIs

**Files:**
- Modify: `ros2_ws/src/guardian_core/guardian_core/dashboard.py`
- Create: `tests/test_dashboard_ros_graph.py`

**Interfaces:**
- `GET /api/ros-graph/samples` returns `{"schema": ..., "samples": [...]}`.
- `POST /api/ros-graph/inspect` accepts only `files` and optional `profile`.
- Both routes require an authenticated session.

- [ ] **Step 1: Write failing HTTP contract tests**

Cover:

```python
def test_ros_graph_samples_require_login_and_return_bounded_catalog(server):
    ...

def test_ros_graph_inspect_returns_graph_without_executing_source(server):
    ...

def test_ros_graph_inspect_rejects_extra_fields_and_oversized_batches(server):
    ...
```

Assert unauthenticated `401`, authenticated `200`, schema, nodes, edges,
findings, `execution == "not_executed"`, and no process/import side effects.

- [ ] **Step 2: Run the focused HTTP tests and verify RED**

Run:

```bash
python3 -m pytest -q tests/test_dashboard_ros_graph.py
```

Expected: route/API failures because the endpoints are not registered.

- [ ] **Step 3: Add route dispatch and bounded request handling**

Import the graph analyzer, add constants for the 512 KiB request budget, and
register:

```text
GET  /api/ros-graph/samples
POST /api/ros-graph/inspect
```

Read the request body once, reject invalid content length and oversized JSON
before parsing, enforce exact payload keys, and map `GraphSecurityError` to a
bounded `400` response. Never include raw source in error responses.

- [ ] **Step 4: Run the focused HTTP tests and verify GREEN**

Run the same test file and then the existing Dashboard security contract tests.

### Task 3: Add the ROS Security Graph Dashboard workspace

**Files:**
- Modify: `ros2_ws/src/guardian_core/guardian_core/frontend/index.html`
- Modify: `ros2_ws/src/guardian_core/guardian_core/frontend/app.js`
- Modify: `ros2_ws/src/guardian_core/guardian_core/frontend/styles.css`
- Modify: `tests/test_frontend_workspace.py`

**Interfaces:**
- New workspace route: `ros-graph`.
- New API constants: `/api/ros-graph/samples`, `/api/ros-graph/inspect`.
- New DOM contract includes graph SVG, summary, path list, and finding details.

- [ ] **Step 1: Write failing frontend contract tests**

Assert the new workspace exposes:

```text
data-panel="ros-graph"
id="panel-ros-graph"
id="ros-graph-svg"
id="ros-graph-findings"
id="ros-graph-paths"
/api/ros-graph/inspect
EXTRACTED
INFERRED
UNSUPPORTED
```

Update the existing ordered workspace list without changing the default first
workspace.

- [ ] **Step 2: Run frontend tests and verify RED**

Run:

```bash
python3 -m pytest -q tests/test_frontend_workspace.py
```

Expected: assertions fail because the workspace and graph controls do not
exist.

- [ ] **Step 3: Add the workspace markup**

Add a compact analysis workspace with:

- native multiple-file input and built-in sample selector;
- inspect button and status text;
- summary metrics for files, nodes, edges, findings and verdict;
- an SVG graph viewport with accessible fallback list;
- finding and dangerous-path details;
- a visible static-analysis boundary statement.

- [ ] **Step 4: Implement bounded frontend graph rendering**

Add:

```javascript
async function loadRosGraphSamples() { ... }
async function inspectRosGraph() { ... }
function renderRosGraph(report) { ... }
function renderRosGraphSvg(report) { ... }
```

Use `esc()` for all source-derived text. Position nodes deterministically by
kind/column and draw only the bounded result. Color by node kind and risk, and
render `UNSUPPORTED` files as review-required nodes. Do not use `innerHTML`
with unescaped report fields.

- [ ] **Step 5: Add responsive, restrained graph styles**

Use stable SVG dimensions, horizontal scrolling for dense graphs, accessible
focus states, and no gradients or decorative background shapes. Keep the graph
as a framed analysis tool, not a marketing hero.

- [ ] **Step 6: Run frontend tests and syntax checks**

Run:

```bash
python3 -m pytest -q tests/test_frontend_workspace.py
node --check ros2_ws/src/guardian_core/guardian_core/frontend/app.js
```

### Task 4: Document the workflow and preserve safety boundaries

**Files:**
- Create: `docs/ros_security_graph.md`
- Modify: `README.md`
- Modify: `PROJECT_GUIDE.md`
- Modify: `HANDOFF.md`

- [ ] **Step 1: Document inputs, schema, rules, and limits**

Explain the static graph workflow, supported file types, rule IDs, path
provenance, limits, and the distinction between static evidence and runtime
Guardian decisions.

- [ ] **Step 2: Add operator usage**

Document built-in sample flow and the authenticated Dashboard route without
exposing raw URLs or credentials as production defaults.

- [ ] **Step 3: Record the implementation and verification**

Add a dated `HANDOFF.md` entry with the final test/build results and explicit
production limitations.

### Task 5: Full verification

**Files:**
- No additional source files.

- [ ] **Step 1: Run the graph-focused and Dashboard tests**

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
python3 -m pytest -q tests/test_ros_graph_security.py tests/test_dashboard_ros_graph.py tests/test_frontend_workspace.py
```

- [ ] **Step 2: Run the complete project test suite**

```bash
python3 -m pytest -q tests
```

Expected: all existing tests plus the new graph tests pass.

- [ ] **Step 3: Run build and static checks**

```bash
bash deploy/run_guardian.sh build --distro humble
python -m compileall -q ros2_ws/src/guardian_core/guardian_core tests
node --check ros2_ws/src/guardian_core/guardian_core/frontend/app.js
git diff --check
```

- [ ] **Step 4: Inspect the final diff**

Confirm no external Graphify dependency, no source execution, no network call,
no secrets, no generated debug files, and no changes to the Guardian real-time
decision contract.
