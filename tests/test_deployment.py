import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "run_guardian.sh"


def _bash():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required for deployment helper behavior tests")
    return bash


def _shell_path(path: Path):
    if os.name != "nt":
        return str(path)
    result = subprocess.run(
        ["wsl.exe", "wslpath", "-a", str(path).replace("\\", "/")],
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _write_executable(path: Path, content: str):
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _fake_environment(tmp_path: Path, *distros: str):
    ros_root = tmp_path / "opt" / "ros"
    bin_dir = tmp_path / "bin"
    workspace = tmp_path / "workspace with spaces"
    (workspace / "ros2_ws").mkdir(parents=True)
    (workspace / "configs").mkdir()
    (workspace / "configs" / "guardian.yaml").write_text(
        "guardian_node:\n  ros__parameters:\n    task: navigate_to_goal\n",
        encoding="utf-8",
    )
    bin_dir.mkdir()
    command_log = tmp_path / "commands.log"
    for distro in distros:
        distro_dir = ros_root / distro
        distro_dir.mkdir(parents=True)
        _write_executable(
            distro_dir / "setup.bash",
            f'export FAKE_ROS_SOURCED="{distro}"\n',
        )
    return ros_root, bin_dir, workspace, command_log


def _install_workspace_setup(workspace: Path, distro: str):
    install_dir = workspace / "install" / distro
    install_dir.mkdir(parents=True, exist_ok=True)
    _write_executable(
        install_dir / "setup.bash",
        f'export FAKE_WORKSPACE_SOURCED="{distro}"\n',
    )


def _fake_commands(bin_dir: Path, command_log: Path):
    _write_executable(
        bin_dir / "colcon",
        """#!/usr/bin/env bash
printf 'colcon|ROS=%s|%s\\n' "${FAKE_ROS_SOURCED:-}" "$*" >> "$GUARDIAN_COMMAND_LOG"
""",
    )
    _write_executable(
        bin_dir / "ros2",
        """#!/usr/bin/env bash
printf 'ros2|ROS=%s|WS=%s|%s\\n' "${FAKE_ROS_SOURCED:-}" "${FAKE_WORKSPACE_SOURCED:-}" "$*" >> "$GUARDIAN_COMMAND_LOG"
""",
    )
    shell_path = _shell_path(bin_dir)
    if os.name == "nt":
        path = f"{shell_path}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    else:
        path = f"{shell_path}:{os.environ.get('PATH', '')}"
    return {
        "GUARDIAN_COMMAND_LOG": _shell_path(command_log),
        "PATH": path,
    }


def _run(tmp_path: Path, *args, env=None):
    env = env or os.environ.copy()
    helper = _shell_path(HELPER)
    if os.name == "nt":
        exports = " ".join(
            f"{name}={shlex.quote(env[name])}"
            for name in ("GUARDIAN_ROS_ROOT", "GUARDIAN_COMMAND_LOG", "PATH")
            if name in env
        )
        command = " ".join(
            ["bash", shlex.quote(helper), *(shlex.quote(arg) for arg in args)]
        )
        return subprocess.run(
            [_bash(), "-lc", f"export {exports}; exec {command}"],
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
    return subprocess.run(
        [_bash(), helper, *args],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )


def test_build_keeps_colcon_trees_separate_per_distro(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "build",
        "--distro",
        "humble",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    log = command_log.read_text(encoding="utf-8")
    assert f"--build-base {_shell_path(workspace / 'build' / 'humble')}" in log
    assert f"--install-base {_shell_path(workspace / 'install' / 'humble')}" in log
    assert f"--log-base {_shell_path(workspace / 'log' / 'humble')}" in log


def test_build_places_colcon_global_log_base_before_build(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "build",
        "--distro",
        "humble",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    log = command_log.read_text(encoding="utf-8")
    command = log.split("|", 2)[-1]
    tokens = shlex.split(command)
    assert tokens.index("--log-base") < tokens.index("build")


def test_auto_distro_rejects_multiple_installed_ros_distros(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(
        tmp_path, "humble", "jazzy"
    )
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)
    env.pop("ROS_DISTRO", None)

    result = _run(
        tmp_path,
        "build",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode != 0
    assert "ambiguous" in result.stderr.lower()


def test_core_sources_matching_install_and_passes_absolute_params_file(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "jazzy")
    _install_workspace_setup(workspace, "jazzy")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "core",
        "--distro",
        "jazzy",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    log = command_log.read_text(encoding="utf-8")
    assert "ros2|ROS=jazzy|WS=jazzy|run guardian_core guardian_node" in log
    assert f"--params-file {_shell_path(workspace / 'configs' / 'guardian.yaml')}" in log


def test_demo_sources_matching_overlay_and_uses_fixed_local_launcher(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    _install_workspace_setup(workspace, "humble")
    (workspace / "deploy").mkdir()
    (workspace / "deploy" / "run_local_demo.py").write_text("# trusted fixture\n")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)
    _write_executable(bin_dir / "python3", "#!/usr/bin/env bash\n"
        "printf 'demo|ROS=%s|WS=%s|%s\\n' \"${FAKE_ROS_SOURCED:-}\" \"${FAKE_WORKSPACE_SOURCED:-}\" \"$*\" >> \"$GUARDIAN_COMMAND_LOG\"\n")
    result = _run(tmp_path, "demo", "--distro", "humble", "--workspace", _shell_path(workspace), env=env)
    assert result.returncode == 0, result.stderr
    log = command_log.read_text()
    assert "demo|ROS=humble|WS=humble|" in log
    assert _shell_path(workspace / "deploy" / "run_local_demo.py") in log
    assert "--config" in log


def test_all_uses_only_documented_config_file_launch_argument(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    _install_workspace_setup(workspace, "humble")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "all",
        "--distro",
        "humble",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    log = command_log.read_text(encoding="utf-8")
    assert (
        f"ros2|ROS=humble|WS=humble|launch guardian_core guardian.launch.py "
        f"config_file:={_shell_path(workspace / 'configs' / 'guardian.yaml')}"
    ) in log
    assert "port:=" not in log


def test_unsupported_explicit_distro_fails_before_running_commands(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "build",
        "--distro",
        "iron",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode != 0
    assert "unsupported" in result.stderr.lower()
    assert not command_log.exists()


def test_ros_setup_can_reference_unset_trace_variable(tmp_path):
    ros_root, bin_dir, workspace, command_log = _fake_environment(tmp_path, "humble")
    (ros_root / "humble" / "setup.bash").write_text(
        'export FAKE_ROS_SOURCED="${AMENT_TRACE_SETUP_FILES}"\n',
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(_fake_commands(bin_dir, command_log))
    env["GUARDIAN_ROS_ROOT"] = _shell_path(ros_root)

    result = _run(
        tmp_path,
        "build",
        "--distro",
        "humble",
        "--workspace",
        _shell_path(workspace),
        env=env,
    )

    assert result.returncode == 0, result.stderr


def test_guardian_service_requires_ros_security_environment_file():
    service = (ROOT / "deploy" / "guardian@.service").read_text(encoding="utf-8")
    assert "ROS_SECURITY_ENABLE=true" in service
    assert "ROS_SECURITY_STRATEGY=Enforce" in service
    assert "EnvironmentFile=" in service
