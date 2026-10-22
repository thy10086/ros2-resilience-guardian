#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly ROS_ROOT="${GUARDIAN_ROS_ROOT:-/opt/ros}"

usage() {
    cat >&2 <<'EOF'
Usage: run_guardian.sh <build|test|dashboard|core|simulator|all>
    [--distro auto|humble|jazzy] [--workspace PATH]
EOF
}

fail() {
    printf 'run_guardian.sh: %s\n' "$*" >&2
    exit 1
}

command_name="${1:-}"
if [[ -z "$command_name" ]]; then
    usage
    exit 2
fi
shift

workspace="${GUARDIAN_WORKSPACE:-$DEFAULT_WORKSPACE}"
distro="${GUARDIAN_DISTRO:-auto}"

while (($# > 0)); do
    case "$1" in
        --distro)
            (($# >= 2)) || fail "--distro requires humble, jazzy, or auto"
            distro="$2"
            shift 2
            ;;
        --workspace)
            (($# >= 2)) || fail "--workspace requires a path"
            workspace="$2"
            shift 2
            ;;
        -h|--help)
            usage >&1
            exit 0
            ;;
        *)
            usage
            fail "unknown argument: $1"
            ;;
    esac
done

case "$command_name" in
    build|test|dashboard|core|simulator|all) ;;
    *)
        usage
        fail "unsupported command: $command_name"
        ;;
esac

case "$distro" in
    auto|humble|jazzy) ;;
    *)
        fail "unsupported ROS distro '$distro'; use humble or jazzy"
        ;;
esac

workspace="$(cd -- "$workspace" 2>/dev/null && pwd -P)" ||
    fail "workspace does not exist: $workspace"
[[ -d "$workspace/ros2_ws" ]] ||
    fail "ROS workspace is missing: $workspace/ros2_ws"

if [[ "$distro" == "auto" ]]; then
    if [[ -n "${ROS_DISTRO:-}" ]]; then
        case "$ROS_DISTRO" in
            humble|jazzy)
                distro="$ROS_DISTRO"
                ;;
            *)
                fail "unsupported ROS_DISTRO '$ROS_DISTRO'; use humble or jazzy"
                ;;
        esac
    else
        installed=()
        for candidate in humble jazzy; do
            if [[ -f "$ROS_ROOT/$candidate/setup.bash" ]]; then
                installed+=("$candidate")
            fi
        done
        if ((${#installed[@]} == 0)); then
            fail "no supported ROS installation found under $ROS_ROOT"
        fi
        if ((${#installed[@]} != 1)); then
            fail "ROS distro selection is ambiguous; pass --distro humble or --distro jazzy"
        fi
        distro="${installed[0]}"
    fi
fi

ros_setup="$ROS_ROOT/$distro/setup.bash"
[[ -f "$ros_setup" ]] ||
    fail "ROS $distro setup file not found: $ros_setup"

# ROS setup scripts in Humble/Jazzy may read optional trace variables before
# defining them. Keep nounset for this helper, but not while importing ROS.
set +u
source "$ros_setup"
set -u
export ROS_DISTRO="$distro"

ros_workspace="$workspace/ros2_ws"
build_base="$workspace/build/$distro"
install_base="$workspace/install/$distro"
log_base="$workspace/log/$distro"
config_file="$workspace/configs/guardian.yaml"

build() {
    mkdir -p "$build_base" "$install_base" "$log_base"
    cd "$ros_workspace"
    colcon --log-base "$log_base" build \
        --symlink-install \
        --base-paths src \
        --build-base "$build_base" \
        --install-base "$install_base"
}

source_workspace() {
    local setup_file="$install_base/setup.bash"
    [[ -f "$setup_file" ]] ||
        fail "matching workspace install is missing: $setup_file; run build first"
    set +u
    source "$setup_file"
    set -u
}

run_project_tests() {
    source_workspace
    cd "$workspace"
    python3 -m pytest tests
}

run_node() {
    local executable="$1"
    [[ -f "$config_file" ]] ||
        fail "configuration file is missing: $config_file"
    source_workspace
    ros2 run guardian_core "$executable" \
        --ros-args \
        --params-file "$config_file"
}

run_all() {
    [[ -f "$config_file" ]] ||
        fail "configuration file is missing: $config_file"
    source_workspace
    ros2 launch guardian_core guardian.launch.py "config_file:=$config_file"
}

case "$command_name" in
    build)
        build
        ;;
    test)
        run_project_tests
        ;;
    dashboard)
        run_node guardian_dashboard
        ;;
    core)
        run_node guardian_node
        ;;
    simulator)
        run_node amr_simulator
        ;;
    all)
        run_all
        ;;
esac
