$ErrorActionPreference = "Stop"

$workspace = Split-Path -Parent $PSScriptRoot
$workspaceWsl = "/mnt/c/Users/thy/Documents/Codex/2026-09-25/new-chat/work/ros2-resilience-guardian"
$command = @"
source /opt/ros/humble/setup.bash
cd $workspaceWsl/ros2_ws
source install/setup.bash
export PYTHONPATH=$workspaceWsl/ros2_ws/src/guardian_core:$workspaceWsl/ros2_ws/src/guardian_interfaces:/opt/ros/humble/lib/python3.10/site-packages:/opt/ros/humble/local/lib/python3.10/dist-packages:$workspaceWsl/ros2_ws/install/guardian_core/lib/python3.10/site-packages:$workspaceWsl/ros2_ws/install/guardian_interfaces/local/lib/python3.10/dist-packages
export GUARDIAN_FRONTEND_DIR=$workspaceWsl/ros2_ws/src/guardian_core/guardian_core/frontend
exec python3 -c 'from guardian_core.dashboard import main; main()' --ros-args -p port:=8088 -p host:=127.0.0.1
"@

Start-Process `
    -FilePath "wsl.exe" `
    -ArgumentList @("-d", "Ubuntu-22.04", "--", "bash", "-lc", $command) `
    -WindowStyle Hidden

Write-Output "Guardian Dashboard starting at http://127.0.0.1:8088"
