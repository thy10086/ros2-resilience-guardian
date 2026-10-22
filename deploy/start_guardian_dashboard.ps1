[CmdletBinding()]
param(
    [ValidateSet("auto", "humble", "jazzy")]
    [string] $Distro = "auto",
    [string] $WslDistro = "",
    [string] $Workspace = ""
)

$ErrorActionPreference = "Stop"

function ConvertTo-BashArgument([string] $Value) {
    return "'" + $Value.Replace("'", "'\''") + "'"
}

$repo = if ($Workspace) {
    (Resolve-Path -LiteralPath $Workspace).Path
} else {
    (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
}

$wslPathArguments = @()
if ($WslDistro) {
    $wslPathArguments += @("-d", $WslDistro)
}
$wslPathArguments += @("--", "wslpath", "-a", $repo)
$workspaceWsl = (& wsl.exe @wslPathArguments).Trim()
if ($LASTEXITCODE -ne 0 -or -not $workspaceWsl) {
    throw "Unable to resolve repository path through wslpath: $repo"
}

$helper = "$workspaceWsl/deploy/run_guardian.sh"
$command = @(
    (ConvertTo-BashArgument $helper),
    "dashboard",
    "--distro",
    (ConvertTo-BashArgument $Distro),
    "--workspace",
    (ConvertTo-BashArgument $workspaceWsl)
) -join " "

$runArguments = @()
if ($WslDistro) {
    $runArguments += @("-d", $WslDistro)
}
$runArguments += @("--", "bash", "-lc", $command)

Start-Process `
    -FilePath "wsl.exe" `
    -ArgumentList $runArguments `
    -WindowStyle Hidden | Out-Null

Write-Output "Guardian Dashboard starting at http://127.0.0.1:8080"
