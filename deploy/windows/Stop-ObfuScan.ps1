[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$statePath = Join-Path $PSScriptRoot 'runtime\obfuscan.process.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    Write-Output 'No ObfuScan process state file exists; nothing was stopped.'
    exit 0
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$processId = [int]$state.ProcessId

try {
    $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop
}
catch {
    $processInfo = $null
}

if ($null -eq $processInfo) {
    Remove-Item -LiteralPath $statePath -Force
    Write-Output "PID $processId is no longer running; stale state was removed."
    exit 0
}

$expectedScript = [string]$state.WebServerScript
if ([string]::IsNullOrWhiteSpace($processInfo.CommandLine) -or $processInfo.CommandLine.IndexOf($expectedScript, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "PID $processId does not match the recorded web_server.py command line. Refusing to stop a possibly unrelated process."
}

if ($PSCmdlet.ShouldProcess("PID $processId", 'Stop ObfuScan web service')) {
    Stop-Process -Id $processId -Force
    Remove-Item -LiteralPath $statePath -Force
    Write-Output "Stopped ObfuScan web service (PID $processId)."
}
