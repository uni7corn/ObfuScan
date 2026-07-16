[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'obfuscan.config.psd1'),
    [int]$HealthCheckTimeoutSeconds = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not [IO.Path]::IsPathRooted($expanded)) {
        $expanded = Join-Path $PSScriptRoot $expanded
    }
    $resolved = [IO.Path]::GetFullPath($expanded)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label does not exist: $resolved"
    }
    return $resolved
}

function Assert-IntegerRange {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][long]$Minimum,
        [Parameter(Mandatory = $true)][long]$Maximum
    )

    $parsed = 0L
    if (-not [long]::TryParse([string]$Value, [ref]$parsed) -or $parsed -lt $Minimum -or $parsed -gt $Maximum) {
        throw "$Name must be an integer between $Minimum and $Maximum."
    }
    return $parsed
}

$configFile = Resolve-ExistingFile -Path $ConfigPath -Label 'Configuration file'
$config = Import-PowerShellDataFile -LiteralPath $configFile

$requiredKeys = @(
    'ProjectRoot', 'PythonExecutable', 'EngineExecutable', 'ListenHost', 'ListenPort',
    'MaxUploadBytes', 'ScanTimeoutSeconds', 'MaxScannerStdoutBytes', 'MaxScannerStderrBytes',
    'RequestIdleTimeoutSeconds',
    'MaxActiveConnections', 'MaxConcurrentScans', 'MinFreeDiskReserveBytes',
    'ExposeEnginePath'
)
foreach ($key in $requiredKeys) {
    if (-not $config.ContainsKey($key)) {
        throw "Missing required configuration key: $key"
    }
}

$projectRoot = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$config.ProjectRoot))
if (-not (Test-Path -LiteralPath $projectRoot -PathType Container)) {
    throw "ProjectRoot does not exist: $projectRoot"
}

$python = Resolve-ExistingFile -Path ([string]$config.PythonExecutable) -Label 'Python executable'
$engine = Resolve-ExistingFile -Path ([string]$config.EngineExecutable) -Label 'ObfuScan engine'
$webServer = Resolve-ExistingFile -Path (Join-Path $projectRoot 'web_server.py') -Label 'Web server script'

$listenHost = [string]$config.ListenHost
if ($listenHost -ne '127.0.0.1') {
    throw "Unsafe ListenHost '$listenHost'. Public deployment must keep ObfuScan on 127.0.0.1 behind Caddy."
}

$listenPort = Assert-IntegerRange -Name 'ListenPort' -Value $config.ListenPort -Minimum 1 -Maximum 65535
$maxUpload = Assert-IntegerRange -Name 'MaxUploadBytes' -Value $config.MaxUploadBytes -Minimum 314572800 -Maximum 4294967296
$scanTimeout = Assert-IntegerRange -Name 'ScanTimeoutSeconds' -Value $config.ScanTimeoutSeconds -Minimum 10 -Maximum 86400
$maxScannerStdout = Assert-IntegerRange -Name 'MaxScannerStdoutBytes' -Value $config.MaxScannerStdoutBytes -Minimum 1048576 -Maximum 268435456
$maxScannerStderr = Assert-IntegerRange -Name 'MaxScannerStderrBytes' -Value $config.MaxScannerStderrBytes -Minimum 65536 -Maximum 16777216
$requestIdleTimeout = Assert-IntegerRange -Name 'RequestIdleTimeoutSeconds' -Value $config.RequestIdleTimeoutSeconds -Minimum 5 -Maximum 300
$maxConnections = Assert-IntegerRange -Name 'MaxActiveConnections' -Value $config.MaxActiveConnections -Minimum 2 -Maximum 32
$maxScans = Assert-IntegerRange -Name 'MaxConcurrentScans' -Value $config.MaxConcurrentScans -Minimum 1 -Maximum 2
$diskReserve = Assert-IntegerRange -Name 'MinFreeDiskReserveBytes' -Value $config.MinFreeDiskReserveBytes -Minimum 67108864 -Maximum 17179869184

if ($maxScans -gt 1) {
    Write-Warning 'More than one concurrent scan requires a measured CPU/RAM/disk capacity test.'
}

$runtimeDir = Join-Path $PSScriptRoot 'runtime'
$logDir = Join-Path $PSScriptRoot 'logs'
$statePath = Join-Path $runtimeDir 'obfuscan.process.json'
New-Item -ItemType Directory -Path $runtimeDir, $logDir -Force | Out-Null

if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    try {
        $oldState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $oldProcess = Get-Process -Id ([int]$oldState.ProcessId) -ErrorAction Stop
        throw "ObfuScan appears to be running already (PID $($oldProcess.Id)). Use Stop-ObfuScan.ps1 first."
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        Remove-Item -LiteralPath $statePath -Force
    }
}

$environment = [ordered]@{
    OBFUSCAN_HOST                         = $listenHost
    OBFUSCAN_PORT                         = [string]$listenPort
    OBFUSCAN_EXECUTABLE                   = $engine
    OBFUSCAN_MAX_UPLOAD_BYTES             = [string]$maxUpload
    OBFUSCAN_SCAN_TIMEOUT_SECONDS         = [string]$scanTimeout
    OBFUSCAN_MAX_SCANNER_STDOUT_BYTES     = [string]$maxScannerStdout
    OBFUSCAN_MAX_SCANNER_STDERR_BYTES     = [string]$maxScannerStderr
    OBFUSCAN_REQUEST_IDLE_TIMEOUT_SECONDS = [string]$requestIdleTimeout
    OBFUSCAN_MAX_ACTIVE_CONNECTIONS       = [string]$maxConnections
    OBFUSCAN_MAX_CONCURRENT_SCANS          = [string]$maxScans
    OBFUSCAN_MIN_FREE_DISK_RESERVE_BYTES  = [string]$diskReserve
    OBFUSCAN_EXPOSE_ENGINE_PATH            = $(if ([bool]$config.ExposeEnginePath) { '1' } else { '0' })
    PYTHONUNBUFFERED                       = '1'
}

$previousEnvironment = @{}
foreach ($name in $environment.Keys) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $environment[$name], 'Process')
}

$stdoutPath = Join-Path $logDir 'web.stdout.log'
$stderrPath = Join-Path $logDir 'web.stderr.log'
try {
    $process = Start-Process `
        -FilePath $python `
        -ArgumentList @('-u', ('"{0}"' -f $webServer)) `
        -WorkingDirectory $projectRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru
}
finally {
    foreach ($name in $environment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}

$state = [ordered]@{
    ProcessId        = $process.Id
    StartedAtUtc     = [DateTime]::UtcNow.ToString('o')
    PythonExecutable = $python
    WebServerScript  = $webServer
    ListenUrl        = "http://${listenHost}:$listenPort"
}
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

$deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(3, $HealthCheckTimeoutSeconds))
$healthUrl = "http://${listenHost}:$listenPort/status"
$healthy = $false
do {
    Start-Sleep -Milliseconds 300
    if ($process.HasExited) {
        break
    }
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2
        $healthy = ($response.StatusCode -eq 200)
    }
    catch {
        $healthy = $false
    }
} while (-not $healthy -and [DateTime]::UtcNow -lt $deadline)

if (-not $healthy) {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    throw "ObfuScan did not become healthy at $healthUrl. Check $stderrPath and $stdoutPath."
}

[pscustomobject]@{
    Status           = 'Healthy'
    ProcessId        = $process.Id
    InternalUrl      = "http://${listenHost}:$listenPort"
    PublicExposure   = 'Caddy only; never publish port 8080'
    MaxUploadMiB     = [Math]::Floor($maxUpload / 1MB)
    ConcurrentScans  = $maxScans
    StandardOutput   = $stdoutPath
    StandardError    = $stderrPath
}
