# Copy this file to obfuscan.config.psd1 and edit the paths for the VPS.
# Import-PowerShellDataFile reads this as data; it is not an executable script.
@{
    ProjectRoot                 = 'D:\Tools\ObfuScan'
    PythonExecutable            = 'C:\Python311\python.exe'
    EngineExecutable            = 'D:\Tools\ObfuScan\ObfuScan.exe'

    # The launcher rejects non-loopback values. Port 8080 must not be exposed publicly.
    ListenHost                  = '127.0.0.1'
    ListenPort                  = 8080

    # 512 MiB supports the verified 265 MiB APK plus multipart overhead.
    MaxUploadBytes              = 536870912
    ScanTimeoutSeconds          = 900
    MaxScannerStdoutBytes       = 33554432
    MaxScannerStderrBytes       = 1048576
    RequestIdleTimeoutSeconds   = 60

    # Conservative defaults for a private/small-scale service.
    MaxActiveConnections        = 8
    MaxConcurrentScans          = 1
    MinFreeDiskReserveBytes     = 4294967296

    # Never disclose absolute server paths to Internet clients.
    ExposeEnginePath            = $false
}
