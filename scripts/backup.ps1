# PooGuard PostgreSQL Backup Script (Windows)
# Usage: .\backup.ps1 [-OutputDir <path>] [-Local] [-Help]

param(
    [string]$OutputDir = ".\backups",
    [switch]$Local,
    [switch]$Help
)

if ($Help) {
    Write-Host "PooGuard PostgreSQL Backup Script"
    Write-Host ""
    Write-Host "Usage: .\backup.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -OutputDir <path>   Output directory (default: .\backups)"
    Write-Host "  -Local              Run locally (requires pg_dump installed)"
    Write-Host "  -Help               Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\backup.ps1                           # Docker backup to .\backups"
    Write-Host "  .\backup.ps1 -OutputDir C:\backups     # Custom output directory"
    Write-Host "  .\backup.ps1 -Local                    # Local backup (requires pg_dump)"
    exit 0
}

# Configuration
$DbName = "pooguard"
$DbUser = "pooguard"
$DbHost = "localhost"
$DbPort = "5432"
$DockerService = "postgres"

# Create backup directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Generate timestamp for filename
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFile = Join-Path $OutputDir "pooguard_backup_$Timestamp.sql.gz"

Write-Host "PooGuard PostgreSQL Backup" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date)"
Write-Host "Output: $BackupFile"
Write-Host ""

if (-not $Local) {
    Write-Host "Mode: Docker"

    # Check if docker is available
    try {
        docker --version | Out-Null
    }
    catch {
        Write-Host "Error: Docker is not installed or not in PATH" -ForegroundColor Red
        exit 1
    }

    # Check if postgres container is running
    $running = docker compose ps --status running 2>$null | Select-String $DockerService
    if (-not $running) {
        # Try alternative check
        $running = docker compose ps 2>$null | Select-String "$DockerService.*Up"
        if (-not $running) {
            Write-Host "Error: PostgreSQL container is not running" -ForegroundColor Red
            Write-Host "Start it with: docker compose up -d postgres"
            exit 1
        }
    }

    Write-Host "Running pg_dump in Docker container..."

    # Create backup using pg_dump and gzip
    # Note: On Windows, we need to handle the piping differently
    $tempSqlFile = Join-Path $env:TEMP "pooguard_backup_$Timestamp.sql"

    docker compose exec -T $DockerService pg_dump -U $DbUser $DbName > $tempSqlFile

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: pg_dump failed" -ForegroundColor Red
        if (Test-Path $tempSqlFile) { Remove-Item $tempSqlFile }
        exit 1
    }

    # Compress using .NET GZip
    try {
        $inputStream = [System.IO.File]::OpenRead($tempSqlFile)
        $outputStream = [System.IO.File]::Create($BackupFile)
        $gzipStream = New-Object System.IO.Compression.GZipStream($outputStream, [System.IO.Compression.CompressionMode]::Compress)
        $inputStream.CopyTo($gzipStream)
        $gzipStream.Close()
        $outputStream.Close()
        $inputStream.Close()

        # Clean up temp file
        Remove-Item $tempSqlFile
    }
    catch {
        Write-Host "Error compressing backup: $_" -ForegroundColor Red
        if (Test-Path $tempSqlFile) { Remove-Item $tempSqlFile }
        exit 1
    }
}
else {
    Write-Host "Mode: Local"

    # Check if pg_dump is available
    try {
        pg_dump --version | Out-Null
    }
    catch {
        Write-Host "Error: pg_dump is not installed or not in PATH" -ForegroundColor Red
        exit 1
    }

    $tempSqlFile = Join-Path $env:TEMP "pooguard_backup_$Timestamp.sql"

    # Use DATABASE_URL if available
    if ($env:DATABASE_URL) {
        Write-Host "Using DATABASE_URL..."
        pg_dump $env:DATABASE_URL > $tempSqlFile
    }
    else {
        Write-Host "Using default connection settings..."
        Write-Host "Host: ${DbHost}:${DbPort}"
        $env:PGPASSWORD = $env:DB_PASSWORD
        pg_dump -h $DbHost -p $DbPort -U $DbUser $DbName > $tempSqlFile
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: pg_dump failed" -ForegroundColor Red
        if (Test-Path $tempSqlFile) { Remove-Item $tempSqlFile }
        exit 1
    }

    # Compress using .NET GZip
    try {
        $inputStream = [System.IO.File]::OpenRead($tempSqlFile)
        $outputStream = [System.IO.File]::Create($BackupFile)
        $gzipStream = New-Object System.IO.Compression.GZipStream($outputStream, [System.IO.Compression.CompressionMode]::Compress)
        $inputStream.CopyTo($gzipStream)
        $gzipStream.Close()
        $outputStream.Close()
        $inputStream.Close()

        Remove-Item $tempSqlFile
    }
    catch {
        Write-Host "Error compressing backup: $_" -ForegroundColor Red
        if (Test-Path $tempSqlFile) { Remove-Item $tempSqlFile }
        exit 1
    }
}

# Verify backup was created
if (Test-Path $BackupFile) {
    $BackupSize = (Get-Item $BackupFile).Length
    $BackupSizeFormatted = "{0:N2} KB" -f ($BackupSize / 1KB)
    if ($BackupSize -gt 1MB) {
        $BackupSizeFormatted = "{0:N2} MB" -f ($BackupSize / 1MB)
    }

    Write-Host ""
    Write-Host "Backup completed successfully!" -ForegroundColor Green
    Write-Host "File: $BackupFile"
    Write-Host "Size: $BackupSizeFormatted"

    # Show recent backups
    Write-Host ""
    Write-Host "Recent backups in ${OutputDir}:"
    Get-ChildItem -Path $OutputDir -Filter "*.sql.gz" | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | Format-Table Name, Length, LastWriteTime -AutoSize
}
else {
    Write-Host "Error: Backup file was not created" -ForegroundColor Red
    exit 1
}
