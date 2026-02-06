# PooGuard PostgreSQL Restore Script (Windows)
# Usage: .\restore.ps1 -BackupFile <path> [-Local] [-Yes] [-Help]

param(
    [string]$BackupFile,
    [switch]$Local,
    [switch]$Yes,
    [switch]$Help
)

if ($Help) {
    Write-Host "PooGuard PostgreSQL Restore Script"
    Write-Host ""
    Write-Host "Usage: .\restore.ps1 -BackupFile <path> [options]"
    Write-Host ""
    Write-Host "Arguments:"
    Write-Host "  -BackupFile <path>  Path to backup file (.sql.gz or .sql)"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Local              Run locally (requires psql installed)"
    Write-Host "  -Yes                Skip confirmation prompt"
    Write-Host "  -Help               Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\restore.ps1 -BackupFile .\backups\clawguard_backup_20240101_120000.sql.gz"
    Write-Host "  .\restore.ps1 -BackupFile backup.sql.gz -Local -Yes"
    exit 0
}

# Check if backup file was provided
if (-not $BackupFile) {
    Write-Host "Error: No backup file specified" -ForegroundColor Red
    Write-Host "Usage: .\restore.ps1 -BackupFile <path> [options]"
    Write-Host "Run '.\restore.ps1 -Help' for more information"
    exit 1
}

# Check if backup file exists
if (-not (Test-Path $BackupFile)) {
    Write-Host "Error: Backup file not found: $BackupFile" -ForegroundColor Red
    exit 1
}

# Configuration
$DbName = "clawguard"
$DbUser = "clawguard"
$DbHost = "localhost"
$DbPort = "5432"
$DockerService = "postgres"

# Determine if file is compressed
$IsCompressed = $BackupFile -match "\.gz$"

Write-Host "PooGuard PostgreSQL Restore" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date)"
Write-Host "Backup file: $BackupFile"
Write-Host "Compressed: $IsCompressed"
Write-Host ""

# Safety confirmation
if (-not $Yes) {
    Write-Host "WARNING: This will overwrite the existing database!" -ForegroundColor Yellow
    Write-Host "All current data in the '$DbName' database will be lost." -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Are you sure you want to continue? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Restore cancelled."
        exit 0
    }
    Write-Host ""
}

# Decompress if needed
$SqlFile = $BackupFile
if ($IsCompressed) {
    $SqlFile = Join-Path $env:TEMP "clawguard_restore_temp.sql"
    Write-Host "Decompressing backup..."
    try {
        $inputStream = [System.IO.File]::OpenRead($BackupFile)
        $gzipStream = New-Object System.IO.Compression.GZipStream($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
        $outputStream = [System.IO.File]::Create($SqlFile)
        $gzipStream.CopyTo($outputStream)
        $outputStream.Close()
        $gzipStream.Close()
        $inputStream.Close()
    }
    catch {
        Write-Host "Error decompressing backup: $_" -ForegroundColor Red
        exit 1
    }
}

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
        $running = docker compose ps 2>$null | Select-String "$DockerService.*Up"
        if (-not $running) {
            Write-Host "Error: PostgreSQL container is not running" -ForegroundColor Red
            Write-Host "Start it with: docker compose up -d postgres"
            exit 1
        }
    }

    Write-Host "Dropping and recreating database..."
    docker compose exec -T $DockerService psql -U $DbUser -d postgres -c "DROP DATABASE IF EXISTS $DbName;"
    docker compose exec -T $DockerService psql -U $DbUser -d postgres -c "CREATE DATABASE $DbName OWNER $DbUser;"

    Write-Host "Restoring from backup..."
    Get-Content $SqlFile | docker compose exec -T $DockerService psql -U $DbUser -d $DbName

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: Some errors occurred during restore" -ForegroundColor Yellow
    }
}
else {
    Write-Host "Mode: Local"

    # Check if psql is available
    try {
        psql --version | Out-Null
    }
    catch {
        Write-Host "Error: psql is not installed or not in PATH" -ForegroundColor Red
        exit 1
    }

    if ($env:DATABASE_URL) {
        Write-Host "Using DATABASE_URL..."
        # Extract connection for postgres db (to drop/create)
        $baseUrl = $env:DATABASE_URL -replace "/[^/]+$", ""

        Write-Host "Dropping and recreating database..."
        psql "$baseUrl/postgres" -c "DROP DATABASE IF EXISTS $DbName;"
        psql "$baseUrl/postgres" -c "CREATE DATABASE $DbName;"

        Write-Host "Restoring from backup..."
        psql $env:DATABASE_URL -f $SqlFile
    }
    else {
        Write-Host "Using default connection settings..."
        Write-Host "Host: ${DbHost}:${DbPort}"
        $env:PGPASSWORD = $env:DB_PASSWORD

        Write-Host "Dropping and recreating database..."
        psql -h $DbHost -p $DbPort -U $DbUser -d postgres -c "DROP DATABASE IF EXISTS $DbName;"
        psql -h $DbHost -p $DbPort -U $DbUser -d postgres -c "CREATE DATABASE $DbName OWNER $DbUser;"

        Write-Host "Restoring from backup..."
        psql -h $DbHost -p $DbPort -U $DbUser -d $DbName -f $SqlFile
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: Some errors occurred during restore" -ForegroundColor Yellow
    }
}

# Clean up temp file if we decompressed
if ($IsCompressed -and (Test-Path $SqlFile)) {
    Remove-Item $SqlFile
}

Write-Host ""
Write-Host "Restore completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Note: You may need to run database migrations if the backup is from an older version:"
Write-Host "  cd backend; npx knex migrate:latest"
