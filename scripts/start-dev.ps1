# ClawGuard Development Startup Script (Windows)

Write-Host "Starting ClawGuard Development Environment" -ForegroundColor Cyan
Write-Host ""

$rootDir = Split-Path -Parent $PSScriptRoot

# Check for .env file
if (-not (Test-Path "$rootDir/.env")) {
    Write-Host "Creating .env from .env.example..."
    Copy-Item "$rootDir/.env.example" "$rootDir/.env"
    Write-Host "Please edit .env with your settings" -ForegroundColor Yellow
}

# Start Docker services (no frontend - runs locally for fast HMR)
Write-Host "Starting Docker services (postgres, redis, model-service, backend)..."
docker-compose -f "$rootDir/docker-compose.yml" -f "$rootDir/docker-compose.dev.yml" up -d postgres redis model-service backend

# Wait for postgres to be ready
Write-Host "Waiting for PostgreSQL..." -NoNewline
$retries = 0
while ($retries -lt 30) {
    $result = docker-compose -f "$rootDir/docker-compose.yml" -f "$rootDir/docker-compose.dev.yml" exec -T postgres pg_isready 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 1
    $retries++
}
Write-Host " ready"

# Run migrations via the backend container
Write-Host "Running database migrations..."
docker-compose -f "$rootDir/docker-compose.yml" -f "$rootDir/docker-compose.dev.yml" exec -T backend npx knex migrate:latest
docker-compose -f "$rootDir/docker-compose.yml" -f "$rootDir/docker-compose.dev.yml" exec -T backend npx knex seed:run

# Install frontend deps and start locally
Write-Host ""
Write-Host "Installing frontend dependencies..."
Push-Location "$rootDir/frontend"
npm install

Write-Host ""
Write-Host "  Backend:  http://localhost:3001  (Docker)" -ForegroundColor Green
Write-Host "  Frontend: http://localhost:3000  (local)" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the frontend. Then run:" -ForegroundColor DarkGray
Write-Host "  docker-compose -f docker-compose.yml -f docker-compose.dev.yml down" -ForegroundColor DarkGray
Write-Host ""

npm run dev
Pop-Location
