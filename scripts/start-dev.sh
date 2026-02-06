#!/bin/bash

# PooGuard Development Startup Script

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Starting PooGuard Development Environment"
echo ""

# Check for .env file
if [ ! -f "$ROOT_DIR/.env" ]; then
    echo "Creating .env from .env.example..."
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    echo "Please edit .env with your settings"
fi

# Start Docker services (no frontend - runs locally for fast HMR)
echo "Starting Docker services (postgres, redis, model-service, backend)..."
docker-compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.dev.yml" up -d postgres redis model-service backend

# Wait for postgres to be ready
echo -n "Waiting for PostgreSQL..."
retries=0
until docker-compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.dev.yml" exec -T postgres pg_isready > /dev/null 2>&1; do
    echo -n "."
    sleep 1
    retries=$((retries + 1))
    if [ $retries -ge 30 ]; then
        echo " timed out!"
        exit 1
    fi
done
echo " ready"

# Run migrations via the backend container
echo "Running database migrations..."
docker-compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.dev.yml" exec -T backend npx knex migrate:latest
docker-compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.dev.yml" exec -T backend npx knex seed:run

# Install frontend deps and start locally
echo ""
echo "Installing frontend dependencies..."
cd "$ROOT_DIR/frontend"
npm install

echo ""
echo "  Backend:  http://localhost:3001  (Docker)"
echo "  Frontend: http://localhost:3000  (local)"
echo ""
echo "Press Ctrl+C to stop the frontend. Then run:"
echo "  docker-compose -f docker-compose.yml -f docker-compose.dev.yml down"
echo ""

npm run dev
