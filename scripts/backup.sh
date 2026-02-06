#!/bin/bash

# PooGuard PostgreSQL Backup Script
# Usage: ./backup.sh [options]
#
# Options:
#   -d, --docker     Run inside Docker container (default)
#   -l, --local      Run locally (requires pg_dump installed)
#   -o, --output     Output directory (default: ./backups)
#   -h, --help       Show this help message

set -e

# Default configuration
BACKUP_DIR="./backups"
USE_DOCKER=true
DB_NAME="clawguard"
DB_USER="clawguard"
DB_HOST="localhost"
DB_PORT="5432"
DOCKER_SERVICE="postgres"
COMPOSE_FILE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--docker)
            USE_DOCKER=true
            shift
            ;;
        -l|--local)
            USE_DOCKER=false
            shift
            ;;
        -o|--output)
            BACKUP_DIR="$2"
            shift 2
            ;;
        -f|--compose-file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "PooGuard PostgreSQL Backup Script"
            echo ""
            echo "Usage: ./backup.sh [options]"
            echo ""
            echo "Options:"
            echo "  -d, --docker       Run inside Docker container (default)"
            echo "  -l, --local        Run locally (requires pg_dump installed)"
            echo "  -o, --output DIR   Output directory (default: ./backups)"
            echo "  -f, --compose-file Specify docker-compose file"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./backup.sh                      # Docker backup to ./backups"
            echo "  ./backup.sh -l -o /var/backups   # Local backup to /var/backups"
            echo "  ./backup.sh -f docker-compose.prod.yml"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp for filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/clawguard_backup_${TIMESTAMP}.sql.gz"

echo "PooGuard PostgreSQL Backup"
echo "==========================="
echo "Timestamp: $(date)"
echo "Output: $BACKUP_FILE"
echo ""

if [ "$USE_DOCKER" = true ]; then
    echo "Mode: Docker"

    # Check if docker compose is available
    if command -v docker &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
        # Fall back to docker-compose if docker compose fails
        if ! $DOCKER_COMPOSE version &> /dev/null 2>&1; then
            if command -v docker-compose &> /dev/null; then
                DOCKER_COMPOSE="docker-compose"
            else
                echo "Error: Neither 'docker compose' nor 'docker-compose' found"
                exit 1
            fi
        fi
    else
        echo "Error: Docker is not installed or not in PATH"
        exit 1
    fi

    # Build compose command with optional file flag
    COMPOSE_CMD="$DOCKER_COMPOSE"
    if [ -n "$COMPOSE_FILE" ]; then
        COMPOSE_CMD="$DOCKER_COMPOSE -f $COMPOSE_FILE"
    fi

    # Check if postgres container is running
    if ! $COMPOSE_CMD ps --status running 2>/dev/null | grep -q "$DOCKER_SERVICE"; then
        # Try alternative check for older docker-compose versions
        if ! $COMPOSE_CMD ps 2>/dev/null | grep -q "${DOCKER_SERVICE}.*Up"; then
            echo "Error: PostgreSQL container is not running"
            echo "Start it with: $COMPOSE_CMD up -d postgres"
            exit 1
        fi
    fi

    echo "Running pg_dump in Docker container..."
    $COMPOSE_CMD exec -T $DOCKER_SERVICE pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_FILE"
else
    echo "Mode: Local"

    # Check if pg_dump is available
    if ! command -v pg_dump &> /dev/null; then
        echo "Error: pg_dump is not installed"
        exit 1
    fi

    # Use DATABASE_URL if available, otherwise use defaults
    if [ -n "$DATABASE_URL" ]; then
        echo "Using DATABASE_URL..."
        pg_dump "$DATABASE_URL" | gzip > "$BACKUP_FILE"
    else
        echo "Using default connection settings..."
        echo "Host: $DB_HOST:$DB_PORT"
        PGPASSWORD="${DB_PASSWORD:-}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_FILE"
    fi
fi

# Verify backup was created
if [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo ""
    echo "Backup completed successfully!"
    echo "File: $BACKUP_FILE"
    echo "Size: $BACKUP_SIZE"

    # Show recent backups
    echo ""
    echo "Recent backups in $BACKUP_DIR:"
    ls -lht "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -5
else
    echo "Error: Backup file was not created"
    exit 1
fi
