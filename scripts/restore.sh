#!/bin/bash

# PooGuard PostgreSQL Restore Script
# Usage: ./restore.sh <backup_file> [options]
#
# Options:
#   -d, --docker     Run inside Docker container (default)
#   -l, --local      Run locally (requires psql installed)
#   -y, --yes        Skip confirmation prompt
#   -h, --help       Show this help message

set -e

# Default configuration
USE_DOCKER=true
SKIP_CONFIRM=false
DB_NAME="clawguard"
DB_USER="clawguard"
DB_HOST="localhost"
DB_PORT="5432"
DOCKER_SERVICE="postgres"
COMPOSE_FILE=""
BACKUP_FILE=""

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
        -y|--yes)
            SKIP_CONFIRM=true
            shift
            ;;
        -f|--compose-file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "PooGuard PostgreSQL Restore Script"
            echo ""
            echo "Usage: ./restore.sh <backup_file> [options]"
            echo ""
            echo "Arguments:"
            echo "  backup_file        Path to backup file (.sql.gz or .sql)"
            echo ""
            echo "Options:"
            echo "  -d, --docker       Run inside Docker container (default)"
            echo "  -l, --local        Run locally (requires psql installed)"
            echo "  -f, --compose-file Specify docker-compose file"
            echo "  -y, --yes          Skip confirmation prompt"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./restore.sh backups/clawguard_backup_20240101_120000.sql.gz"
            echo "  ./restore.sh backup.sql.gz -l -y"
            echo "  ./restore.sh backup.sql.gz -f docker-compose.prod.yml"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            if [ -z "$BACKUP_FILE" ]; then
                BACKUP_FILE="$1"
            else
                echo "Error: Multiple backup files specified"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if backup file was provided
if [ -z "$BACKUP_FILE" ]; then
    echo "Error: No backup file specified"
    echo "Usage: ./restore.sh <backup_file> [options]"
    echo "Run './restore.sh --help' for more information"
    exit 1
fi

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Determine if file is compressed
IS_COMPRESSED=false
if [[ "$BACKUP_FILE" == *.gz ]]; then
    IS_COMPRESSED=true
fi

echo "PooGuard PostgreSQL Restore"
echo "============================"
echo "Timestamp: $(date)"
echo "Backup file: $BACKUP_FILE"
echo "Compressed: $IS_COMPRESSED"
echo ""

# Safety confirmation
if [ "$SKIP_CONFIRM" = false ]; then
    echo "WARNING: This will overwrite the existing database!"
    echo "All current data in the '$DB_NAME' database will be lost."
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Restore cancelled."
        exit 0
    fi
    echo ""
fi

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

    echo "Dropping and recreating database..."
    $COMPOSE_CMD exec -T $DOCKER_SERVICE psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
    $COMPOSE_CMD exec -T $DOCKER_SERVICE psql -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

    echo "Restoring from backup..."
    if [ "$IS_COMPRESSED" = true ]; then
        gunzip -c "$BACKUP_FILE" | $COMPOSE_CMD exec -T $DOCKER_SERVICE psql -U "$DB_USER" -d "$DB_NAME"
    else
        cat "$BACKUP_FILE" | $COMPOSE_CMD exec -T $DOCKER_SERVICE psql -U "$DB_USER" -d "$DB_NAME"
    fi
else
    echo "Mode: Local"

    # Check if psql is available
    if ! command -v psql &> /dev/null; then
        echo "Error: psql is not installed"
        exit 1
    fi

    # Use DATABASE_URL if available, otherwise use defaults
    if [ -n "$DATABASE_URL" ]; then
        echo "Using DATABASE_URL..."
        # Extract connection details from DATABASE_URL for drop/create
        # Format: postgres://user:password@host:port/database
        DB_CONN="${DATABASE_URL%/*}"  # Remove database name

        echo "Dropping and recreating database..."
        psql "$DB_CONN/postgres" -c "DROP DATABASE IF EXISTS $DB_NAME;"
        psql "$DB_CONN/postgres" -c "CREATE DATABASE $DB_NAME;"

        echo "Restoring from backup..."
        if [ "$IS_COMPRESSED" = true ]; then
            gunzip -c "$BACKUP_FILE" | psql "$DATABASE_URL"
        else
            psql "$DATABASE_URL" < "$BACKUP_FILE"
        fi
    else
        echo "Using default connection settings..."
        echo "Host: $DB_HOST:$DB_PORT"

        export PGPASSWORD="${DB_PASSWORD:-}"

        echo "Dropping and recreating database..."
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

        echo "Restoring from backup..."
        if [ "$IS_COMPRESSED" = true ]; then
            gunzip -c "$BACKUP_FILE" | psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"
        else
            psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$BACKUP_FILE"
        fi
    fi
fi

echo ""
echo "Restore completed successfully!"
echo ""
echo "Note: You may need to run database migrations if the backup is from an older version:"
echo "  cd backend && npx knex migrate:latest"
