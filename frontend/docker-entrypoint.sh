#!/bin/sh
set -e

# Check if SSL certificates exist
if [ ! -f /etc/nginx/ssl/fullchain.pem ] || [ ! -f /etc/nginx/ssl/privkey.pem ]; then
    echo "WARNING: SSL certificates not found at /etc/nginx/ssl/"
    echo "Expected files: fullchain.pem and privkey.pem"
    echo ""
    echo "For production: Mount your certificates using -v /path/to/certs:/etc/nginx/ssl:ro"
    echo "For development: Generate self-signed certificates (see DEPLOYMENT.md)"
    echo ""
    echo "Falling back to HTTP-only mode..."

    # Copy the non-SSL config if certificates are missing
    if [ -f /etc/nginx/conf.d/default.conf.http-fallback ]; then
        cp /etc/nginx/conf.d/default.conf.http-fallback /etc/nginx/conf.d/default.conf
    fi
fi

# Execute the CMD
exec "$@"
