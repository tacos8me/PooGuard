# PooGuard Production Deployment Guide

This guide covers deploying PooGuard with HTTPS/TLS support for production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [TLS Certificate Setup](#tls-certificate-setup)
- [Production Deployment](#production-deployment)
- [Development with TLS](#development-with-tls)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Database Backup and Restore](#database-backup-and-restore)
  - [Manual Backups](#manual-backups)
  - [Automated Backups](#automated-backups)
  - [Restoring from Backup](#restoring-from-backup)
  - [Backup Retention](#backup-retention)
- [Volumes and Data Persistence](#volumes-and-data-persistence)

## Prerequisites

- Docker and Docker Compose installed
- Domain name pointing to your server (for Let's Encrypt)
- Ports 80 and 443 available

## TLS Certificate Setup

### Option 1: Let's Encrypt (Recommended for Production)

Let's Encrypt provides free, automated TLS certificates. Use Certbot to obtain them:

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Obtain certificate (standalone mode - stop any services on port 80 first)
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Certificates will be saved to:
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

Copy or symlink certificates to the PooGuard certs directory:

```bash
mkdir -p ./certs
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./certs/
sudo chmod 644 ./certs/*.pem
```

**Certificate Renewal:**

Let's Encrypt certificates expire every 90 days. Set up automatic renewal:

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab for automatic renewal
sudo crontab -e
# Add: 0 0 1 * * certbot renew --post-hook "docker-compose restart frontend"
```

### Option 2: Self-Signed Certificates (Development/Testing Only)

For development or internal testing, generate self-signed certificates:

```bash
mkdir -p ./certs

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ./certs/privkey.pem \
  -out ./certs/fullchain.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# For development with multiple domains/localhost
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ./certs/privkey.pem \
  -out ./certs/fullchain.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"
```

**Note:** Self-signed certificates will show browser warnings. This is expected and acceptable only for development.

### Option 3: Commercial Certificates

If using a commercial CA (DigiCert, Comodo, etc.):

1. Generate a Certificate Signing Request (CSR):
   ```bash
   openssl req -new -newkey rsa:2048 -nodes \
     -keyout ./certs/privkey.pem \
     -out ./certs/server.csr \
     -subj "/C=US/ST=State/L=City/O=Organization/CN=yourdomain.com"
   ```

2. Submit the CSR to your CA and receive the certificate

3. Save the certificate chain as `./certs/fullchain.pem` (include intermediate certificates)

## Production Deployment

### 1. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# Database
DB_PASSWORD=your_secure_database_password_here

# JWT Secret (generate with: openssl rand -base64 64)
JWT_SECRET=your_jwt_secret_here

# HuggingFace Token (for model downloads)
HF_TOKEN=your_huggingface_token

# TLS Configuration
TLS_CERT_PATH=./certs
NGINX_SERVER_NAME=yourdomain.com
```

### 2. Prepare Certificates

Ensure your certificates are in place:

```bash
ls -la ./certs/
# Should show:
# fullchain.pem  (certificate + intermediate chain)
# privkey.pem    (private key)
```

### 3. Deploy with TLS

```bash
# Build and start with production TLS configuration
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Check logs
docker-compose logs -f frontend

# Verify HTTPS is working
curl -I https://yourdomain.com
```

### 4. Verify Deployment

```bash
# Check all services are running
docker-compose ps

# Test HTTPS redirect (should return 301)
curl -I http://yourdomain.com

# Test HTTPS (should return 200)
curl -I https://yourdomain.com

# Check SSL certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com < /dev/null 2>/dev/null | openssl x509 -noout -dates
```

## Development with TLS

For local development with TLS (useful for testing HTTPS features):

```bash
# Generate self-signed certificates
mkdir -p ./certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ./certs/privkey.pem \
  -out ./certs/fullchain.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Start with production TLS config
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Access at https://localhost (accept the certificate warning)
```

## Security Considerations

### HSTS (HTTP Strict Transport Security)

The production configuration includes HSTS with a 2-year max-age. This tells browsers to always use HTTPS. Be aware:

- Once enabled, browsers will refuse HTTP connections for 2 years
- Ensure your TLS setup is stable before deploying
- Consider starting with a shorter max-age during initial rollout

### Security Headers

The following security headers are enabled:

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | max-age=63072000; includeSubDomains; preload | Force HTTPS |
| X-Frame-Options | DENY | Prevent clickjacking |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-XSS-Protection | 1; mode=block | XSS filter (legacy browsers) |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer info |
| Content-Security-Policy | (see config) | XSS/injection prevention |

### SSL/TLS Configuration

The configuration uses:
- TLS 1.2 and 1.3 only (no legacy SSL/TLS 1.0/1.1)
- Strong cipher suites (ECDHE, AES-GCM, ChaCha20)
- OCSP stapling for faster certificate validation
- HTTP/2 support for better performance

### Firewall Rules

Ensure your firewall allows:
- Port 80 (for HTTP to HTTPS redirect)
- Port 443 (for HTTPS)

Block direct access to internal services:
- Port 3001 (backend) - only accessible through nginx
- Port 8000 (model-service) - only accessible through backend
- Port 5432 (PostgreSQL) - only accessible internally
- Port 6379 (Redis) - only accessible internally

## Troubleshooting

### Certificate Issues

**"SSL certificate problem: self signed certificate"**
- Using self-signed certs is only for development
- For production, use Let's Encrypt or a commercial CA

**"SSL certificate has expired"**
- Renew certificates: `sudo certbot renew`
- Copy renewed certs to ./certs directory
- Restart frontend: `docker-compose restart frontend`

**Permission denied reading certificates**
```bash
sudo chmod 644 ./certs/*.pem
```

### nginx Won't Start

**Check nginx configuration:**
```bash
docker-compose exec frontend nginx -t
```

**Check certificate paths:**
```bash
docker-compose exec frontend ls -la /etc/nginx/ssl/
```

### Port Already in Use

```bash
# Find process using port 443
sudo lsof -i :443

# Kill the process or stop the conflicting service
sudo systemctl stop apache2  # if Apache is running
```

### HTTPS Not Working After Deployment

1. Check that certificates are mounted:
   ```bash
   docker-compose exec frontend ls -la /etc/nginx/ssl/
   ```

2. Check nginx logs:
   ```bash
   docker-compose logs frontend
   ```

3. Verify DNS points to your server:
   ```bash
   dig yourdomain.com
   ```

4. Test with curl:
   ```bash
   curl -v https://yourdomain.com
   ```

## File Structure

```
pooguard/
├── certs/                      # TLS certificates (not in git)
│   ├── fullchain.pem          # Certificate + chain
│   └── privkey.pem            # Private key
├── docker-compose.yml          # Base configuration
├── docker-compose.prod.yml     # Production TLS override
├── docker-compose.dev.yml      # Development override
├── frontend/
│   ├── Dockerfile              # Standard Dockerfile (HTTP)
│   ├── Dockerfile.prod         # Production Dockerfile (HTTPS)
│   ├── nginx.conf              # HTTP-only nginx config
│   ├── nginx.ssl.conf          # HTTPS nginx config
│   └── docker-entrypoint.sh    # Startup script
└── DEPLOYMENT.md               # This file
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `docker-compose up -d` | Start with HTTP only |
| `docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | Start with HTTPS |
| `docker-compose -f docker-compose.yml -f docker-compose.dev.yml up` | Development mode |
| `docker-compose logs -f frontend` | View nginx logs |
| `docker-compose exec frontend nginx -t` | Test nginx config |
| `docker-compose restart frontend` | Restart after cert update |

---

## Database Backup and Restore

PooGuard uses PostgreSQL for persistent storage. Regular backups are essential for data protection and disaster recovery.

### Manual Backups

#### Using the Backup Script

The simplest way to create a backup is using the provided script:

```bash
# Create a backup (Docker mode - default)
./scripts/backup.sh

# Create a backup with custom output directory
./scripts/backup.sh -o /path/to/backups

# Create a backup in local mode (requires pg_dump installed)
./scripts/backup.sh -l
```

The script will create a compressed backup file named `pooguard_backup_YYYYMMDD_HHMMSS.sql.gz`.

#### Using Docker Compose Directly

You can also run backups directly with Docker Compose:

```bash
# Quick one-liner backup
docker compose exec -T postgres pg_dump -U pooguard pooguard | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Using the backup service (stores in Docker volume)
docker compose run --rm backup
```

The backup service stores backups in the `pooguard-backups` Docker volume, which is also mounted at `/backups` in the postgres container.

#### Copying Backups from Docker Volume

To copy backups from the Docker volume to your local filesystem:

```bash
# List backups in the volume
docker compose exec postgres ls -la /backups

# Copy a specific backup to local directory
docker compose cp postgres:/backups/pooguard_backup_20240101_120000.sql.gz ./backups/

# Copy all backups
docker compose exec postgres sh -c 'cat /backups/*.sql.gz' > all_backups.tar.gz
```

### Automated Backups

#### Using Cron (Linux/macOS)

Set up automated daily backups using cron:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2:00 AM
0 2 * * * cd /path/to/pooguard && ./scripts/backup.sh -o /var/backups/pooguard >> /var/log/pooguard-backup.log 2>&1

# Add weekly backup on Sundays at 3:00 AM
0 3 * * 0 cd /path/to/pooguard && ./scripts/backup.sh -o /var/backups/pooguard/weekly >> /var/log/pooguard-backup.log 2>&1
```

#### Using Docker Compose Backup Service

For a Docker-native approach, you can use a cron container or scheduled task:

```bash
# Run backup using Docker Compose (good for scheduled tasks)
0 2 * * * cd /path/to/pooguard && docker compose run --rm backup >> /var/log/pooguard-backup.log 2>&1
```

#### Using Systemd Timer (Linux)

Create a systemd service and timer for more robust scheduling:

```ini
# /etc/systemd/system/pooguard-backup.service
[Unit]
Description=PooGuard Database Backup
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/path/to/pooguard
ExecStart=/path/to/pooguard/scripts/backup.sh -o /var/backups/pooguard
User=root

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/pooguard-backup.timer
[Unit]
Description=Run PooGuard backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl enable pooguard-backup.timer
sudo systemctl start pooguard-backup.timer
```

#### Windows Task Scheduler

For Windows deployments, use Task Scheduler:

1. Open Task Scheduler
2. Create a new Basic Task
3. Set trigger to daily at your preferred time
4. Set action to run: `powershell.exe`
5. Arguments: `-ExecutionPolicy Bypass -File C:\path\to\pooguard\scripts\backup.ps1`

### Restoring from Backup

#### Using the Restore Script

```bash
# Restore from backup (will prompt for confirmation)
./scripts/restore.sh backups/pooguard_backup_20240101_120000.sql.gz

# Restore without confirmation prompt
./scripts/restore.sh backups/pooguard_backup_20240101_120000.sql.gz -y

# Restore in local mode
./scripts/restore.sh backup.sql.gz -l
```

**Warning:** Restoring will drop and recreate the database, destroying all current data.

#### Manual Restore with Docker Compose

```bash
# Stop the backend to prevent writes during restore
docker compose stop backend

# Drop and recreate the database
docker compose exec postgres psql -U pooguard -d postgres -c "DROP DATABASE IF EXISTS pooguard;"
docker compose exec postgres psql -U pooguard -d postgres -c "CREATE DATABASE pooguard OWNER pooguard;"

# Restore from compressed backup
gunzip -c backup_20240101_120000.sql.gz | docker compose exec -T postgres psql -U pooguard -d pooguard

# Restore from uncompressed backup
cat backup.sql | docker compose exec -T postgres psql -U pooguard -d pooguard

# Restart the backend
docker compose start backend
```

#### Restore from Docker Volume

If your backup is in the Docker volume:

```bash
docker compose exec postgres sh -c 'gunzip -c /backups/pooguard_backup_20240101_120000.sql.gz | psql -U pooguard -d pooguard'
```

#### Post-Restore Steps

After restoring, you may need to:

1. **Run migrations** if the backup is from an older version:
   ```bash
   cd backend && npx knex migrate:latest
   ```

2. **Clear Redis cache** to ensure consistency:
   ```bash
   docker compose exec redis redis-cli FLUSHALL
   ```

3. **Restart all services** to refresh connections:
   ```bash
   docker compose restart
   ```

### Backup Retention

Implement a backup retention policy to manage storage space while maintaining recovery options.

#### Recommended Retention Policy

| Backup Type | Retention Period | Frequency |
|-------------|------------------|-----------|
| Daily       | 7 days           | Every day |
| Weekly      | 4 weeks          | Every Sunday |
| Monthly     | 12 months        | 1st of month |

#### Automated Cleanup Script

Add this to your cron or scheduled task to clean up old backups:

```bash
#!/bin/bash
# cleanup-backups.sh

BACKUP_DIR="/var/backups/pooguard"

# Delete daily backups older than 7 days
find "$BACKUP_DIR" -name "pooguard_backup_*.sql.gz" -mtime +7 -delete

# Keep weekly backups for 4 weeks (28 days)
# Keep monthly backups for 365 days

echo "Backup cleanup completed at $(date)"
```

Add to cron:

```bash
# Run cleanup daily at 4:00 AM
0 4 * * * /path/to/cleanup-backups.sh >> /var/log/pooguard-backup.log 2>&1
```

#### Storage Considerations

- **Compression:** Backups are gzip compressed (~70-90% reduction)
- **Estimated size:** Approximately 1-5MB per 10,000 request logs
- **Off-site storage:** Consider syncing backups to cloud storage (S3, GCS, Azure Blob)

Example S3 sync:

```bash
# Sync backups to S3 (add to cron after backup)
aws s3 sync /var/backups/pooguard s3://your-bucket/pooguard-backups/ --delete
```

---

## Volumes and Data Persistence

PooGuard uses the following named Docker volumes:

| Volume Name | Purpose | Mount Point |
|-------------|---------|-------------|
| `pooguard-postgres-data` | PostgreSQL data | `/var/lib/postgresql/data` |
| `pooguard-redis-data` | Redis AOF/RDB data | `/data` |
| `pooguard-model-cache` | HuggingFace model cache | `/home/appuser/.cache/huggingface` |
| `pooguard-backups` | Database backups | `/backups` (in postgres container) |

### Listing Volumes

```bash
docker volume ls | grep pooguard
```

### Inspecting Volumes

```bash
docker volume inspect pooguard-postgres-data
```

### Backing Up Volumes

For complete disaster recovery, you may want to backup entire volumes:

```bash
# Backup postgres data volume
docker run --rm -v pooguard-postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-volume.tar.gz -C /data .

# Restore postgres data volume
docker run --rm -v pooguard-postgres-data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/postgres-volume.tar.gz"
```

**Note:** Volume backups require stopping the containers first to ensure data consistency.

---

## Additional Resources

- [PostgreSQL Documentation - Backup and Restore](https://www.postgresql.org/docs/current/backup.html)
- [Docker Volumes Documentation](https://docs.docker.com/storage/volumes/)
- [pg_dump Documentation](https://www.postgresql.org/docs/current/app-pgdump.html)
