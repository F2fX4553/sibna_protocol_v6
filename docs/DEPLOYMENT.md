# Sibna Relay: Deployment Guide
## Deploying and Scaling the Sibna Infrastructure

The reference server in `server/main.py` is a FastAPI application designed to handle Pre-Key bundles and message relay.

### 1. Prerequisites
- **Python 3.10+**
- **SQLite3** (for metadata and key storage)
- **FastAPI / Uvicorn**

### 2. Basic Setup
```bash
cd server
pip install -r ../requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Production Hardening

#### Reverse Proxy (Nginx)
It is **mandatory** to run the Relay behind a reverse proxy for SSL/TLS termination.
```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 1M;
    }
}
```

#### Security Configuration
- **HTTPS Enforcement**: It is **mandatory** to run the Relay behind a reverse proxy for SSL/TLS termination. The client/SDK expects an encrypted connection for production.
- **Rate Limiting**: The server has built-in in-memory rate limiting. For high-availability, move this to a Redis-based limiter to sync across instances.
- **Data Retention**: Pending messages are purged automatically via a background thread after the `MESSAGE_TTL` expires (default: 24h).
- **TOFU (Trust On First Use)**: The server enforces Identity Key pinning. Once a `user_id` is registered with an identity key, it cannot be overwritten by another key.

### 4. Backups and Monitoring

#### Database Backups
Since the relay uses SQLite for mapping and bundles, regular file-level backups are essential:
- **Strategy**: Use `sqlite3 .backup` periodically.
- **Off-site**: Sync backups to a secure, off-site location.

#### Monitoring
- **Health Check**: Periodically poll `GET /server/info`.
- **Metrics**: Track message volume and registration rates to identify anomalies or spam attacks.

### 5. Scaling Considerations
- **Statelessness**: The relay is largely stateless, allowing for horizontal scalability behind a load balancer. 
- **Database Migration**: For extreme scale, migrate the SQLite schema to a distributed database like PostgreSQL.
