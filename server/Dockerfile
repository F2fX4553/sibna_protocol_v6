# Docker Deployment for Sibna Relay

# Stage 1: Build & Setup
FROM python:3.12-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy server code
COPY server/ .

# Create volume for persistence
VOLUME /app/data
ENV DB_PATH=/app/data/relay.db

# Expose FastAPI port
EXPOSE 8000

# Run the relay
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
