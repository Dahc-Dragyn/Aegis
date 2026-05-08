# --- AEGIS TACTICAL MANIFOLD: PASSIVE ORCHESTRATOR ---
FROM python:3.11-slim

# 1. System Dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 2. Workspace Setup
WORKDIR /app
RUN mkdir -p /app/artifacts /app/triage /app/aegis_mcp

# 3. Python Environment
COPY aegis_mcp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Source Transfer
COPY triage/ /app/triage/
COPY aegis_mcp/server.py /app/aegis_mcp/

# 5. Environment Config
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# 6. Operational Entry
EXPOSE 8080
CMD ["python", "aegis_mcp/server.py"]
