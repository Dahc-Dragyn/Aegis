FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (e.g., for python-multipart/fastapi)
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY aegis_mcp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and triage engine
COPY aegis_mcp/ ./aegis_mcp/
COPY triage/ ./triage/
COPY intel/ ./intel/

# Create results directory for persistence
RUN mkdir -p /app/forensic_results

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=8000

# Expose ingestion port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "aegis_mcp.server:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


