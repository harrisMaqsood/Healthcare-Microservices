FROM python:3.11-slim

# Security: Create non-root user
RUN groupadd -r healthcareai && useradd -r -g healthcareai healthcareai

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /var/log/healthcare_ai /data/chroma_db
RUN chown -R healthcareai:healthcareai /app /var/log/healthcare_ai /data/chroma_db

# Switch to non-root user
USER healthcareai

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]