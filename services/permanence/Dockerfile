# aixcc-build: aixcc-permanence-server
ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -U pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY permanence_service.py .

# Create data directory
RUN mkdir -p /data/permanence_storage

# Set environment variables
ENV PERMANENCE_STORAGE_ROOT=/data/permanence_storage
ENV PERMANENCE_DB_PATH=/data/permanence.db
ENV PERMANENCE_HOST=0.0.0.0
ENV PERMANENCE_PORT=31337

# Expose the port
EXPOSE 31337

# Run the application
CMD ["python", "permanence_service.py"]