# Permanence Service

A backend service for storing artifacts from ARTIPHISHELL's CI campaigns, designed to work with the PermanenceClient.

## Overview

This service provides a REST API that accepts and stores:
- Indexed functions
- Grammar-reached functions
- Seed-reached functions
- Deduplicated POV reports
- POI reports
- Patch attempts (successful and unsuccessful)

All data is stored in both the filesystem and a SQLite database.

## Features

- **Dual Storage**: All artifacts are stored in both the filesystem and SQLite database
- **Authentication**: API access is protected with an API key
- **Request Logging**: All requests are logged for audit purposes
- **Organization**: Data is organized by project and harness
- **Status API**: Provides service statistics and status information

## Setup

### Prerequisites

- Python 3.9+
- pip

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/shellphish-support-syndicate/artiphishell.git
   cd artiphishell/libs/permanence/server
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure environment variables (optional):
   ```
   export PERMANENCE_STORAGE_ROOT=/path/to/storage
   export PERMANENCE_DB_PATH=/path/to/permanence.db
   export PERMANENCE_API_SECRET=your-secret-key
   export PERMANENCE_HOST=0.0.0.0
   export PERMANENCE_PORT=8000
   ```

4. Run the service:
   ```
   python permanence_service.py
   ```

### Docker

Alternatively, you can use Docker:

1. Build the image:
   ```
   docker build -t permanence-service .
   ```

2. Run the container:
   ```
   docker run -d -p 8000:8000 \
     -v /host/path/to/data:/data \
     -e PERMANENCE_API_SECRET=your-secret-key \
     --name permanence-service permanence-service
   ```

## API Endpoints

### Authentication

All endpoints require the `SHELLPHISH_SECRET` header with your API key.

### Endpoints

- `POST /indexed_functions/{project_name}`
- `POST /grammar_reached_functions/{project_name}/{harness_name}`
- `POST /seed_reached_functions/{project_name}/{harness_name}`
- `POST /deduplicated_pov_report/{project_name}/{harness_name}`
- `POST /poi_report/{project_name}/{harness_name}`
- `POST /successful_patch/{project_name}/{harness_name}`
- `POST /unsuccessful_patch_attempt/{project_name}/{harness_name}`
- `GET /status` - Get service status and statistics

## Storage Structure

```
permanence_storage/
├── project1/
│   ├── functions/
│   │   └── function_keys.json
│   ├── extra/
│   │   └── extra_data.json
│   ├── harness1/
│   │   ├── grammars/
│   │   │   ├── grammar_*.txt
│   │   │   └── hit_functions_*.json
│   │   ├── seeds/
│   │   │   ├── seed_*.bin
│   │   │   └── hit_functions_*.json
│   │   ├── pov_reports/
│   │   │   ├── dedup_report_*.json
│   │   │   └── crashing_seed_*.bin
│   │   ├── poi_reports/
│   │   │   └── poi_report_*.json
│   │   └── patches/
│   │       ├── successful_patch_*.patch
│   │       ├── unsuccessful_patch_reasoning_*.txt
│   │       └── patched_functions_*.json
│   └── harness2/
│       └── ...
└── project2/
    └── ...
```

## Database Schema

The service uses SQLite with the following tables:

- `indexed_functions`
- `grammar_reached_functions`
- `seed_reached_functions`
- `deduplicated_pov_reports`
- `poi_reports`
- `patch_attempts`

## Configuring Client

To use this service with the provided PermanenceClient, set these environment variables:

```bash
export PERMANENCE_API_BASE_URL="http://your-service-host:8000"
export PERMANENCE_API_SECRET="your-secret-key"
```

## Monitoring

Logs are stored in `permanence_service.log` and also output to the console.