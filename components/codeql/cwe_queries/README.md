# CWE Queries for CodeQL Analysis

This component runs CWE (Common Weakness Enumeration) queries on CodeQL databases and uploads the results to an analysis graph.

## Features

- **Multi-language support**: Java/JVM and C/C++ projects
- **CWE vulnerability detection**: Uses CodeQL security queries
- **Delta mode support**: Can analyze both base and current versions for comparison
- **Analysis graph integration**: Uploads vulnerabilities with codeflow information
- **Flexible function resolution**: Local or remote function resolver
- **Safe data management**: Optional cleanup of existing data

## Pipeline Architecture

### Full Mode
The `codeql_cwe_queries` task runs in full mode and analyzes the current codebase:
- Uses current CodeQL database
- Outputs to `codeql_cwe_report` and `codeql_cwe_sarif_report`

### Delta Mode
The `codeql_cwe_queries_base` task runs only in delta mode and analyzes both versions:
- Uses both base and current CodeQL databases
- Project IDs: `{{ project_id }}` (current) and `{{ project_id }}-base` (base)
- Outputs to base-specific repositories: `codeql_cwe_report_base` and `codeql_cwe_sarif_report_base`
- Requires `delta_mode_task` input to ensure it only runs in delta mode

**Note:** In delta mode, we run both `codeql_cwe_queries` (for current/HEAD) and `codeql_cwe_queries_base` (for base). The base run now always passes `--skip-analysis-graph` to avoid updating the Neo4j database.

- **Data-cleanup note:**
- • Base runs no longer pass `--clear-existing-cwe-data`, ensuring they never wipe findings produced by the HEAD run.

### Function Resolver Dependencies
Both tasks use the local function resolver with:
- **`full_functions_indices`**: Function index file (output from function-index-generator)
- **`functions_json_dir`**: Original function JSON directory (input to function-index-generator)

*Note: The `functions_by_file_index_json` input has been removed as it's not required for the local function resolver.*

## Local Testing Setup

### Prerequisites

- Dev container environment
- Docker and Docker Compose
- Access to backup data with CodeQL databases

**Note:** The `run_from_backup.sh` script should be run from within the dev container environment to ensure all dependencies and services are available.

### 1. Set Up Analysis Graph (Neo4j) in devContainer

#### Step 1: Navigate to backup folder
```bash
cd /path/to/your/backup/folder
```

#### Step 2: Extract analysis graph data
```bash
# If you have an analysis graph backup
tar -xf analysisgraph.tar.gz   # or similar backup file
```

#### Step 3: Create Docker Compose configuration
```bash
nano docker-compose.yaml
```

#### Step 4: Copy and paste this configuration:
```yaml
services:
  analysis-graph:
    image: neo4j:latest
    container_name: aixcc-analysis-graph
    network_mode: bridge
    restart: always
    environment:
      - NEO4J_AUTH=neo4j/helloworldpdt
      - NEO4J_AUTH=none    # temporarily disable auth
      - NEO4J_dbms_allow__upgrade=true
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - ./analysisgraph/var/lib/neo4j/data:/data
      - ./analysisgraph/var/lib/neo4j/logs:/logs
      - ./analysisgraph/var/lib/neo4j/import:/var/lib/neo4j/import
      - ./analysisgraph/var/lib/neo4j/plugins:/plugins
```

#### Step 5: Start the analysis graph
```bash
docker compose up
```

#### Step 6: Verify Neo4j is running
- Web interface: http://localhost:7474
- Bolt connection: bolt://localhost:7687
- Default credentials: neo4j/helloworldpdt

### 2. Run CWE Analysis

#### Using the backup script (from DevContainer)
```bash
cd /path/to/artiphishell/components/codeql/cwe_queries
./run_from_backup.sh
```

The script will:
1. Extract project metadata from backup
2. Set up function resolver data (function indices and JSON files)
3. Ask you to choose function resolver type (local or remote)
4. Ask you to choose whether to upload to analysis graph
5. Run CWE queries with all required arguments
6. Optionally upload results to analysis graph (based on your choice, always skip for base)

Interactive prompts (function-resolver choice and graph-upload choice) appear exactly once regardless of language.

#### Delta Mode Support (backup script)
The backup script automatically checks for a `codeql_build_base.codeql_database_path` entry in the selected backup:

1. If present, it extracts that DB, labels it with project-id `${PROJ_ID}-base`, and runs `run_cwe_queries.py` **after** the current run.
2. The base invocation always includes `--skip-analysis-graph` and *omits* `--clear-existing-cwe-data` so that:
   • Neo4j remains untouched, and
   • Findings from the current run stay intact.
3. Reports are written next to the current ones using the `_base` suffix.

**Note on Analysis Graph Upload:**
- Choose **"Upload to analysis graph"** (default) if you have the analysis graph container (Neo4j) running and want to store results for further analysis
- Choose **"Skip analysis graph upload"** if you only want to generate reports for testing/debugging or if the analysis graph container is not available

### 3. Verify Results

#### Check output files
```bash
ls -la out/cwe_analysis_*/
# Should contain:
# - codeql_cwe_sarif_report.json (raw CodeQL results)
# - codeql_cwe_report.json (processed results)
```

#### Query the analysis graph
Open Neo4j Browser at http://localhost:7474 and run:

```cypher
// Check uploaded vulnerabilities
MATCH (func:CFGFunction)-[r:HAS_CWE_VULNERABILITY]->(cwe:CWEVulnerability)
RETURN count(r) as total_vulnerabilities;

// View vulnerability details
MATCH (func:CFGFunction)-[r:HAS_CWE_VULNERABILITY]->(cwe:CWEVulnerability)
RETURN
  func.identifier as function_id,
  cwe.rule_id as rule_id,
  cwe.cwe_tags as cwe_tags,
  r.line_number as line_number
LIMIT 10;

// Check codeflow functions
MATCH (func:CFGFunction)-[r:HAS_CWE_VULNERABILITY]->(cwe:CWEVulnerability)
WHERE r.codeflow_functions IS NOT NULL
RETURN
  func.identifier as function_id,
  cwe.rule_id as rule_id,
  size(r.codeflow_functions) as num_codeflows
LIMIT 5;

// Check related locations functions
MATCH (func:CFGFunction)-[r:HAS_CWE_VULNERABILITY]->(cwe:CWEVulnerability)
WHERE r.related_locations_functions IS NOT NULL
RETURN
  func.identifier as function_id,
  cwe.rule_id as rule_id,
  size(r.related_locations_functions) as num_related_locations
LIMIT 5;
```

## Command Line Arguments

### Required Arguments (run_cwe_queries.py)
- `--project-name`: Name of the project in CodeQL database
- `--project-id`: Unique identifier for the project
- `--codeql-cwe-sarif-report`: Output path for raw SARIF report
- `--codeql-cwe-report`: Output path for processed JSON report
- `--language`: Project language (`jvm`, `java`, `c`, `c++`, `cpp`)
- `--codeql-database-path`: Path to the CodeQL database directory
- `--full-functions-indices`: Path to function index file (from function-index-generator)
- `--functions-json-dir`: Path to function JSON directory (original JSON files)

### Optional Arguments
- `--local-run`: Use local function resolver (default behavior when indices/JSON provided)
- `--skip-analysis-graph`: Skip uploading results to analysis graph (default: false, uploads by default)
- `--clear-existing-cwe-data`: Remove existing CWE data before upload (default: false)
- `--collect-rules-stats`: Collect comprehensive statistics about CodeQL rules (default: false)

## Rule Filtering and Whitelist

### Default Filtering Criteria
By default, CWE queries apply strict filtering to ensure high-quality results:
- **CWE Tags Required**: Rules must have proper CWE categorization
- **Error Severity**: Only rules with `severity="error"` are processed
- **Security Severity**: Rules must have defined security severity levels

### Whitelisted Rules
Certain critical rules bypass all filtering criteria and are always included:
- `java/toctou-race-condition`: Time-of-check time-of-use race conditions
- `java/relative-path-command`: Relative path command execution vulnerabilities

Whitelisted rules will be processed even if they lack standard metadata, ensuring important security issues are never missed.

## Rules Statistics Collection

When using `--collect-rules-stats`, the tool generates a comprehensive analysis of CodeQL rules:

### Output File: `error_rules.json`
```json
{
  "statistics": {
    "total_rules": 150,
    "total_errors": 75,
    "total_warnings": 45
  },
  "error_rules": {
    "java/zipslip": {
      "severity": "error",
      "description": "Arbitrary file write during archive extraction",
      "short_description": "Zip slip vulnerability",
      "tags": ["security", "external/cwe/cwe-22"],
      "security_severity": "7.5"
    }
  },
  "warning_rules": {
    "java/unused-parameter": {
      "severity": "warning",
      "description": "Unused parameter detected",
      "tags": ["maintainability"]
    }
  }
}
```

This feature is useful for:
- **Quality Assurance**: Understanding rule coverage and distribution
- **Security Analysis**: Identifying which error-level security rules are available
- **Rule Management**: Tracking rules by severity and security impact

## Supported Languages

### Java/JVM Projects
- **Query Suites**: java-security-experimental, java-security-extended

### C/C++ Projects
- **Query Suites**: cpp-security-experimental, cpp-security-extended

## Output Structure

### SARIF Report (`codeql_cwe_sarif_report.json`)
Raw CodeQL results in SARIF format with:
- Rule definitions and metadata
- Vulnerability locations
- Code flow information
- Severity levels

### Resolved Report (`codeql_cwe_report.json`)
Processed results with:
```json
{
  "metadata": {
    "language": "jvm",
    "total_vulnerable_functions": 7,
    "total_vulnerabilities": 9,
    "findings_per_rule_id": {
      "java/zipslip": 5,
      "java/partial-path-traversal": 2
    }
  },
  "vulnerable_functions": {
    "/src/project-parent/zt-zip/src/main/java/Example.java:42:11::public void process()": {
      "results": [
        {
          "rule_id": "java/zipslip",
          "rule_info": {
            "problem.severity": "error",
            "security-severity": "7.5",
            "cwe_tags": ["cwe-22"]
          },
          "message": "Arbitrary file write during archive extraction",
          "start_line": 42,
          "cwe_tags": ["cwe-22"],
          "level": "error",
          "security_severity": "7.5",
          "code_flow_functions": {
            "0": ["func1", "func2", "func3"],
            "1": ["func1", "func4"]
          },
          "related_locations_functions": [
            "related_func1",
            "related_func2"
          ]
        }
      ]
    }
  }
}
```

## Analysis Graph Integration

The component uploads CWE vulnerabilities to a Neo4j analysis graph with:

- **CFGFunction** nodes representing analyzed functions
- **CWEVulnerability** nodes representing security issues
- **HAS_CWE_VULNERABILITY** relationships connecting functions to vulnerabilities

## Enhanced Vulnerability Tracking

### Code Flow Functions
Code flow functions track the complete execution path that leads to a vulnerability:
- Each vulnerability can have multiple code flows (different paths to the same issue)
- Each code flow is represented as an array of function identifiers
- Useful for understanding how data flows through the system to create vulnerabilities

Example:
```json
"code_flow_functions": {
  "0": ["userInput", "processData", "writeFile"],
  "1": ["configRead", "parseValue", "writeFile"]
}
```

### Related Locations Functions
Related locations functions identify contextual functions that are relevant to a vulnerability:
- Functions that perform related operations (e.g., file system operations for path traversal)
- Helper functions involved in the vulnerable operation
- Functions that share similar vulnerability patterns

Example:
```json
"related_locations_functions": [
  "validatePath",
  "createDirectory",
  "checkPermissions"
]
```

### Relationship Properties
- `line_number`: Location of vulnerability
- `codeflow_functions`: Array of function call paths showing vulnerability propagation
- `related_locations_functions`: Array of function identifiers for related/contextual locations

## Environment Variables

```bash
# Analysis Graph Configuration
export ANALYSIS_GRAPH_BOLT_URL="bolt://neo4j:helloworldpdt@localhost:7687"

# Task-specific database URL (for multi-tenant setups)
export CRS_TASK_NUM="12345"
```