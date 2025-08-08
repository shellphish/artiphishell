# Language Server API

This API allows users to upload project source code, start a language server, and list active projects and servers.

---

## Usage Flow

### 1. Upload Project Source

#### Endpoint:
`/upload_source` (HTTP POST)

#### Payload:
- `project_id`: Unique project identifier (string).
- `language`: Project language (e.g., `"java"`, `"c"`).
- `file`: Tar.gz file containing the source code.

#### Example Command:
```bash
curl -X POST -F "project_id=my_unique_project" \
    -F "file=@java/data/jenkins.tar.gz" \
    -F "language=java" \
    http://localhost:5000/upload_source
```

#### Response Example:
```json
{
  "success": true,
  "project_id": "my_unique_project",
  "project_dir": "/tmp/uploads/my_unique_project"
}
```


### 2. Start Language Server


#### Endpoint:
`/start_langserver` (HTTP POST)

#### Payload:
JSON object containing:

`project_id`: The unique project ID.
`language`: The language (e.g., "java", "c").

#### Example Command:
```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"project_id": "my_unique_project", "language": "java"}' \
    http://localhost:5000/start_langserver
```
#### Response Example:
```json
{
  "language": "java",
  "project_id": "my_unique_project",
  "port": 48763,
  "project_dir": "/tmp/uploads/my_unique_project_server_<uuid>/jenkins"
}
```

### 3. List Active Projects


#### Endpoint:
`/list_projects` (HTTP GET)

Example Command:
```bash
curl -X GET http://localhost:5000/list_projects
```

#### Response:
A JSON object listing all uploaded projects with their status and server details.

```json
{
  "projects": [
    {
      "project_id": "my_unique_project",
      "language": "java",
      "server_port": 48763,
      "project_dir": "/tmp/uploads/my_unique_project_server_<uuid>/jenkins"
    }
  ]
}
```