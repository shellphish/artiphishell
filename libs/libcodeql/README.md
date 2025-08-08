# libcodeql


### Example


`base_url` defaults to `os.getenv("CODEQL_SERVER_URL", "http://codeql:4000")`

#### CLI
```bash
$ codeql-query --help
usage: codeql-query [-h] --cp_name CP_NAME --project_id PROJECT_ID (--query_tmpl QUERY_TMPL | --query_file QUERY_FILE) [--query_params QUERY_PARAMS] [--base_url BASE_URL]
                    [--timeout TIMEOUT] [--output OUTPUT]

options:
  -h, --help            show this help message and exit
  --cp_name CP_NAME
  --project_id PROJECT_ID
  --query_tmpl QUERY_TMPL
  --query_file QUERY_FILE
  --query_params QUERY_PARAMS
  --base_url BASE_URL
  --timeout TIMEOUT     Timeout in seconds for the query
  --output OUTPUT       The path to a file to write the output to.

$ codeql-analyze --help
usage: codeql-analyze [-h] --cp_name CP_NAME --project_id PROJECT_ID [--queries [QUERIES ...]] [--base_url BASE_URL] [--timeout TIMEOUT] [--output OUTPUT]

options:
  -h, --help            show this help message and exit
  --cp_name CP_NAME
  --project_id PROJECT_ID
  --queries [QUERIES ...]
  --base_url BASE_URL
  --timeout TIMEOUT     Timeout in seconds for the analysis
  --output OUTPUT       The path to a file to write the output to.

# You shouldn't need to use codeql-upload-db, it's mainly for codeql_build component.
$ codeql-upload-db --help
usage: codeql-upload-db [-h] --cp_name CP_NAME --project_id PROJECT_ID --language LANGUAGE
                        --db_file DB_FILE [--base_url BASE_URL]

options:
  -h, --help            show this help message and exit
  --cp_name CP_NAME
  --project_id PROJECT_ID
  --language LANGUAGE
  --db_file DB_FILE
  --base_url BASE_URL
```

### Python lib

```python
from libcodeql.client import CodeQLClient
import asyncio

query = """
import cpp

from FunctionCall call, Function func
where 
    call.getTarget().hasName("strcpy") and
    call.getEnclosingFunction() = func
select call, func, call.getLocation(), "Call to strcpy found in function " + func.getName() + "."
"""

async def main():
    client = CodeQLClient()

    # You shouldn't need to use upload-db, it's mainly for codeql_build component.
    # await client.upload_db("cups", "1", "c", "/path/to/bundled-codeql-db.zip")

    task1 = asyncio.create_task(client.query({
        "cp_name": "cups", 
        "project_id": "1", 
        "query_tmpl": "info-extraction-c/generic_c_reaching_files.ql.j2", 
        "query_params": {"target_functions": ['memcpy']},
        "timeout": 60*60  # Optional, timeout in seconds
    }))
    
    task2 = asyncio.create_task(client.query({
        "cp_name": "cups", 
        "project_id": "1", 
        "query": query,
        "timeout": 60*60,  # Optional, timeout in seconds
        "result_set": "set1",  # Optional, only required when your query produces multiple result sets
        "entities": "all"      # Optional, passed in to bqrs decode as a cliarg in case you want to decode entities differently.
                               # see https://docs.github.com/en/code-security/codeql-cli/codeql-cli-manual/bqrs-decode#--entitiesfmtfmt
    }))

    task3 = asyncio.create_task(client.analyze({
        "cp_name": "cups", 
        "project_id": "1", 
        "queries": [],
        "timeout": 60*60  # Optional, timeout in seconds
    }))

    result1, result2, result3 = await asyncio.gather(task1, task2, task3)
    print(result1)
    print(result2)
    print(result3)

if __name__ == "__main__":
    asyncio.run(main())

```

or if you hate async

```python
from libcodeql.client import CodeQLClient

query = """
import cpp

from FunctionCall call, Function func
where 
    call.getTarget().hasName("strcpy") and
    call.getEnclosingFunction() = func
select call, func, call.getLocation(), "Call to strcpy found in function " + func.getName() + "."
"""

client = CodeQLClient()

# You shouldn't need to use upload-db, it's mainly for codeql_build component.
# client.upload_db("cups", "1", "c", "/path/to/bundled-codeql-db.zip")

result1 = client.query({
    "cp_name": "cups", 
    "project_id": "1", 
    "query_tmpl": "info-extraction-c/generic_c_reaching_files.ql.j2", 
    "query_params": {"target_functions": ['memcpy']},
    "timeout": 60*60  # Optional, timeout in seconds
})

result2 = client.query({
    "cp_name": "cups", 
    "project_id": "1", 
    "query": query,
    "timeout": 60*60  # Optional, timeout in seconds
})

result3 = client.analyze({
    "cp_name": "cups", 
    "project_id": "1", 
    "queries": [],
    "timeout": 60*60  # Optional, timeout in seconds
})

print(result1)
print(result2)
print(result3)
```

For java, you can run codeql query in buildless mode. In CI, you can simply add "-buildless" to `cp_name`. 
For example,
```python

# With build query
result0 = client.query({
    "cp_name": "zookeeper", 
    "project_id": "1", 
    "query": query
})

# Buildless query
result1 = client.query({
    "cp_name": "zookeeper-buildless", 
    "project_id": "1", 
    "query": query
})
```

Buildless mode should be significantly faster than non-build mode, but it also will have false negative if your code base contains large amount of codes generated during build.
