## LSPClient Usage

### Installation
Install the package with:

```bash
pip install /libs/lspclient/
```
Read the README.md in the lspclient package for more information.

### Create an Instance of LSPClient
Create an instance by specifying the language server type (e.g., "clangd" for C/C++ or "java" for JDTLS), host, ports, and workspace directory:

```python
from lspclient import LSPClient
```

### Configuration values:
```python
lang_server_central_host = "127.0.0.1"
lang_server_central_port = 5000
lang_server_host = "127.0.0.1"
PROJECTID = ".....project-id-from-pipeline....."
```

#### Create an instance (choose "clangd" for C/C++ or "java" for Java):
```python
client = LSPClient(
    lang_server="clangd", # or "java"
    lang_server_host=lang_server_host, 
    lang_server_central_host=lang_server_central_host,
    lang_server_central_port=lang_server_central_port,
)
```

### 0. Start the Language Server
Start the language server (e.g., Clangd or Java) before initializing the client.
`client.start_server("<PROJECTID>")`

**Note - Don't call this function again and again**


### 1. Initialize the LSP Client
For both Clangd and Java servers, call the initialization method with the absolute path to your workspace:

```python
# For a Clangd server (or Java, as applicable):
client.initialize()
```
Note: Depending on your server's index time, you may need to wait a bit after initialization.

### 2. Retrieve Workspace Symbols

Retrieve symbols from the workspace that match a query string:

```python
response = client.send_message(message="workspace_symbols", query="main")
print("Workspace Symbols Response:")
print(response)
```

### 3. Go to Definition
Locate the definition of a symbol at the specified position in a file:

```python
response = client.send_message(
    message="go_to_definition",
    relative_file_path="path/to/file",
    line=7,
    character=4
)
print("Go To Definition Response:")
print(response)
```

### 4. Go to Declaration
Find the declaration of a symbol from a given document and position:

```python
response = client.send_message(
    message="go_to_declaration",
    relative_file_path="path/to/file",
    line=10,
    character=5
)
print("Go To Declaration Response:")
print(response)
```

### 5. Go to Type Definition
Retrieve the type definition for the symbol at the specified location:

```python
response = client.send_message(
    message="go_to_type_definition",
    relative_file_path="path/to/file",
    line=10,
    character=5
)
print("Go To Type Definition Response:")
print(response)
```

### 6. Go to Implementation
Locate the implementation of the symbol found at the given position:

```python
response = client.send_message(
    message="go_to_implementation",
    relative_file_path="path/to/file",
    line=10,
    character=5
)
print("Go To Implementation Response:")
print(response)
```

### 7. Find References
Search for all references to a symbol, including its declaration if specified:

```python
response = client.send_message(
    message="find_references",
    relative_file_path="path/to/file",
    line=10,
    character=5,
    include_declaration=True
)
print("Find References Response:")
print(response)
```
### 8. Close the Connection
Once finished, close the connection:

```python
client.close()
``` 

### Sample Python Code
```python
from lspclient import LSPClient

BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

lang_server_central_host = "127.0.0.1"
lang_server_central_port = 5000

abs_path_to_workspace = "/tmp/uploads/e3bd1258-f7a9-4c71-a064-e39ffec19bc1/Simple_CMake_Project"
lang_server_host = "127.0.0.1"
lang_server_port = 56403

client = LSPClient(
    lang_server="clangd",
    lang_server_host=lang_server_host,
    lang_server_port=lang_server_port,
    lang_server_central_host=lang_server_central_host,
    lang_server_central_port=lang_server_central_port,
    project_dir=abs_path_to_workspace
)

client.initialize()

# For example, to request "go_to_definition" at line 7, character 4 in main.c:
data = client.send_message(
    "go_to_definition",
    relative_file_path="main.c",
    line=7,
    character=4
)
print(data)
```
