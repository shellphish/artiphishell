"""
pip install /libs/lspclient/

Read README.md in lspclient for more information
"""

import time
from lspclient import LSPClient

BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

lang_server_central_host = "127.0.0.1"
lang_server_central_port = 5000

lang_server_host = "127.0.0.1"

# Create an instance of LSPClient for Clangd.
client = LSPClient(
    lang_server="clangd",
    lang_server_host=lang_server_host,
    lang_server_central_host=lang_server_central_host,
    lang_server_central_port=lang_server_central_port
)

# Start the language server.
started = client.start_language_server("my_unique_project2")
if not started:
    print(f"{RED}Failed to start the language server.{RESET}")
    exit(1)
time.sleep(2)

# Initialize the client.
client.initialize()

# Give the server some time to complete indexing if needed.
time.sleep(2)

# 1. Retrieve Workspace Symbols.
print("Testing workspace_symbols...")
ws_response = client.send_message(
    message="workspace_symbols",
    query="ngx_http_process_black_list"  # Update query as needed.
)
print("Workspace Symbols Response:")
print(ws_response)
time.sleep(1)

# 2. Go to Definition.
print("Testing go_to_definition...")
def_response = client.send_message(
    message="go_to_definition",
    relative_file_path="src/os/unix/ngx_recv.c",  # Adjust with your source file.
    line=143,
    character=24
)
print("Go To Definition Response:")
print(def_response)
time.sleep(1)

# 3. Go to Declaration.
print("Testing go_to_declaration...")
decl_response = client.send_message(
    message="go_to_declaration",
    relative_file_path="src/os/unix/ngx_recv.c",
    line=143,
    character=24
)
print("Go To Declaration Response:")
print(decl_response)
time.sleep(1)

# 4. Go to Type Definition.
print("Testing go_to_type_definition...")
type_def_response = client.send_message(
    message="go_to_type_definition",
    relative_file_path="src/os/unix/ngx_recv.c",
    line=143,
    character=24
)
print("Go To Type Definition Response:")
print(type_def_response)
time.sleep(1)

# 5. Go to Implementation.
print("Testing go_to_implementation...")
impl_response = client.send_message(
    message="go_to_implementation",
    relative_file_path="src/os/unix/ngx_recv.c",
    line=143,
    character=24
)
print("Go To Implementation Response:")
print(impl_response)
time.sleep(1)

# 6. Find References.
print("Testing find_references...")
refs_response = client.send_message(
    message="find_references",
    relative_file_path="src/http/ngx_http_request.c",
    line=3962,
    character=0,
    include_declaration=True
)
print("Find References Response:")
print(refs_response)
time.sleep(1)

# 7. Close the Connection.
client.close()
print("Connection closed.")
