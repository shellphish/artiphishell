import json
import os
import socket
from abc import ABC, abstractmethod
import time
import requests

# Terminal color codes
BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

BUF_SIZE = 256000


class LSPClientBase(ABC):
    def __init__(self, lang_server_host: str, timeout: int = 10,
                 lang_server_central_host: str = '127.0.0.1',
                 lang_server_central_port: int = 5000) -> None:
        self.host = lang_server_host
        self.port = None
        self.project_dir = None
        self.timeout = timeout
        self.lang_server_central_host = lang_server_central_host
        self.lang_server_central_port = lang_server_central_port
        self._message_id = 0
        self.is_server_ready = False
        self.buffer = b""

        # Create and configure the socket.

    def is_server_ready(self):
        return self.is_server_ready

    def get_file_content(self, project_dir: str, relative_path: str) -> dict:
        params = {"project_dir": project_dir, "relative_file_path": relative_path}
        url = f"http://{self.lang_server_central_host}:{self.lang_server_central_port}/get_file_content"
        response = requests.get(url, params=params)
        return response.json()

    def _next_id(self) -> int:
        current = self._message_id
        self._message_id += 1
        return current

    def _update_uri_values(self, data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "uri" and isinstance(value, str):
                    # Replace the project directory part in the URI
                    data[key] = value.replace(f'file://{self.project_dir}/', "")
                else:
                    # Recurse into nested dictionaries or lists
                    self._update_uri_values(value)
        elif isinstance(data, list):
            for item in data:
                self._update_uri_values(item)

        return data

    def _read_json_response(self) -> dict:
        # Wait until header is received
        while b"\r\n\r\n" not in self.buffer:
            self.buffer += self.sock.recv(BUF_SIZE - len(self.buffer))
        header_end = self.buffer.find(b"\r\n\r\n")
        header_text = self.buffer[:header_end].decode("utf-8")

        # Parse the Content-Length header.
        content_length_value = None
        for line in header_text.splitlines():
            if line.lower().startswith("content-length:"):
                try:
                    content_length_value = int(line.split(":", 1)[1].strip())
                except ValueError:
                    raise ValueError("Invalid Content-Length value.")
                break
        if content_length_value is None:
            raise ValueError("Content-Length header not found.", self.buffer)

        # Ensure the full payload is received.
        while len(self.buffer) < header_end + 4 + content_length_value:
            self.buffer += self.sock.recv(BUF_SIZE - len(self.buffer))
        payload = self.buffer[header_end + 4: header_end + 4 + content_length_value]

        try:
            json_response = json.loads(payload.decode("utf-8"))
            json_response = self._update_uri_values(json_response)
        except Exception as e:
            raise Exception("Invalid JSON response.", payload) from e

        self.buffer = self.buffer[header_end + 4 + content_length_value:]
        return json_response

    def send_json_rpc(self, message_dict: dict) -> None:
        request_json = json.dumps(message_dict)
        content_length = len(request_json)
        message = f"Content-Length: {content_length}\r\n\r\n{request_json}"
        self.sock.sendall(message.encode("utf-8"))

    def file_open_simulate(self, project_dir: str, relative_path: str = "compile_commands.json",
                           language_id: str = "cpp") -> None:
        file = self.get_file_content(project_dir, relative_path)
        file_content = file.get('content', '')
        fake_open_message = {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "languageId": language_id,
                    "text": file_content,
                    "uri": f"file://{project_dir}/{relative_path}",
                    "version": 1
                }
            }
        }
        self.send_json_rpc(fake_open_message)

    def workspace_symbols(self, query: str) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "workspace/symbol",
            "params": {"query": query}
        }
        self.send_json_rpc(message)
        return _id

    def go_to_definition(self, file_uri: str, line: int, character: int) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "textDocument/definition",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }
        self.send_json_rpc(message)
        return _id

    def go_to_declaration(self, file_uri: str, line: int, character: int) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "textDocument/declaration",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }
        self.send_json_rpc(message)
        return _id

    def go_to_type_definition(self, file_uri: str, line: int, character: int) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "textDocument/typeDefinition",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }
        self.send_json_rpc(message)
        return _id

    def go_to_implementation(self, file_uri: str, line: int, character: int) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "textDocument/implementation",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character}
            }
        }
        self.send_json_rpc(message)
        return _id

    def find_references(self, file_uri: str, line: int, character: int,
                        include_declaration: bool = False) -> int:
        _id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "textDocument/references",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": include_declaration}
            }
        }
        self.send_json_rpc(message)
        return _id

    def close(self) -> None:
        self.is_server_ready = False
        self.sock.close()

    @abstractmethod
    def initialize(self) -> int:
        """Initialize the language server."""
        pass

    @abstractmethod
    def send_message(self, message: str, **kwargs) -> dict:
        """
        Send an LSP message. Expected keyword arguments depend on the message type.
        """
        pass


class LSPClient:
    def __new__(cls, lang_server: str, lang_server_host: str, timeout: int = 10,
                lang_server_central_host: str = '127.0.0.1', lang_server_central_port: int = 5000):
        if lang_server == "clangd":
            return LSPClientClangd(lang_server_host, timeout, lang_server_central_host,
                                   lang_server_central_port)
        elif lang_server == "java":
            return LSPClientJava(lang_server_host, timeout, lang_server_central_host,
                                 lang_server_central_port)


class LSPClientClangd(LSPClientBase):
    def initialize(self) -> int:
        _id = self._next_id()
        config_path = os.path.join(os.path.dirname(__file__), "clangd.json")
        with open(config_path, "r") as file:
            init_message = json.load(file)
        # Adjust initialization parameters for clangd.
        init_message['id'] = _id
        init_message['params']['rootPath'] = self.project_dir
        init_message['params']['rootUri'] = f"file://{self.project_dir}"
        init_message['params']['workspaceFolders'][0]['uri'] = f"file://{self.project_dir}"
        init_message['params']['workspaceFolders'][0]['name'] = os.path.basename(self.project_dir)

        self.send_json_rpc(init_message)

        FLAG = {"jsonrpc": "2.0", "method": "$/progress",
                "params": {"token": "backgroundIndexProgress", "value": {"kind": "end"}}}
        first_time = True
        while True:
            _response = self._read_json_response()
            print(f"{BLUE}{json.dumps(_response, indent=4)}{RESET}")
            if _response.get('id') == 0 and first_time:
                self.initialized()
                self.file_open_simulate(self.project_dir)
                first_time = False
            if _response.get('params') and _response.get('params', {}).get('token') == "backgroundIndexProgress":
                self.send_json_rpc({"id": 0, "jsonrpc": "2.0", "results": None})
            if _response == FLAG:
                self.is_server_ready = True
                print("Server is ready.")
                return 0

    def start_language_server(self, project_id: str) -> dict:

        # Construct the API URL
        api_url = f"http://{self.lang_server_central_host}:{self.lang_server_central_port}/start_langserver"

        # Prepare request payload
        payload = {
            "project_id": project_id,
            "language": "c"
        }

        try:
            # Send request to start language server
            response = requests.post(api_url, json=payload)

            # Check response status
            if response.status_code == 200:
                self.project_dir = response.json().get("project_dir")
                self.port = int(response.json().get("port"))
                time.sleep(5)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port))
                return response.json()
            else:
                return {"error": f"Failed to start language server: {response.text}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def initialized(self) -> None:
        initialized_message = {
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }
        self.send_json_rpc(initialized_message)

    def send_message(self, message: str, **kwargs) -> dict:
        """
        Expected kwargs for:
          - "workspace_symbols": query=<str>
          - "go_to_definition", "go_to_declaration", "go_to_type_definition", "go_to_implementation":
              relative_file_path=<str>, line=<int>, symbol=<str>, [file_uri=<str>]
          - "find_references": relative_file_path=<str>, line=<int>, symbol=<str>,
              [file_uri=<str>], [include_declaration=<bool>]
        """
        _id = None
        if not self.is_server_ready:
            raise RuntimeError("Server is not ready.")

        if message == "workspace_symbols":
            query = kwargs.get("query")
            _id = self.workspace_symbols(query)
        elif message in ["go_to_definition", "go_to_declaration", "go_to_type_definition", "go_to_implementation"]:
            relative_file_path = kwargs.get("relative_file_path")
            line = kwargs.get("line")
            character = kwargs.get("character")
            file_uri = kwargs.get("file_uri", f"file://{self.project_dir}/{relative_file_path}")
            self.file_open_simulate(self.project_dir, relative_file_path)
            # Wait for the file to become idle.
            while True:
                _response = self._read_json_response()
                print(f"{BLUE}{json.dumps(_response, indent=4)}{RESET}")
                if (_response.get('params') and
                        _response.get('params').get('state') == 'idle' and
                        _response.get('params').get('uri') == relative_file_path):
                    break
            if message == "go_to_definition":
                _id = self.go_to_definition(file_uri, line, character)
            elif message == "go_to_declaration":
                _id = self.go_to_declaration(file_uri, line, character)
            elif message == "go_to_type_definition":
                _id = self.go_to_type_definition(file_uri, line, character)
            elif message == "go_to_implementation":
                _id = self.go_to_implementation(file_uri, line, character)
        elif message == "find_references":
            relative_file_path = kwargs.get("relative_file_path")
            line = kwargs.get("line")
            character = kwargs.get("character")
            include_declaration = kwargs.get("include_declaration", False)
            file_uri = kwargs.get("file_uri", f"file://{self.project_dir}/{relative_file_path}")
            self.file_open_simulate(self.project_dir, relative_file_path)
            _id = self.find_references(file_uri, line, character, include_declaration)
        else:
            raise ValueError("Invalid message type.")

        while True:
            _response = self._read_json_response()
            print(f"{BLUE}{json.dumps(_response, indent=4)}{RESET}")
            if _response.get('id') == _id:
                return _response


class LSPClientJava(LSPClientBase):
    def initialize(self) -> int:
        _id = self._next_id()
        init_message = {
            "jsonrpc": "2.0",
            "id": _id,
            "method": "initialize",
            "params": {
                "initializationOptions": {
                    "workspaceFolders": [f"file://{self.project_dir}"],
                    "initializationOptions": {"skipBuild": True},
                    "settings": {"java": {"autobuild": {"enabled": False}}}
                }
            }
        }
        self.send_json_rpc(init_message)
        while True:
            _response = self._read_json_response()
            print(f"{BLUE}{json.dumps(_response, indent=4)}{RESET}")
            if _response.get('params') and _response.get('params', {}).get('type') == "Started":
                self.is_server_ready = True
                self.initialized()
                return 0

    def start_language_server(self, project_id: str) -> dict:

        # Construct the API URL
        api_url = f"http://{self.lang_server_central_host}:{self.lang_server_central_port}/start_langserver"

        # Prepare request payload
        payload = {
            "project_id": project_id,
            "language": "java"
        }

        try:
            # Send request to start language server
            response = requests.post(api_url, json=payload)

            # Check response status
            if response.status_code == 200:
                self.project_dir = response.json().get("project_dir")
                self.port = response.json().get("port")
                time.sleep(5)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port))
                return response.json()
            else:
                return {"error": f"Failed to start language server: {response.text}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def initialized(self) -> None:
        initialized_message = {
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }
        self.send_json_rpc(initialized_message)

    def send_message(self, message: str, **kwargs) -> dict:
        """
        Expected kwargs for:
          - "workspace_symbols": query=<str>
          - "go_to_definition", "go_to_declaration", "go_to_type_definition", "go_to_implementation":
              relative_file_path=<str>, line=<int>, symbol=<str>, [file_uri=<str>]
          - "find_references": relative_file_path=<str>, line=<int>, symbol=<str>,
              [file_uri=<str>], [include_declaration=<bool>]
        """
        _id = None
        if not self.is_server_ready:
            raise RuntimeError("Server is not ready.")

        if message == "workspace_symbols":
            query = kwargs.get("query")
            _id = self.workspace_symbols(query)
        elif message in ["go_to_definition", "go_to_declaration", "go_to_type_definition", "go_to_implementation"]:
            relative_file_path = kwargs.get("relative_file_path")
            line = kwargs.get("line")
            character = kwargs.get("character")
            file_uri = kwargs.get("file_uri", f"file://{self.project_dir}/{relative_file_path}")
            # For Java, simulate a file open with language_id "java".
            self.file_open_simulate(self.project_dir, relative_file_path, language_id="java")
            if message == "go_to_definition":
                _id = self.go_to_definition(file_uri, line, character)
            elif message == "go_to_declaration":
                _id = self.go_to_declaration(file_uri, line, character)
            elif message == "go_to_type_definition":
                _id = self.go_to_type_definition(file_uri, line, character)
            elif message == "go_to_implementation":
                _id = self.go_to_implementation(file_uri, line, character)
        elif message == "find_references":
            relative_file_path = kwargs.get("relative_file_path")
            line = kwargs.get("line")
            character = kwargs.get("character")
            include_declaration = kwargs.get("include_declaration", False)
            file_uri = kwargs.get("file_uri", f"file://{self.project_dir}/{relative_file_path}")
            self.file_open_simulate(self.project_dir, relative_file_path, language_id="java")
            _id = self.find_references(file_uri, line, character, include_declaration)
        else:
            raise ValueError("Invalid message type.")

        while True:
            _response = self._read_json_response()
            print(f"{BLUE}{json.dumps(_response, indent=4)}{RESET}")
            if _response.get('id') == _id:
                return _response
