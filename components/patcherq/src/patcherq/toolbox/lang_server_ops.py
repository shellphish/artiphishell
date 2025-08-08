from agentlib.lib import tools
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from lspclient import LSPClient
from .peek_utils import *
from .peek_utils import *

from enum import Enum
from urllib.parse import urlparse
import time
import os
import yaml

BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

MAX_RESULTS = 25

LANG_SERVER_URL = os.getenv("LANG_SERVER_URL", "http://172.17.0.3:5000")

GlobalLangServerSkill = None

class LangServerSkill:
    """
    A class to handle language server operations.
    """
    def __init__(self, project_source: str, **kwargs):
                
        with open(kwargs['project_yaml'], "r") as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
            
        self.project_language = project_metadata.language.value
        self.project_source = project_source
        self.initialized = False
        
        parsed = urlparse(LANG_SERVER_URL)
        
        if self.project_language in ['c', 'cpp', 'c++']:
            lang_server_type='clangd'
        else:
            lang_server_type='java'
            
        print("Connecting to language server at {}:{}...".format(parsed.hostname, parsed.port))
        self.client = LSPClient(lang_server_type, parsed.hostname, 10, parsed.hostname, parsed.port)
        
        #TODO: Get lang_server_project_id
        started = self.client.start_language_server(kwargs.get('lang_server_project_id', '0'))
        if not started:
            print(f"{RED}Failed to start the language server.{RESET}")
            return
        time.sleep(2)
        
        self.client.initialize()
        time.sleep(2)
        
        global GlobalLangServerSkill
        GlobalLangServerSkill = self
        self.initialized = True
    
    def send_message(self, message: str, **kwargs):
        raw_output = self.client.send_message(message, **kwargs).get('result', [])
        truncated_output = str(raw_output[:MAX_RESULTS])
        if not raw_output:
            return f"No results found\n"
        return truncated_output
    
    def get_start_character_from_line_symbol(self, line: int, symbol: str, file_path: str):
        file_path = file_path.lstrip('/')
        full_file_path = os.path.join(self.project_source, file_path)

        if not os.path.exists(full_file_path):
            return tool_error(f"File {full_file_path} does not exist.")
        elif not os.path.isfile(full_file_path):
            return tool_error(f"{full_file_path} is not a file.")
        else:
            with open(full_file_path, 'r') as file:
                file_content = file.read()
                
        lines = file_content.split('\n')
        if line >= len(lines):
            return -1
        line_content = lines[line]
        start_index = line_content.find(symbol)
        print("line content:", line_content)
        print("symbol:", symbol)
        if start_index == -1:
            return -1
        return start_index

@tools.tool
def get_symbol_references(symbol: str) -> str:
    """
    Get the references of a symbol by name.
    
    :param symbol: The name of the symbol to find the references for.
    :return: A list of references to the symbol in the workspace.
    """
    global GlobalLangServerSkill
    return GlobalLangServerSkill.send_message("workspace_symbols", query=symbol)

@tools.tool
def go_to_definition(file_path: str, line: int, symbol: str) -> str:
    """
    Locate the definition of a symbol in a file.
    
    :param file_path: The relative path to the file.
    :param line: The line number where the symbol is located.
    :param symbol: The symbol in context.
    :return: The definition location of the symbol.
    """
    global GlobalLangServerSkill
    character = GlobalLangServerSkill.get_start_character_from_line_symbol(line-1, symbol, file_path)
    if character == -1:
        return tool_error(f"Symbol {symbol} not found in file {file_path} at line {line}")
    return GlobalLangServerSkill.send_message("go_to_definition", relative_file_path=file_path, line=line-1, character=character)

@tools.tool
def go_to_declaration(file_path: str, line: int, symbol: str) -> str:
    """
    Find the declaration of a symbol in a file.
    
    :param file_path: The relative path to the file.
    :param line: The line number where the symbol is located.
    :param symbol: The symbol in context.
    :return: The declaration location of the symbol.
    """
    global GlobalLangServerSkill
    character = GlobalLangServerSkill.get_start_character_from_line_symbol(line-1, symbol, file_path)
    if character == -1:
        return tool_error(f"Symbol {symbol} not found in file {file_path} at line {line}")
    return GlobalLangServerSkill.send_message("go_to_declaration", relative_file_path=file_path, line=line-1, character=character)

@tools.tool
def go_to_type_definition(file_path: str, line: int, symbol: str) -> str:
    """
    Retrieve the type definition of a symbol in a file.
    
    :param file_path: The relative path to the file.
    :param line: The line number where the symbol is located.
    :param symbol: The symbol in context.
    :return: The type definition location of the symbol.
    """
    global GlobalLangServerSkill
    character = GlobalLangServerSkill.get_start_character_from_line_symbol(line-1, symbol, file_path)
    if character == -1:
        return tool_error(f"Symbol {symbol} not found in file {file_path} at line {line}")
    return GlobalLangServerSkill.send_message("go_to_type_definition", relative_file_path=file_path, line=line-1, character=character)

@tools.tool
def go_to_implementation(file_path: str, line: int, symbol: str) -> str:
    """
    Locate the implementation of a symbol in a file.
    
    :param file_path: The relative path to the file.
    :param line: The line number where the symbol is located.
    :param symbol: The symbol in context.
    :return: The implementation location of the symbol.
    """
    global GlobalLangServerSkill
    character = GlobalLangServerSkill.get_start_character_from_line_symbol(line-1, symbol, file_path)
    if character == -1:
        return tool_error(f"Symbol {symbol} not found in file {file_path} at line {line}")
    return GlobalLangServerSkill.send_message("go_to_implementation", relative_file_path=file_path, line=line-1, character=character)

@tools.tool
def find_references(file_path: str, line: int, symbol: str, include_declaration: bool = False) -> str:
    """
    Find all references to a symbol in a file.
    
    :param file_path: The relative path to the file.
    :param line: The line number where the symbol is located.
    :param symbol: The symbol in context.
    :param include_declaration: Whether to include the declaration as a reference.
    :return: A list of reference locations for the symbol.
    """
    global GlobalLangServerSkill
    character = GlobalLangServerSkill.get_start_character_from_line_symbol(line-1, symbol, file_path)
    if character == -1:
        return tool_error(f"Symbol {symbol} not found in file {file_path} at line {line}")
    return GlobalLangServerSkill.send_message("find_references", relative_file_path=file_path, line=line-1, character=character, include_declaration=include_declaration)

LANG_SERVER_TOOLS = {
    "get_symbol_references": get_symbol_references,
    "go_to_definition": go_to_definition,
    "go_to_declaration": go_to_declaration,
    "go_to_type_definition": go_to_type_definition,
    # "go_to_implementation": go_to_implementation,
    "find_references": find_references
}

if __name__ == "__main__":
    LangServerSkill("c", "172.17.0.3", 5000, '1')
    print(get_symbol_references("main"))