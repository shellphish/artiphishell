# import openai
import os

from collections import namedtuple
from dotenv import load_dotenv

load_dotenv()

# NOTE: create a .env file and set OPENAI_API_KEY=<your key> and MODEL=<your model choice>

# MODEL = os.getenv("OPENAI_MODEL") or 'gpt-4o-2024-05-13'
# assert MODEL in ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-1106-preview', 'gpt-4o-2024-05-13']
MODEL = os.getenv("OPENAI_MODEL") or 'oai-gpt-4o'
OPENAI_API_KEY = os.getenv("AIXCC_LITELLM_HOSTNAME") or 'sk-1234'
CLIENT = os.environ.get("AIXCC_LITELLM_HOSTNAME")


AVAILABLE_FUNCTIONS = [{
    "type": "function",
    "function": {
      "name": "get_lines_from_src",
      "description": "Note: Do not pass the datatype of function, for example if you want to call void main(), just pass main() as the function_identifier.\nNote: Global variables cannot be accessed in this function.\n\n# RETURN VALUE: The source code between the specified start and end lines in the src_file_path.",
      "parameters": {
        "type": "object",
        "required": ["src_file_name", "start_line", "end_line"],
        "properties": {
          "src_file_name": {
            "type": "string",
            "description": "The name of the source file to extract the source code from."
          },
          "start_line": {
            "type": "string",
            "description": "The starting line number within the src_file_path to extract."
          },
          "end_line": {
            "type": "string",
            "description": "The ending line number within the send_line to extract."
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "get_function_source",
      "description": "This function retrieves the source code for the specified function from the source file.\nparam function_signature: str, the signature of the function to retrieve the source code for.\nreturn str, the source code for the function or list of most similar signatures.\n\n# RETURN VALUE: None",
      "parameters": {
        "type": "object",
        "required": ["function_signature"],
        "properties": {
          "function_signature": {
            "type": "string",
            "description": ""
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "get_context_and_registers_between_lines",
      "description": "Retrieves context, local variables, and register information for each instruction between the specified start and end lines in the source code.\n\n\n\nNote:\n- INPUT_DATA: Global variable automatically passed, consisting of input data for the program.\n- SRC_ROOT_PATH: Global variable automatically passed, consisting of the path to the root dir.\n- BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.\n\n# RETURN VALUE: A dictionary containing context information for each instruction between the specified start and end lines.",
      "parameters": {
        "type": "object",
        "required": ["start_line", "end_line", "src_file_name"],
        "properties": {
          "start_line": {
            "type": "string",
            "description": "The starting line number within the src code to analyze."
          },
          "end_line": {
            "type": "string",
            "description": "The ending line number within the src code to analyze."
          },
          "src_file_name": {
            "type": "string",
            "description": "The name of the source file to analyze."
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "get_context_and_registers_for_function",
      "description": "This function retrieves a dictionary containing information about the backtrace, local variables, and registers for each instruction in the specified function by performing dynamic execution using GDB.\n\n\n\nNote:\n- INPUT_DATA: Global variable automatically passed, consisting of input data for the program.\n- SRC_ROOT_PATH: Global variable automatically passed, consisting of the path to the root dir.\n- BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.\n\n# RETURN VALUE: A dictionary containing context information for each instruction in the function.",
      "parameters": {
        "type": "object",
        "required": ["function_identifier", "src_file_name"],
        "properties": {
          "function_identifier": {
            "type": "string",
            "description": "The identifier of the function to analyze using gdb. This should include the function signature, e.g., \"functionName(arg1, arg2, ...)\" or \"functionName()\" if no arguments are known."
          },
          "src_file_name": {
            "type": "string",
            "description": "The name of the source file to analyze."
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "set_break_point_and_get_context",
      "description": "Sets a breakpoint at the specified line number in the source code and retrieves the context and registers at that breakpoint.\n\n\nNote:\n- INPUT_DATA: Global variable automatically passed, consisting of input data for the program.\n- SRC_FILE_PATH: Global variable automatically passed, consisting of the path to the source file.\n- BINARY_PATH: Global variable automatically passed, consisting of the path to the binary file.\n\n# RETURN VALUE: A dictionary containing context information at the breakpoint.",
      "parameters": {
        "type": "object",
        "required": ["line_number"],
        "properties": {
          "line_number": {
            "type": "integer",
            "description": "The line number in the source code where the breakpoint should be set."
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "propose_root_cause",
      "description": "param yaml_report: str, yaml report\nThe structure of the yaml_report is as follows:\n{   \"function_name\": \"The name of the function that was the root cause of the crash\",\n\"root_cause\": \"The root cause of the crash, explain the bug in detail\",\n\"root_cause_diff_from_crash_site\": \"Yes/No\",\n\"solution\": \"specific solution to the bug\"\n\"security_vulnerability\": \"Yes/No\"\n\"proposed_patch\": \"The proposed patch to fix the bug, only provide the code snippet that needs to be changed\"\n}\n\n# RETURN VALUE: None",
      "parameters": {
        "type": "object",
        "required": ["yaml_report"],
        "properties": {
          "yaml_report": {
            "type": "string",
            "description": ""
          }
        }
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "finish_task",
      "description": "Call this function once there are no more build errors\n\n# RETURN VALUE: None",
      "parameters": {
        "type": "object",
        "required": [],
        "properties": {}
      }
    }
  }
]

