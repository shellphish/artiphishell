from collections import namedtuple
import functools
import inspect
import json
import traceback
import typing

import yaml
# import openai
from rich import print
from difflib import SequenceMatcher
import os
import re

FUNCTIONS = None

def recursively_get_all_files(directory):
    """
    Take directory as argument, then get all the files present in that directory, if the file is a directory then call this function recursively, if the file is a file, then store its path in a list.
    """
    all_file_paths = set()
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        if os.path.isdir(file_path):
            all_paths = recursively_get_all_files(file_path)
            all_file_paths = all_file_paths.union(all_paths)
        else:
            all_file_paths.add(file_path)
    return list(all_file_paths)

"""
This function also takes care of macros
"""
def generate_function_list(functions_dir):
    """
    Take the functions directory as input, and then generate the list of functions present in the directory.
    """
    global FUNCTIONS
    print("fetching all the files in the functions directory")
    all_files = recursively_get_all_files(functions_dir)
    print("all files fetched, total files: {} ✅".format(len(all_files)))
    print("generating function dictionary")
    functions = {}
    for file_name in all_files:
        with open(file_name, "r") as my_file:
            file_data = json.load(my_file)
            """
            sample_file_data = {'hash': '083f13eeac12a196a58721e7169d33c4',
                                'code': '#define ngx_align_ptr(p, a)                                                   \\\n    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))\n',
                                'signature': 'ngx_align_ptr(p,a)',
                                'filename': 'ngx_config.h',
                                'cfg': '',
                                'start_line': 101,
                                'start_column': 9,
                                'start_offset': 1835,
                                'end_line': 102,
                                'end_column': 80,
                                'end_offset': 1986,
                                'global_variables': [],
                                'local_variables': [],
                                'func_return_type': '',
                                'arguments': [],
                                'filepath': 'nginx/src/core/ngx_config.h',
                                'funcname': 'ngx_align_ptr',
                                'full_funcname': 'ngx_align_ptr',
                                'func_calls_in_func_with_fullname': [],
                                'comments': []}
            """
            signature = file_data["funcname"]
            if signature:
                functions[signature] = file_data
    FUNCTIONS = functions
    print("function dictionary generated ✅")
    return 0
    
def fetch_function_source_using_file_path(function_signature, file_path, line_number=None):
    """
    Tries to get the function source code using the file path and line number, when the function signature is not found in the FUNCTIONS global variable
    params function_signature: the function signature
    params file_path: the file path where the function is present
    params line_number: the line number where the function is present
    
    return: the function source code, or error  
    """
    
    
    with open(file_path, "r") as file:
        lines = file.readlines()
        function_start_line = 0
        function_end_line = 0
        
def convert_python_dictionary_to_string(dictionary):
    """
    This function converts a python dictionary to a string, it should also handle nested dictionary structure (using recursive calls), with proper indentation.
    """
    string = ""
    for key, value in dictionary.items():
        if isinstance(value, dict):
            string += f"{key}:\n"
            string += convert_python_dictionary_to_string(value)
        else:
            string += f"{key}: {value}\n"
    return string


def fetch_function_source_using_signature(function_signature, line_number=None, file_path=None):
    """
    This function is used to fetch the function source code using the function signature
    """
    
    global FUNCTIONS
    if FUNCTIONS is None:
        print("FUNCTIONS global variable is not set, please set it by calling the generate_function_list function")
        return {"error": "Function signature not found in the FUNCTIONS global variable"}
    if function_signature in FUNCTIONS:
        function_return_dict = {"code": FUNCTIONS[function_signature]["code"], "filepath": FUNCTIONS[function_signature]["filepath"], "start_line": FUNCTIONS[function_signature]["start_line"], "end_line": FUNCTIONS[function_signature]["end_line"]}
        return function_return_dict
    else:
        print("Function signature not found in the FUNCTIONS global variable ❌")
        if file_path is not None and line_number is not None:
            print("Trying to fetch the function source code using the file path and line number...")
            
            if "(" in function_signature:
                function_signature = function_signature.split("(")[0]
            
            #function_source = fetch_function_source_using_file_path(function_signature, file_path, line_number)
            
            # We have the file path, so we can use that to get the function source code
            return function_source
        return {"error": "Function signature not found in the FUNCTIONS global variable"}

    

def convert_python_dict_to_text(dictionary, out=""):
    # We convert dict with keys to text. Each key will be new line, if the value consits of next dictionary then the key for that will be indented
   
    for key, value in dictionary.items():
        if isinstance(value, dict):
            out += f"{key}:\n"
            out = convert_python_dict_to_text(value, out)
        else:
            out += f"{key}: {value}\n"
    return out

def format_srcdict_to_str(src_dict, function_name):
    """
    This function is used to convert the dictionary to source code
    """
    start_line = src_dict["start_line"]
    end_line = src_dict["end_line"]
    code = src_dict["code"]
    src_code = ""
    # adding line_number next to each line
    if len(code.split("\n")) -1 == (end_line - start_line + 1):
        all_lines = code.split("\n")
        all_lines = all_lines[0:-1]
        for idx, line in enumerate(all_lines):
            src_code += f"{start_line + idx}: {line}\n"
    else:
        src_code = code

    return_string = f"##FILE_PATH: {src_dict['filepath']}\n"
    return_string += f"##FUNCTION_NAME: {function_name}\n"
    return_string += f"##START_LINE: {src_dict['start_line']}\n"
    return_string += f"##ENDLINE: {src_dict['end_line']}\n\n"
    return_string += f"##CODE:\n{src_code}"
    return return_string



def get_most_similar_function_signature(function_signature):
    """
    This function is used when the function signautre provided by the model does not match any exitsing function signature in the FUNCTIONS global variable,
    So this function tries to identify the most similar function signature from the FUNCTIONS global variable, to help the LLM
    NOTE:FUNCTIONS (the global dictionary), is already generated by the generate_function_list function
    return: 5 most similar function signatures
    """
    global FUNCTIONS
    similar_functions = []
    for function in FUNCTIONS:
        if function_signature in function:
            similarity = SequenceMatcher(None, function_signature, function ).ratio()
            similar_functions.append((function, similarity))
        else:
            continue
    similar_functions.sort(key=lambda x: x[1], reverse=True)
    five_most_similar_functions = similar_functions[:5]
    # now we get the filepath of these functions
    similar_functions_dict = {}

    for function, similarity in five_most_similar_functions:
        similar_functions_dict[function] = {"file_path": FUNCTIONS[function]["filepath"], "function_name": function}
    return similar_functions_dict


def extract_stack_trace_from_poi(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)

    # Extract the stack trace
    #stack_trace = data.get('additional_information', {}).get('asan_report_data', {}).get('stack_traces', {}).get('allocate', [])
    stack_trace = data.get('stack_traces', [])
    # Filter the stack trace until '/src/' is not present in 'src_file' key
    filtered_trace = []
    crashing_function_name = None
    crashing_function_relative_path = None
    idx = 0
    crashing_location = None
    for trace in stack_trace[0]['call_locations']:
        if trace['key_index']:
            filtered_trace.append(trace)
            if crashing_function_name is None:
                crashing_function_name = trace['function_name']
                crashing_function_relative_path = trace['relative_file_path']
                crashing_location = trace['line_number']
            idx += 1
        else:
            if idx == 0:
                filtered_trace.append(trace)
                idx += 1
            else:
                break
    # Extract the crashing function and its path from the filtered trace
    return crashing_function_name, crashing_function_relative_path, crashing_location, filtered_trace


def parse_doc(doc: str):
    param_docs = {}
    return_doc = None
    real_doc = ''

    if not doc:
        return param_docs, return_doc, real_doc

    for line in doc.split('\n'):
        line = line.strip()
        if line.startswith(':param'):
            line = line[6:].strip()
            param_name, param_doc = line.split(':', maxsplit=1)
            param_docs[param_name.strip()] = param_doc.strip()
        elif line.startswith(':return:'):
            line = line[8:].strip()
            return_doc = line.strip()
        else:
            real_doc += line + '\n'

    return param_docs, return_doc, real_doc.strip()

def type_annotation_to_json_schema(type_annotation):
    if type_annotation is str:
        return {"type": "string"}
    elif type_annotation is int:
        return {"type": "integer"}
    elif type_annotation is float:
        return {"type": "number"}
    elif type_annotation is bool:
        return {"type": "boolean"}
    elif type_annotation is None:
        return {"type": "null"}

    # now handle the types from `typing`
    origin_type = typing.get_origin(type_annotation)
    if origin_type is None:
        raise ValueError(f"unsupported type annotation: {type_annotation}")

    if origin_type is dict:
        key_type, value_type = typing.get_args(type_annotation)
        assert key_type is str, f"unsupported type annotation for a JSON schema: {type_annotation}"
        return {
            "type": "object",
            "additionalProperties": type_annotation_to_json_schema(value_type),
        }
    elif origin_type is list:
        value_type, = typing.get_args(type_annotation)
        return {
            "type": "array",
            "items": type_annotation_to_json_schema(value_type),
        }
    else:
        raise ValueError(f"unsupported type annotation: {type_annotation}")


ChatGPTFunctionMetadata = namedtuple('ChatGPTFunctionMetadata', ['name', 'arg_names', 'kwarg_names'])
ChatGPTFunction = namedtuple('ChatGPTFunction', ['schema', 'metadata', 'function'])
__CHATGPT_FUNCTIONS = []

def chatgpt_function(function):
    '''
    A decorator that takes a python function and exposes it to the chatgpt engine.

    An example of such a translation is that a function like this:
    ```
    def get_function_source(name=None):
        """
        Returns the C source code for the function named `name`. Returns None if the function is unknown or a builtin with known semantics.

        :param name: The name of the function to return the source code for.
        :return: source code for `name` or None if not found.
        """
        return FUNCTIONS.get(name, None)
    ```

    would be translated to this:
    ```
    functions.append({
        "name": "get_function_source",
        "description": "Returns the C source code for the function named `name`. Returns None if the function is unknown or a builtin with known semantics.\n# RETURN VALUE: source code for `name` or None if not found.",

        # json schema for parameters
        "parameters": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name of the function to return the source code for.",
                },
            },
        },
    })
    ```
    '''

    if type(function) is functools.partial:
        # code = function.func.__code__
        fname = function.func.__name__
        argcount = function.func.__code__.co_argcount
        varnames = function.func.__code__.co_varnames[:argcount][len(function.args):]
        code_flags = function.func.__code__.co_flags
        annotations = function.func.__annotations__
        defaults = function.func.__defaults__ # strip the partial'ed args
        func_doc = function.func.__doc__
    else:
        # code = function.__code__
        fname = function.__name__
        argcount = function.__code__.co_argcount
        varnames = function.__code__.co_varnames[:argcount]
        code_flags = function.__code__.co_flags
        annotations = function.__annotations__
        defaults = function.__defaults__
        func_doc = function.__doc__

    args = varnames
    if args and args[0] == 'self':
        args = args[1:]
    # we don't support *args or **kwargs
    assert code_flags & (inspect.CO_VARARGS) == 0, f"unsupported function signature: *args in {fname}"
    # assert code_flags & inspect.CO_VARKEYWORDS != 0, f"must handle **kwargs in {fname}"
    arg_types = annotations
    defaults = defaults or []
    if len(defaults) > 0:
        args, kwargs = args[:-len(defaults)], args[-len(defaults):]
    else:
        args = args
        kwargs = []

    param_docs, return_doc, function_doc = parse_doc(func_doc)
    required_args = args

    properties = {}

    for arg in args:
        arg_type = arg_types.get(arg, str)
        arg_doc = param_docs.get(arg, '')
        property = type_annotation_to_json_schema(arg_type)
        property['description'] = arg_doc
        properties[arg] = property

    for kwarg, default in zip(kwargs, defaults):
        kwarg_type = arg_types.get(kwarg, str)
        kwarg_doc = param_docs.get(kwarg, '')
        property = type_annotation_to_json_schema(kwarg_type)
        property['description'] = kwarg_doc + f"\n\n# DEFAULT: {default!r}"
        properties[kwarg] = property

    func_schema = {
        "type": "function",
        "function": {
            "name": fname,
            "description": f"{function_doc}\n\n# RETURN VALUE: {return_doc}",
            "parameters": {
                "type": "object",
                "required": args,
                "properties": properties,
            },
        }
    }

    # func_schema = {
        
    #         "name": fname,
    #         "description": f"{function_doc}\n\n# RETURN VALUE: {return_doc}",
    #         "parameters": {
    #             "type": "object",
    #             "required": args,
    #             "properties": properties,
    #         },
    # }
    chatgpt_function_metadata = ChatGPTFunctionMetadata(fname, args, kwargs)
    chatgpt_function = ChatGPTFunction(func_schema, chatgpt_function_metadata, function)
    __CHATGPT_FUNCTIONS.append(chatgpt_function)

    function.__chatgpt_metadata__ = chatgpt_function_metadata
    function.__chatgpt_schema__ = func_schema
    function.__chatgpt_function__ = chatgpt_function

    return function

def get_chatgpt_function_schema(decorated_funcs_to_use):
    return [func.__chatgpt_schema__ for func in decorated_funcs_to_use]

def get_function_call_result_message(tool_call_id, function_name, success, res, message_id):
    return dict(
        role='tool',
        tool_call_id=tool_call_id,
        name = res.pop('name', function_name),
        content = f'# TOOL RETURNED {"SUCCESS" if success else "ERROR"}\n\n' + json.dumps(res, indent=2),
        message_id = message_id
    )

def call_chatgpt_function(function_name, arguments, prompt_for_confirmation=True, available_functions=None):
    if available_functions is None:
        available_functions = [cgptf.function for cgptf in __CHATGPT_FUNCTIONS]
    for func in available_functions:
        if func.__chatgpt_metadata__.name == function_name:
            break
    else:
        return False, {
            'called_function': function_name,
            'called_arguments': arguments,
            'error': f"ERROR: Unknown function {function_name!r}",
            'hints': {
                'available_functions': [f.__chatgpt_metadata__.name for f in available_functions],
            },
        }

    # check if the arguments are valid
    try:
        arguments = json.loads(arguments)
    except json.JSONDecodeError as e:
        bt = traceback.format_exc()
        return False, {
            'call': {
                'function': function_name,
                'arguments': arguments,
            },
            'error': {
                'description': f'Invalid JSON in the function arguments: {e}',
            }
        }

    schema = func.__chatgpt_schema__
    func_name, arg_names, kwarg_names = func.__chatgpt_metadata__

    # check if the arguments are valid
    for arg in arg_names:
        if arg not in arguments:
            return False, {
                'call': {
                    'function': function_name,
                    'arguments': arguments,
                },
                'error': {
                    'description': f"ERROR: Missing required argument {arg!r} for function {func_name!r}",
                    'hints': {
                        'required_arguments': arg_names,
                    },
                }
            }

    for arg in arguments:
        if arg not in arg_names and arg not in kwarg_names:
            return False, {
                'call': {
                    'function': function_name,
                    'arguments': arguments,
                },
                'error': {
                    'description': f"ERROR: Unknown argument {arg!r} for function {func_name!r}",
                    'hints': {
                        'available_arguments': arg_names + kwarg_names
                    },
                }
            }

    try:
        args = [arguments[arg] for arg in arg_names]
        kwargs = {arg: arguments[arg] for arg in kwarg_names}
        if prompt_for_confirmation:
            # ask the user if this function call should be allowed
            prompt = f"Call function [bold]{func_name}[/bold] with arguments [bold]{args}[/bold] and keyword arguments [bold]{kwargs}[/bold]"
            print(prompt)

            while input("[y/n]? ").lower() != 'y':
                pass
        result = func(*args, **kwargs)
    except KeyboardInterrupt:
        return False, {
            'call': {
                'function': function_name,
                'arguments': arguments,
            },
            'error': {
                'description': f"ERROR: User did not allow the function call.",
            }
        }
    except Exception as e:
        bt = traceback.format_tb(e.__traceback__)
        return False, {
            'name': func_name,
            'call': {
                'function': function_name,
                'arguments': arguments,
            },
            'error': {
                'description': str(e),
                'hints': {
                    'traceback': bt,
                },
            }
        }

    # do the json encoding out here, because JSON encoding errors are an application bug and SHOULD propagate out to the user
    return True, {
        'name': func_name,
        'call': {
            'function': function_name,
            'arguments': arguments,
        },
        'result': result
    }

