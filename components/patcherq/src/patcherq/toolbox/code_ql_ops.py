
import logging
from functools import wraps

from agentlib.lib import tools
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from libcodeql.client import CodeQLClient
from jinja2 import Environment, FileSystemLoader
from .peek_utils import *
from .peek_utils import *

import yaml
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

GlobalCodeQlSkill = None

CODEQL_DOWN = False

def robust_run(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global CODEQL_DOWN
        if CODEQL_DOWN:
            return tool_error("This toolcall is down for maintenance, do not use it again")
        try:
            return func(*args, **kwargs)
        except:
            CODEQL_DOWN = True
            return tool_error("This toolcall is down for maintenance, do not use it again")
    return wrapper

@tools.tool
def get_function_callers(function_name: str) -> str:
    """
    This tool returns 10 callers of the given function name.
    output format is a list of <CallerID><Filename>:<Funcname>, every entry is a valid caller.
    
    :param function_name: The name of the function you want to get the callers for.
    :return: a string containing the call locations of the function or an error message if the function is not found.
    """
    global GlobalCodeQlSkill
    return GlobalCodeQlSkill.get_function_callers(function_name)

@tools.tool
def get_struct_definition(structure_name: str) -> str:
    """
    Retrive the definition of the given structure name using CodeQL.
    This function can be used to search for the definition of a specific structure in the codebase.
    output format is struct <structure_name> { <structure_definition> };

    :param structure_name: The name of the structure to search for.
    :return: string containing the definition of the structure or an error message if the structure is not found.
    """
    global GlobalCodeQlSkill
    return GlobalCodeQlSkill.get_struct_definition(structure_name)

@tools.tool
def get_struct_definition_location(structure_name: str) -> str:
    """
    Retrive the location of the given structure/class in the source code.

    :param structure_name: The name of the structure/class to search for.
    :return: string containing the relative path to the file with the structure definition.
    """
    global GlobalCodeQlSkill
    return GlobalCodeQlSkill.get_struct_definition_location(structure_name)

@tools.tool
def get_function_definition_location(function_name: str) -> str:
    """
    Retrive the location of the definition of given function in the source code.

    :param function_name: The name of the function to search for.
    :return: string containing the relative path to the file with the function definition.
    """
    global GlobalCodeQlSkill
    return GlobalCodeQlSkill.get_function_definition_location(function_name)

class CodeQlSkill:
    """
    A class to handle CodeQl operations.
    """
    def __init__(self, function_resolver=None, **kwargs):
        # If this is a LOCAL_RUN, we have to setup the codeql db
        # ourselves, otherwise, that is available during CRS execution.
        self.initialized = False
        
        self.local_run = kwargs.get('local_run', None)
        # If this happens, something went terribly wrong
        assert(self.local_run is not None)
        
        with open(kwargs['project_yaml'], "r") as f:
            project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        
        self.project_name = project_metadata.shellphish_project_name
        self.project_language = project_metadata.language.value
        self.project_id = kwargs.get('project_id', None)

        self.func_resolver = function_resolver
        assert(self.func_resolver is not None)
        
        if self.project_language.lower() in ('c++', 'c', 'cpp'):
            self.project_language = 'c'
        else:
            self.project_language = 'java'
        
        self.client = None
        if self.local_run:
           
            codeql_db_path = kwargs.get('codeql_db_path', None)
            if codeql_db_path is None:
                raise ValueError("codeql_db_path is not found ❌")  
            self.client = CodeQLClient()
            print("Uploading codeql db 🚀")
            # We are uploading the codeql server ourselves
            try:
                self.client.upload_db(self.project_name, self.project_id, self.project_language, codeql_db_path)
                print("Codeql db uploaded successfully 🎉")
            except Exception as e:
                
                if 'already exists' in str(e.args):
                    print("Codeql db already exists, skipping upload")
                else:
                    print("Error uploading codeql db ❌")
                    print(f"Error uploading codeql db: {e}")
                    raise ValueError("codeql_db_path is not found ❌")
            
        else:
            self.client = CodeQLClient()

        if self.project_language == 'c':
            self.jinja_env = Environment(loader=FileSystemLoader('/src/patcherq/toolbox/templates/codeQL/c'))
        else:
            self.jinja_env = Environment(loader=FileSystemLoader('/src/patcherq/toolbox/templates/codeQL/java'))
        self.initialized = True

        self.codeql_results_cache = {}
        
        # Finally, setting the global variable
        global GlobalCodeQlSkill
        GlobalCodeQlSkill = self
        
    @robust_run
    def get_struct_definition(self, structure_name: str) -> str:

        # NOTE: check if we already ran this codeQL query
        if 'get_struct_definition' not in self.codeql_results_cache:
            # This means we never executed this tool call at all
            self.codeql_results_cache['get_struct_definition'] = {}
            self.codeql_results_cache['get_struct_definition'][structure_name] = None
        else:
            if self.codeql_results_cache['get_struct_definition'].get(structure_name, None) is not None:
                # If we already have the results for this exact function query we return them
                return self.codeql_results_cache['get_struct_definition'][structure_name]
            else:
                # Otherwise let's prepare the dict 
                self.codeql_results_cache['get_struct_definition'][structure_name] = None

        # Fetching Jinja query template
        structure_def_template = self.jinja_env.get_template('get_struct_definition.j2')
        # Render the template with the given variable
        rendered_query = structure_def_template.render(struct_name=structure_name)
        # Running the query
        struct_def_result = self.client.query({"cp_name":self.project_name, "project_id":self.project_id, "query":rendered_query})
        if struct_def_result:
            print("SUCCESS: Struct definition found: {}".format(struct_def_result))
            message = "struct " + struct_def_result[0]["structType"] + "{" + "\n\t" + "\n\t".join(entry['col2'] for entry in struct_def_result) + "\n" + "};"
            message = tool_success(message)
            return message
        else:
            # If the struct definition is not found, we check if the struct is a typedef
            print("ERROR: Struct definition not found")
            message = "No struct definition found for {}".format(structure_name)
            typedef_template = self.jinja_env.get_template('get_typedef_definition.j2')
            rendered_query = typedef_template.render(typedef_name=structure_name)
            typedef_result = self.client.query({"cp_name":self.project_name, "project_id":self.project_id, "query":rendered_query})
            if typedef_result:
                # If the typedef is found, we return the typedef name and the underlying type
                typedef_name = typedef_result[0]["col1"] 
                underlying_type = typedef_result[0]["col2"]
                message = f"{typedef_name} is not a structure, rather a typedef for {underlying_type}. To get the definition of {underlying_type}, call get_struct_definition('{underlying_type}')."
                return tool_error(message)
                
            else:
                # If the typedef is not found, we return an error message
                return tool_error("{} is not a structure, nor a typedef. Please check the name".format(structure_name))
      
    @robust_run        
    def get_struct_definition_location(self, structure_name: str) -> str:
        
        # NOTE: check if we already ran this codeQL query
        if 'get_struct_definition_location' not in self.codeql_results_cache:
            # This means we never executed this tool call at all
            self.codeql_results_cache['get_struct_definition_location'] = {}
            self.codeql_results_cache['get_struct_definition_location'][structure_name] = None
        else:
            if self.codeql_results_cache['get_struct_definition_location'].get(structure_name, None) is not None:
                # If we already have the results for this exact function query we return them
                return self.codeql_results_cache['get_struct_definition_location'][structure_name]
            else:
                # Otherwise let's prepare the dict 
                self.codeql_results_cache['get_struct_definition_location'][structure_name] = None

        # Fetching Jinja query template
        structure_def_template = self.jinja_env.get_template('get_struct_definition_location.j2')
        # Render the template with the given variable
        rendered_query = structure_def_template.render(struct_name=structure_name)
        # Running the query
        struct_loc_results = self.client.query({"cp_name":self.project_name, "project_id":self.project_id, "query":rendered_query})
        
        if struct_loc_results:
            print(f"📍 Struct definition location found: {struct_loc_results}")

            files_in_scope = []

            # NOTE: we can have multiple results
            for struct_loc_result in struct_loc_results:
                codeql_filename_res = struct_loc_result['filename']
                codeql_startline_res = struct_loc_result['startline']
                # NOTE: validating the result with the func resolver
                # FIXME: in the future, there will be an option that automatically resolve 
                #        the filename to something in the focus repo if it exists.
                maybe_keys_in_scope = self.func_resolver.find_by_filename(codeql_filename_res)
                for maybe_key_in_scope in maybe_keys_in_scope:
                    # Is this in the focus repo?
                    maybe_key_full_info = self.func_resolver.get(maybe_key_in_scope)
                    
                    if maybe_key_full_info.focus_repo_relative_path:
                        files_in_scope.append((maybe_key_full_info.focus_repo_relative_path, codeql_startline_res))
                        # We know this file is in scope because it has a valid func in scope!
                        break
                    else:
                        logger.info(" The file %s is not in the focus repo, skipping...", maybe_key_full_info.focus_repo_relative_path)
                        # Go to the next filename
                        continue

            if len(files_in_scope) == 0:
                message = tool_error("The struct is apparently defined in a file that is not in scope. Try something else.")
                self.codeql_results_cache['get_struct_definition_location'][structure_name] = message
                return message
            else:
                message = f"The struct {structure_name} is defined in the following files:\n"
                for file_id, file_in_scope in enumerate(files_in_scope):
                    message += f"File-{file_id+1}: {file_in_scope[0]} Start Line: {file_in_scope[1]}\n"
            message = tool_success(message)
            self.codeql_results_cache['get_struct_definition_location'][structure_name] = message
            return message
        else:
            message = tool_error(f"The struct {structure_name} is not a structure or a typedef. Please check the name")
            self.codeql_results_cache['get_struct_definition_location'][structure_name] = message
            return message
    
    @robust_run    
    def get_function_definition_location(self, function_name: str) -> str:
        
        # NOTE: check if we already ran this codeQL query
        if 'get_function_definition_location' not in self.codeql_results_cache:
            # This means we never executed this tool call at all
            self.codeql_results_cache['get_function_definition_location'] = {}
            self.codeql_results_cache['get_function_definition_location'][function_name] = None
        else:
            if self.codeql_results_cache['get_function_definition_location'].get(function_name, None) is not None:
                # If we already have the results for this exact function query we return them
                return self.codeql_results_cache['get_function_definition_location'][function_name]
            else:
                # Otherwise let's prepare the dict 
                self.codeql_results_cache['get_function_definition_location'][function_name] = None

        # Fetching Jinja query template
        function_def_template = self.jinja_env.get_template('get_function_definition_location.j2')
        # Render the template with the given variable
        rendered_query = function_def_template.render(function_name=function_name)
        # Running the query
        function_loc_results = self.client.query({"cp_name":self.project_name, "project_id":self.project_id, "query":rendered_query})
        
        if function_loc_results:
            print(f"📍 function definition location found: {function_loc_results}")

            files_in_scope = []

            # NOTE: we can have multiple results
            for function_loc_result in function_loc_results:
                codeql_filename_res = function_loc_result['filename']
                codeql_startline_res = function_loc_result['startline']
                # NOTE: validating the result with the func resolver
                # FIXME: in the future, there will be an option that automatically resolve 
                #        the filename to something in the focus repo if it exists.
                maybe_keys_in_scope = self.func_resolver.find_by_filename(codeql_filename_res)
                for maybe_key_in_scope in maybe_keys_in_scope:
                    # Is this in the focus repo?
                    maybe_key_full_info = self.func_resolver.get(maybe_key_in_scope)
                    
                    if maybe_key_full_info.focus_repo_relative_path:
                        files_in_scope.append((maybe_key_full_info.focus_repo_relative_path, codeql_startline_res))
                        # We know this file is in scope because it has a valid func in scope!
                        break
                    else:
                        logger.info(" The file %s is not in the focus repo, skipping...", maybe_key_full_info.focus_repo_relative_path)
                        # Go to the next filename
                        continue

            if len(files_in_scope) == 0:
                message = tool_error("The function is apparently defined in a file that is not in scope. Try something else.")
                self.codeql_results_cache['get_function_definition_location'][function_name] = message
                return message
            else:
                message = f"The function {function_name} is defined in the following files:\n"
                for file_id, file_in_scope in enumerate(files_in_scope):
                    message += f"File-{file_id+1}: {file_in_scope[0]} Start Line: {file_in_scope[1]}\n"
            message = tool_success(message)
            self.codeql_results_cache['get_function_definition_location'][function_name] = message
            return message
        else:
            message = tool_error(f"{function_name} is not a function. Please check the name")
            self.codeql_results_cache['get_function_definition_location'][function_name] = message
            return message

    @robust_run
    def get_function_callers(self, function_name: str) -> str:
        """
        :param function_name: The name of the function to search for.
        """
        
        # NOTE: check if we already ran this codeQL query
        if 'get_function_callers' not in self.codeql_results_cache:
            # This means we never executed this tool call at all
            self.codeql_results_cache['get_function_callers'] = {}
            self.codeql_results_cache['get_function_callers'][function_name] = None
        else:
            if self.codeql_results_cache['get_function_callers'].get(function_name, None) is not None:
                # If we already have the results for this exact function query we return them
                return self.codeql_results_cache['get_function_callers'][function_name]
            else:
                # Otherwise let's prepare the dict 
                self.codeql_results_cache['get_function_callers'][function_name] = None

        ###############################
        # NOTE: preparing the query! 🙋‍♂️
        ###############################

        # Fetching Jinja query template
        template = self.jinja_env.get_template('get_callers.j2')
        # Render the template with the given variable
        rendered_query = template.render(function_name=function_name)
        # Running the query
        codeql_results = self.client.query({"cp_name":self.project_name, "project_id":self.project_id, "query":rendered_query})
        
        if codeql_results:
            codeql_results = codeql_results[:10]
            
            function_callers = ""
            # NOTE: The result's structure has this format:
            # {
            #     'call': 'call to ngx_mail_pop3_user',
            #     'func': 'ngx_mail_pop3_auth_state',
            #     'col2': 'file:///src/harnesses/bld/src/mail/ngx_mail_pop3_handler.c:183:22:183:39',
            #     'col3': 'Call to ngx_mail_pop3_user found in function ngx_mail_pop3_auth_state.'
            # }
            # 'func' is the caller
            callers_in_scope = []
            for result_id, codeql_result in enumerate(codeql_results):
                caller_func = codeql_result['func']
                # Resolve this with the function resolver
                maybe_callers_in_scope = self.func_resolver.find_by_funcname(caller_func)
                for maybe_caller in maybe_callers_in_scope:
                    maybe_caller_full_info = self.func_resolver.get(maybe_caller)
                    # Is this in the focus repo?
                    if maybe_caller_full_info.focus_repo_relative_path:
                        callers_in_scope.append(maybe_caller_full_info)
                    else:
                        # Go to the next caller
                        continue
            
            if len(callers_in_scope) == 0:
                res = tool_error(f'There are no callers in scope for the function {function_name}.\n')
                self.codeql_results_cache['get_function_callers'][function_name] = res
                return res
            else:
                res = "CallerID:Filename:Funcname\n"
                for caller_id, caller_in_scope in enumerate(callers_in_scope):
                    res += f"Caller-{caller_id+1}:{caller_in_scope.focus_repo_relative_path}:{caller_in_scope.funcname}\n"
                res = tool_success(res)
                self.codeql_results_cache['get_function_callers'][function_name] = res
                return res
        else:
            # If the function is not found, we return an error message
            res = tool_error(f'The CodeQL query for function callers returned no results. You MUST avoid this.')
            self.codeql_results_cache['get_function_callers'][function_name] = res
            return res


CODEQL_TOOLS = {
    "get_function_callers": get_function_callers,
    "get_struct_definition_location": get_struct_definition_location,
}
