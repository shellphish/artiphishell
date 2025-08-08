from pathlib import Path
from typing import List, Dict, Tuple, Any
from enum import Enum
import tempfile
import jinja2
import random
import string
import os
import logging

from libcodeql.client import CodeQLClient

from kumushi.code_parsing import CodeFunction
from kumushi.data import PoI, PoICluster

_l = logging.getLogger(__name__)

CODEQL_QUERY_TEMPLATE_DIR = Path(__file__).parent / "codeql_query_templates"
CODEQL_QUERY_DIR = Path(__file__).parent / "codeql_queries"
CODEQL_QUERY_DIR.mkdir(exist_ok=True)


class QueryType(Enum):
    FUNCTION_VARIABLE_ACCESSES = "function_variable_accesses"
    VARIABLE_ACCESSES = "variable_accesses"
    VARIABLE_TAINT = "variable_taint"


class StaticAnalyzer:
    def __init__(self, crash_poi: PoI | None, project_id: str, project_name: str):

        self.crash_poi = crash_poi
        self.project_id = project_id
        self.project_name = project_name
        self.crash_function = self.crash_poi.function if self.crash_poi else None
        self.crash_line = self.crash_poi.crash_line if self.crash_poi else None
        self.critical_variables_from_crash_function = self.crash_poi.critical_variables if self.crash_poi else None
        self.crash_line_num = self.crash_poi.crash_line_num if self.crash_poi else None
        self.clean_query_dir()

    def retrieve_pois(self, lang: str) -> List[str]:
        return self._retrieve_pois(lang = lang)

    def _retrieve_pois(self, lang: str) -> List[str]:
        critical_variables = self.retrieve_critical_variables(lang = lang)
        functions = self.retrieve_variable_accesses(critical_variables, lang = lang)
        return functions

    def run_query(self, query_type: QueryType, template_vars: Dict[str, Any]):
        query_path = self.render_codeql_query(
            CODEQL_QUERY_TEMPLATE_DIR / f"{query_type}.ql.j2",
            **template_vars
        )
        res = self.run_codeql_query(
            query_path = query_path,
        )
        return res
        
    def retrieve_critical_variables(self, lang : str) -> List[Tuple[str, str]]:
        if self.crash_poi is None:
            return []
        if lang.lower() == 'c':
            query_type = QueryType.FUNCTION_VARIABLE_ACCESSES.value

        else:
            query_type = "function_variable_accesses_java"
        function_variable_access_res = self.run_query(
            query_type, {"function_name": self.crash_function.name}
        )
        # Parse the results to get the critical variables
        critical_variables = self.parse_function_variable_accesses(function_variable_access_res)
        assigned_variables = []
        if lang.lower() == 'c':
            query_type = QueryType.VARIABLE_TAINT.value
            for i in critical_variables:
                variable_name = i[0]
                location = i[2]
                tmp_res = self.run_query(
                    query_type, {"variable_name": variable_name, 'location': location}
                )
                assigned_variables.extend(self.parse_variable_taint_results(tmp_res))
        new_critical_variables = [(i[0], i[1]) for i in critical_variables]
        critical_variables = new_critical_variables + assigned_variables
        return critical_variables
    
    def retrieve_variable_accesses(self, critical_variables: List[Tuple[str, str]], lang : str) -> List[str]:
        "[function_name, variable_access_location, variable_access_type]"

        all_functions_list = []
        if lang.lower() == 'c':
            query_type = QueryType.VARIABLE_ACCESSES.value

        else:
            query_type = "variable_accesses_java"
        for variable, variable_type in critical_variables:
            variable_access_res = self.run_query(
                query_type, {"variable_name": variable}
            )
            functions = self.parse_variable_accesses_results(variable_access_res, variable_type)
            if not functions:
                continue
            all_functions_list.append(functions)
        return self.merge_functions(all_functions_list)

    def merge_functions(self, functions: List[List[str]]):
        if not functions:
            return []
        all_functions = set()
        for function_list in functions:
            for function in function_list:
                all_functions.add(function)
        return list(all_functions)

    def parse_variable_accesses_results(self, variable_accesses_res: List, variable_type: str):

        functions = []
        variable_accesses_res = list(variable_accesses_res)
        for row in variable_accesses_res:
            variable_access_type = row['accessType']
            function = row['f']
            if function not in functions and variable_access_type == variable_type:
                functions.append(function)
        return functions

    def parse_function_variable_accesses(self, function_variable_accesses_res: List) -> List[Tuple[str, str, str]]:
        "Each row of the list should be[variable_access, variable_access_type, variable_access_location, variable]"
        critical_variables = []
        seen_variables = []
        for row in function_variable_accesses_res:
            location = row['location']
            variable = row['va']
            variable_type = row['type']
            _, line, _, _, _ = self.parse_codeql_location(location)
            if (variable, variable_type) not in seen_variables and '...' not in variable and int(line) == self.crash_line_num:
                _l.info(f'{variable} {variable_type} {line}')
                critical_variables.append((variable, variable_type, location))
                seen_variables.append((variable, variable_type))
        return critical_variables

    def parse_variable_taint_results(self, variable_taint_res: List) -> List[Tuple[str, str]]:
        variable_taints = []
        for row in variable_taint_res:
            variable = row['fa']
            variable_type = row['type']
            variable_taints.append((variable, variable_type))
        return variable_taints
    
    def parse_codeql_location(self, location: str):
        location_parts = location.split(":")
        filepath = location_parts[1][7:]
        start_line = location_parts[2]
        offset_start = location_parts[3]
        end_line = location_parts[4]
        offset_end = location_parts[5]
        return filepath, start_line, offset_start, end_line, offset_end

    def render_codeql_query(
            self, 
            template_path: Path, 
            variable_name: str = None, 
            function_name: str = None,
            location: str = None,
            ):
        """
        Render a Jinja2 template with given variables.
        
        Args:
            template_path (str): Path to the template file relative to template_dir
            variable_name (str): Name of the variable to be used in the template
            function_name (str): Name of the function to be used in the template
        
        Returns:
            Path: Path to the rendered query file
        """
        if not variable_name and not function_name:
            raise ValueError("At least one of variable_name or function_name must be provided")
        with open(template_path, "r") as f:
            template = jinja2.Template(f.read())
        template_vars = {}
        if variable_name:
            template_vars["variable_name"] = variable_name
        if function_name:
            template_vars["function_name"] = function_name
        if location:
            template_vars["location"] = location
        # Render the template with variables
        query = template.render(**template_vars)
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

        query_path = CODEQL_QUERY_DIR / Path(random_name).with_suffix(".ql")
        with open(query_path, "w") as f:
            f.write(query) 
        return query_path
            

    def run_codeql_query(self, query_path: Path) -> list[dict]:
        client = CodeQLClient()
        with open(query_path, "r") as f:
            query = f.read()
        result = client.query({
            "cp_name": self.project_name,
            "project_id": self.project_id,
            "query": query
        })
        _l.info(f"CodeQL query result length : {len(result)}")

        return result

    def clean_query_dir(self):
        for file in CODEQL_QUERY_DIR.iterdir():
            if str(file).endswith(".ql"):
                os.remove(CODEQL_QUERY_DIR / file)
        