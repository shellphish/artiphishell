

from typing import List, Dict, Tuple, Union

class PointOfInterest:
    def __init__(self, vuln, file, func, start_line, end_line="X", extra_info=None):
        self.vuln = vuln
        self.file = file
        self.func = func
        self.start_line = start_line
        self.end_line = end_line
        self.extra_info = extra_info


    def __repr__(self):
        return (f"PointOfInterest(vuln={self.vuln}, file={self.file}, "
                f"function={self.function_name}, start_line={self.start_line}, "
                f"end_line={self.end_line}, extra_info={self.extra_info})")
    


class SarifResult:
    def __init__(self, rule_id):
        # The raw SARIF result (might contain interesting data like a message)
        self.sarif_raw_result = ''
        # The actual rule that was triggered
        self.rule_id = rule_id
        # An extra message 
        self.message = ''
        # List of files in scope
        self.files = []
        # This is a list of function names and line numbers
        # e.g., ngx_alloc:123
        self.func_loc =  []
        # List of code flows as extracted from the SARIF file.
        # e.g., ['ngx_alloc:123->ngx_alloc:456']
        self.dataflows = []
        # These are the sinks mentioned in the locations 
        self.sinks = []


    def add_raw_result(self, sarif_raw_result):
        self.sarif_raw_result = sarif_raw_result

    def add_message(self, message):
        self.message = message

    def add_file(self, file_name):
        if file_name not in self.files:
            self.files.append(file_name)
    
    def add_func_loc(self, func_loc):
        if func_loc not in self.func_loc:
            self.func_loc.append(func_loc)

    def add_sink(self, func):
        if func not in self.sinks:
            self.sinks.append(func)

    def add_dataflow(self, dataflow):
        if dataflow not in self.dataflows:
            self.dataflows.append(dataflow)
    
    def __repr__(self):
        return (f"SarifResult(rule_id={self.rule_id}, files={self.files}, "
                f"func_loc={self.func_loc}, dataflow={self.dataflows}), sarif_raw_result={self.sarif_raw_result}")