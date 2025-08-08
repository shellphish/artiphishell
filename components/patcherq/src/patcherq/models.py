
'''
Some of the classes that are used to represent the data that is passed between 
the different components of the system.
'''

import hashlib
from shellphish_crs_utils.models.crs_reports import PoVReport

class FailedPatch:
    def __init__(self, key, diff):
        self.key = key
        self.diff = diff
    
    def __repr__(self):
        return f'FailedPatch(key={self.key}, diff={self.diff})' 

class MitigatedPovReport:
    def __init__(self, pov_report: PoVReport, crashing_input_hex: str, crashing_input_hash: str):
        # NOTE: the crashing_input_hex is the content_hex of the input that caused the crash
        self.pov_report = pov_report
        self.crashing_input_hex = crashing_input_hex
        self.crashing_input_hash = crashing_input_hash

        # Save the crashing input in a temporary file
        data_bytes = bytes.fromhex(self.crashing_input_hex)
        temp_file_path = f'/tmp/crashing_input_{self.crashing_input_hash}.bin'
        with open(temp_file_path, 'wb') as f:
            f.write(data_bytes)

        # Verify if the md5 matches
        with open(temp_file_path, 'rb') as f:
            content = f.read()
            if hashlib.sha256(content).hexdigest() != self.crashing_input_hash:
                raise ValueError(f'Crashing input Hash mismatch: {hashlib.sha256(content).hexdigest()} != {self.crashing_input_hash}!?!?!?')

        self.crashing_input_path = temp_file_path
    
    def __repr__(self):
        return f'MitigatedPovReport(pov_report={self.pov_report}, crashing_input_hex={self.crashing_input_hex}, crashing_input_hash={self.crashing_input_hash})'

class CrashingInput:
    def __init__(self, 
                 crashing_input_hex:str, 
                 crashing_input_hash:str,
                 ):
        self.crashing_input_hex = crashing_input_hex
        self.crashing_input_hash = crashing_input_hash

        # Save the crashing input in a temporary file
        data_bytes = bytes.fromhex(self.crashing_input_hex)
        temp_file_path = f'/tmp/crashing_input_{self.crashing_input_hash}.bin'
        with open(temp_file_path, 'wb') as f:
            f.write(data_bytes)

        # Verify if the md5 matches
        with open(temp_file_path, 'rb') as f:
            content = f.read()
            if hashlib.sha256(content).hexdigest() != self.crashing_input_hash:
                raise ValueError(f'Crashing input Hash mismatch: {hashlib.sha256(content).hexdigest()} != {self.crashing_input_hash}!?!?!?')

        self.crashing_input_path = temp_file_path
    
    def __repr__(self):
        return f'CrashingInput(crashing_input_hex={self.crashing_input_hex}, crashing_input_hash={self.crashing_input_hash}, self.crashing_input_path={self.crashing_input_path})'


class InitialContextReport:
    def __init__(self, project_name:str, 
                       project_language:str,
                       issueTicket:str, 
                       files_in_scope:set,
                       ):
        self.issueTicket = issueTicket
        self.project_name = project_name
        self.project_language = project_language
        self.files_in_scope = files_in_scope
    
    def __str__(self):
        report = f'<Initial_Context_Report>\n'
        report += f'#Project Name\n {self.project_name}\n'
        report += f'#Project Language\n {self.project_language}\n'
        report += f'#Security Issue:\n {self.issueTicket}\n'
        report += f'#Files in Scope:\n'
        for file in self.files_in_scope:
            report += f' -{file}\n'
        report += f'<\Initial_Context_Report>\n'
        return report 


class RootCauseReport:
    def __init__(self, project_name:str, 
                       project_language:str,
                       issueTicket:str, 
                       root_cause_report:dict,
                       ):
        self.issueTicket = issueTicket
        self.project_name = project_name
        self.project_language = project_language
        self.root_cause_report = root_cause_report

    def __str__(self):
        report = f'<Root_Cause_Report>\n'
        report += f'#Project Name\n {self.project_name}\n'
        report += f'#Project Language\n {self.project_language}\n'
        report += f'#Security Issue:\n {self.issueTicket}\n'

        report += f"#Root-Cause:\n {self.root_cause_report['description']}\n"

        changes = self.root_cause_report['changes']
        report += f"#Proposed-Fixes:\n"

        for change in changes:
            report += f" - File: {change['file']}\n"
            fixes = change['fixes']
            for fix in fixes:
                report += f'   Proposed Fix: {fix}\n'
    
        #report += f'#Root Cause:\n {root_cause_data['description']}\n'
        report += f'<\Root_Cause_Report>\n'
        return report

    def __hash__(self):
        return hash(str(self))

