
from agentlib import Agent
from typing import Optional, Any

class IssueGuy(Agent[dict,str]):
    #__LLM_MODEL__ = 'gpt-o1'
    __LLM_MODEL__ = 'claude-3.7-sonnet'
    
    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/issueGuy/issueGuy.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/issueGuy/issueGuy.user.j2'

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    __LLM_ARGS__ = {
        'temperature': 0.0,
        'max_tokens': 8192
    }

    PROGRAM_NAME: Optional[str]
    POI_REPORT: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PROGRAM_NAME = kwargs.get('project_name')
        poi_report = kwargs.get('poi_report')

        assert(self.PROGRAM_NAME is not None)
        assert(poi_report is not None)
        assert(self.PROGRAM_NAME != "")
        assert(poi_report != "")

        self.POI_REPORT = "\n==== BEGIN CRASH REPORT ====\n"
        self.POI_REPORT += f" - Crash reason: {poi_report['crash_reason']}\n"
        self.POI_REPORT += f" - Sanitizer triggered: {poi_report['sanitizer_name']}\n"
        
        if len(poi_report['stack_traces']) == 1:
            self.POI_REPORT += f" - Stack Trace: \n"
            call_locations = poi_report['stack_traces']['main']
            num_of_frames = len(call_locations)
            for call_loc in call_locations:
                self.POI_REPORT += f"    Stack Frame {num_of_frames}:\n"
                self.POI_REPORT += f"      - File: {call_loc['source_relative_file_path']}\n"
                self.POI_REPORT += f"      - Function: {call_loc['function_name']}\n"
                self.POI_REPORT += f"      - Line: {call_loc['line_number']}\n"
                self.POI_REPORT += f"      - Code: {call_loc['line_text']}\n"
                num_of_frames -= 1
        else:
            assert(len(poi_report['stack_traces']) > 1)
            not_main_stack_traces_id = [ f'\'{stid}\'' for stid in poi_report['stack_traces'] if stid != 'main' ]
            not_main_stack_traces_id = " and ".join(not_main_stack_traces_id)
            self.POI_REPORT += f" - The report includes {len(poi_report['stack_traces'])} stack traces.\n"
            self.POI_REPORT += f" - The stack trace with ID 'main' points to the place where the sanitizer noticed a problem, but not necessarility where it originally happened\n"
            self.POI_REPORT += f" - The other stack traces ({not_main_stack_traces_id}) show events that are related to the crash and can be helpful to understand the root cause.\n"
            self.POI_REPORT += f" - Stack Traces: \n"
            
            # Let's put the main stack trace first
            self.POI_REPORT += f"    Stack Trace ID: main\n"
            call_locations = poi_report['stack_traces']['main']
            num_of_frames = len(call_locations)
            for call_loc in call_locations:
                self.POI_REPORT += f"    Stack Frame {num_of_frames}:\n"
                self.POI_REPORT += f"      - File: {call_loc['source_relative_file_path']}\n"
                self.POI_REPORT += f"      - Function: {call_loc['function_name']}\n"
                self.POI_REPORT += f"      - Line: {call_loc['line_number']}\n"
                self.POI_REPORT += f"      - Code: {call_loc['line_text']}\n"
                num_of_frames -= 1
            
            # Now all the other stack traces
            for stack_trace_id, call_locations in poi_report['stack_traces'].items():
                if stack_trace_id == 'main':
                    continue
                self.POI_REPORT += f"    Stack Trace ID: {stack_trace_id}\n"
                num_of_frames = len(call_locations)
                for call_loc in call_locations:
                    self.POI_REPORT += f"    Frame {num_of_frames}:\n"
                    self.POI_REPORT += f"      - File: {call_loc['source_relative_file_path']}\n"
                    self.POI_REPORT += f"      - Function: {call_loc['function_name']}\n"
                    self.POI_REPORT += f"      - Line: {call_loc['line_number']}\n"
                    self.POI_REPORT += f"      - Code: {call_loc['line_text']}\n"
                    num_of_frames -= 1

        self.POI_REPORT += "\n==== END CRASH REPORT ====\n"


    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            PROGRAM_NAME=self.PROGRAM_NAME,
            POI_REPORT=self.POI_REPORT,
        )
        return vars
