
import re
import logging
import json

from datetime import datetime
from agentlib import Agent, AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any, List, Set
from shellphish_crs_utils.function_resolver import FUNCTION_INDEX_KEY

from ..config import Config, CRSMode

from ..toolbox.peek_src import show_file_at, get_functions_by_file, search_string_in_file, search_function, get_function_or_struct_location
from ..toolbox.lang_server_ops import LANG_SERVER_TOOLS
from ..toolbox.code_ql_ops import CODEQL_TOOLS
from ..patch_verifier.exceptions.errors import FailureCodes
from ..toolbox.peek_logs import show_log_at, search_string_in_log
from ..toolbox.peek_diff import get_diff_snippet

from .exceptions import MaxToolCallsExceeded

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# This is the list of tools that the agent can use
# These are returned by the get_available_tools method
TOOLS = {
    'show_file_at': show_file_at,
    'get_functions_by_file': get_functions_by_file,
    #'get_struct_definition': get_struct_definition,
    #'get_function_callers': get_function_callers,
    # 'search_function': search_function,
    'get_function_or_struct_location': get_function_or_struct_location,
    'search_string_in_file': search_string_in_file,
}

TOOLS_WITH_LOGS = {
    'show_file_at': show_file_at,
    'get_functions_by_file': get_functions_by_file,
    'search_string_in_log': search_string_in_log,
    'show_log_at': show_log_at,
    # 'search_function': search_function,
    'get_function_or_struct_location': get_function_or_struct_location,
}

class MyParser(BaseParser):

    # The maximum number of attempts to fix the format of the patch report
    MAX_PATCH_FORMAT_FIX_ATTEMPTS = 3

    # The model used to recover the format of the patch report
    recover_with = 'gpt-4.1-mini'

    # This is the template used to recover the format of the patch report if the parsing fails
    __PATCH_FORMAT_RECOVERY_TEMPLATE = '/src/patcherq/prompts/programmerGuy/extras/patch_format_recovery.j2'

    # This is the output format that describes the output of programmerGuy
    __OUTPUT_DESCRIPTION = '/src/patcherq/prompts/programmerGuy/programmerGuy.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.programmer_guy = kwargs.get('programmer_guy')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        # The output format is the one used by AutoCodeRover
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.programmer_guy.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        patch_report_template = open(f'/src/patcherq/prompts/programmerGuy/extras-lang/patch_reports/report.{current_language}', 'r').read()
        output_format = output_format.replace('<PLACEHOLDER_FOR_EXAMPLE_REPORTS_BY_LANGUAGE>', patch_report_template)
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        if msg['output'] == 'Agent stopped due to max iterations.':
            raise MaxToolCallsExceeded
        return self.parse(msg['output'])
    
    def fix_patch_format(self, text: str, data_fix: bool = False) -> str:
        fix_patch_prompt = open(self.__PATCH_FORMAT_RECOVERY_TEMPLATE, 'r').read()
        fix_llm = LLMFunction.create(
            fix_patch_prompt,
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_patch = text,
                output_format = self.get_format_instructions(),
                data_fix = data_fix,
                chat_history = '\n----------------------\n'.join([chat.content for chat in self.programmer_guy.chat_history]) if data_fix else ''
            )
        )

        return fixed_text
    
    def extract_changes(self, text: str):
        try_itr = 1
        while try_itr <= self.MAX_PATCH_FORMAT_FIX_ATTEMPTS:
            # The definition of the patch emitted format is above
            # Find all <change> elements
            changes = re.findall(r'<change>\s*<file>(.*?)</file>\s*<line>\s*<start>(.*?)</start>\s*<end>(.*?)</end>\s*</line>\s*<original>([\s\S]*?)</original>\s*<patched>([\s\S]*?)</patched>\s*</change>', text, re.DOTALL)
            
            if len(changes) != 0:
                logger.info('✅ Regexp-Parser: Successfully parsed the patch from the output!')
                return changes

            logger.info('🤡 Regexp-Error: Could not parse the patch from the ouput!')
            logger.info('🤡 Regexp-Error: Trying to fix the format of the patch report... Attempt %d!', try_itr)
            text = self.fix_patch_format(text)
            try_itr+=1
        return []

    def extract_patch(self, text: str):
        try_itr = 1
        while try_itr <= self.MAX_PATCH_FORMAT_FIX_ATTEMPTS:
            changes = self.extract_changes(text)
            # Process each <change> entry
            patch = []
            change_id = 0
            error = False
            for file_path, start_loc, end_loc, original_code, patched_code in changes:
                try:
                    
                    parsed_change = {
                        "change_id": int(change_id),
                        "file": file_path.strip(),
                        "line": {
                            "start": int(start_loc.strip()),
                            "end": int(end_loc.strip())
                        },
                        "original": original_code,
                        "patched": patched_code
                    }
                except Exception as e:
                    logger.info('🤡 Parsing-Error: Could not parse the patch from the regexp-match! %s', e)
                    error = True
                    break
                patch.append(parsed_change)
                change_id+=1

            if error:
                logger.info('🤡 Parsing-Error: Trying to fix the format of the patch report... Attempt %d!', try_itr)
                text = self.fix_patch_format(text, data_fix=True)
                try_itr+=1
            else:
                logger.info('✅ Data-Parser: Successfully parsed the patch data from the output!')
                return patch
        return []

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= self.MAX_PATCH_FORMAT_FIX_ATTEMPTS:
            raw_patch = re.search(r'<patch_report>([\s\S]*?)</patch_report>', text)

            if raw_patch:
                patch = self.extract_patch(raw_patch.group(0))
                return raw_patch.group(0), patch
            else:
                logger.info('🤡 Regexp-Error: Could not parse thepatch from the ouput!')
                logger.info('🤡 Regexp-Error: Trying to fix the format of the patch report... Attempt %d!', try_itr)
                text = self.fix_patch_format(text)
                try_itr+=1

        logger.info('Error: Could not parse the patch from the ouput!')
        assert(False)

class simpleParser(BaseParser):
    def get_format_instructions(self) -> str:
        return "Just output the output"
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])
    def parse(self, text: str):
        return text.chat_messages[-1].content

class ProgrammerGuy(AgentWithHistory[dict,str]):
    __LLM_MODEL__ = 'claude-3.7-sonnet'

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/programmerGuy/programmerGuy.CoT.system.j2' 
    __USER_PROMPT_TEMPLATE__ = '/src/patcherq/prompts/programmerGuy/programmerGuy.CoT.user.j2'
    # __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 70

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True
    
    __LLM_ARGS__ = {
        'temperature': 0.0,
        'max_tokens': 8192
    }
    
    # These are passed during the programmerGuy initialization
    ROOT_CAUSE_REPORT: Optional[str]
    LANGUAGE_EXPERTISE: Optional[str]

    # This is here for the feedback loop between the verification
    # pipeline and the programmerGuy
    IS_FEEDBACK: Optional[bool]
    FAILURE: Optional[str]
    FEEDBACK_WHY_PREVIOUS_PATCH_FAILED: Optional[str]
    WITH_PATCHES_ATTEMPT: Optional[str]
    FAILED_PATCHES_ATTEMPT: Optional[str]
    EXTRA_FEEDBACK_INSTRUCTIONS: Optional[str]
    REFINE_JOB: Optional[str]
    FAILED_FUNCTIONALITY: Optional[str] = None
    NUM_CRASHING_INPUTS_TO_PASS: Optional[str]
    WITH_HINTS: Optional[str] = None
    DELTA_HINTS: Optional[str] = None
    
    # Extra prompts used by the recovery LLMFunctions
    __COMPILATION_RECOVERY_TEMPLATE = '/src/patcherq/prompts/programmerGuy/extras/compilation_recovery.j2'
    __CRASH_RECOVERY_TEMPLATE = '/src/patcherq/prompts/programmerGuy/extras/crash_recovery.j2'
    __TESTS_RECOVERY_TEMPLATE = '/src/patcherq/prompts/programmerGuy/extras/tests_recovery.j2'

    # 🪲🔬 Just for live debugging
    chatting_with_human = False
    HUMAN_MSG: Optional[str]

    # Extra cost that we need to keep track when we do LLM calls
    extra_calls_cost = 0
    
    with_codeql_server = False
    with_lang_server = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ROOT_CAUSE_REPORT = kwargs.get('root_cause_report')
        self.LANGUAGE_EXPERTISE = kwargs.get('project_language')
        self.REFINE_JOB = kwargs.get('refine_job', None)
        self.FAILED_FUNCTIONALITY = kwargs.get('failed_functionality', None)

        if self.FAILED_FUNCTIONALITY == False:
            # NOTE: putting it to None so it doesn't show up in the prompt.
            self.FAILED_FUNCTIONALITY = None
        
        self.NUM_CRASHING_INPUTS_TO_PASS = kwargs.get('num_crashing_inputs_to_pass', None)
        
        with_sanitizers: List[str] = kwargs.get('with_sanitizers', None)
        
        self.WITH_HINTS = self.get_hints_for_sanitizers(with_sanitizers)
        
        self.DELTA_HINTS = self.get_hints_for_delta(kwargs.get('funcs_in_scope', None))

        self.with_codeql_server = kwargs.get('with_codeql_server', False)
        self.with_lang_server = kwargs.get('with_lang_server', False)

    def increase_temperature_by(self, value: float):
        current_temperatue = self.__LLM_ARGS__.get('temperature', 0.0)
        new_temperature = current_temperatue + value
        # The temperature should be between 0.0 and 1.0
        new_temperature = max(0.0, min(1.0, new_temperature))
        logger.info('🔥🔥🔥 ProgrammerGuy is heating up... (Current temperature: %s) 🔥🔥🔥', new_temperature)
        # Update the temperature
        ProgrammerGuy.__LLM_ARGS__ = {"temperature": new_temperature}

    def reset_temperature(self):
        ProgrammerGuy.__LLM_ARGS__ = {"temperature": 0.0}
        
    def get_hints_for_delta(self, funcs_in_scope: Set[FUNCTION_INDEX_KEY]) -> str:
        if not funcs_in_scope or not (Config.crs_mode == CRSMode.DELTA):
            return ""
        
        DELTA_HINT = ""
        for func in funcs_in_scope:
            func_diff = get_diff_snippet(func)
            if func_diff:
                DELTA_HINT += f"{func_diff}\n"
            
        return DELTA_HINT

    def get_hints_for_sanitizers(self, sanitizers: List[str]) -> str:
        all_hints = []

        with open("/src/patcherq/prompts/programmerGuy/extras/hints.json", "r") as f:
            human_hints = json.load(f)
        
        # Load all the hints for the current language
        human_hints_for_language = human_hints.get(self.project_language, None)
        # If this happen, something is super rekd....
        assert human_hints_for_language is not None, f"No hints found for language: {self.project_language}"
        
        for sanitizer_triggered in sanitizers:
            for k, hint in human_hints_for_language.items():
                if k.lower() in sanitizer_triggered.lower():
                    all_hints.append(hint)

        the_actual_hints = ''
        for i, hint in enumerate(all_hints):
            the_actual_hints += f"Hint {i+1}: {hint}\n"
        
        return the_actual_hints if len(the_actual_hints) > 0 else None

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            ROOT_CAUSE_REPORT=self.ROOT_CAUSE_REPORT,
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            IS_FEEDBACK=self.IS_FEEDBACK,
            FAILURE=self.FAILURE,
            FEEDBACK_WHY_PREVIOUS_PATCH_FAILED=self.FEEDBACK_WHY_PREVIOUS_PATCH_FAILED,
            WITH_PATCHES_ATTEMPT=self.WITH_PATCHES_ATTEMPT,
            FAILED_PATCHES_ATTEMPT=self.FAILED_PATCHES_ATTEMPT,
            HUMAN_MSG=self.HUMAN_MSG,
            EXTRA_FEEDBACK_INSTRUCTIONS=self.EXTRA_FEEDBACK_INSTRUCTIONS,
            REFINE_JOB=self.REFINE_JOB,
            FAILED_FUNCTIONALITY=self.FAILED_FUNCTIONALITY,
            NUM_CRASHING_INPUTS_TO_PASS=self.NUM_CRASHING_INPUTS_TO_PASS,
            WITH_HINTS=self.WITH_HINTS,
            DELTA_HINTS=self.DELTA_HINTS,
        )
        return vars
    
    def set_feedback(self, failure=None, feedback=None, extra_feedback='', **kwargs):
        # Signal that the ProgrammerGuy will operate with a feedback
        assert(feedback is not None)
        assert(failure is not None)
        assert(extra_feedback is not None)

        self.IS_FEEDBACK = True
        self.FAILURE = failure
        self.FEEDBACK_WHY_PREVIOUS_PATCH_FAILED = feedback
        self.EXTRA_FEEDBACK_INSTRUCTIONS = extra_feedback
    
    def set_human_msg(self, human_msg: str):
        self.HUMAN_MSG = human_msg
        self.chatting_with_human = True
        ProgrammerGuy.__OUTPUT_PARSER__ = simpleParser

    def chatline(self):
        logger.info(" === 👥 <-connect-> 🤖 ===")
        logger.info(" Type 'END' on a new line to send your message, or 'exit' to quit.\n")
        
        chat_on = True
        while chat_on:
            try:
                # Prompt for multiline input
                logger.info("\n👥: (Your message below)")
                lines = []
                while True:
                    line = input("    > ")  # Indent for neatness
                    if line.strip().lower() == "exit":
                        logger.info("\n🔌 Disconnecting... Thank you for chatting! 🌟")
                        return
                    if line.strip().upper() == "END":
                        chat_on = False
                    lines.append(line)

                    # Combine lines into a message
                    msg = "\n".join(lines)
                    
                    # Simulate setting and invoking the response
                    self.set_human_msg(msg)
                    res = self.invoke()
                    
                    # Show response with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    logger.info("\n[%s] 🤖: %s", timestamp, res.value)

            except KeyboardInterrupt:
                logger.info("\n\n⏸️  Chat paused. Type 'exit' to quit or continue typing.")
                continue
        
        ProgrammerGuy.__OUTPUT_PARSER__ = MyParser
        self.HUMAN_MSG = None
        self.chatting_with_human = False

    def set_failed_patches_attempt(self, failed_patches_attempt: str):
        self.WITH_PATCHES_ATTEMPT = True
        self.FAILED_PATCHES_ATTEMPT = failed_patches_attempt

    def get_available_tools(self):
        my_tools = []
        
        if self.IS_FEEDBACK:
            if self.FAILURE == FailureCodes.PATCHED_CODE_STILL_CRASHES:
                my_tools.extend(TOOLS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_HANGS:
                my_tools.extend(TOOLS_WITH_LOGS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_DOES_NOT_COMPILE:
                my_tools.extend(TOOLS_WITH_LOGS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_DOES_NOT_PASS_TESTS:
                my_tools.extend(TOOLS_WITH_LOGS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_DOES_NOT_PASS_BUILD_PASS:
                my_tools.extend(TOOLS_WITH_LOGS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_FAILS_LINTING:
                my_tools.extend(TOOLS.values())
            elif self.FAILURE == FailureCodes.CORRUPTED_PATCH:
                my_tools.extend(TOOLS.values())
            elif self.FAILURE == FailureCodes.ILLEGAL_PATCH_LOCATION:
                my_tools.extend(TOOLS.values())
            elif self.FAILURE == FailureCodes.PATCH_DOES_NOT_SANITIZE:
                my_tools.extend(TOOLS.values())
            elif self.FAILURE == FailureCodes.PATCHED_CODE_DOES_NOT_PASS_CRITIC:
                my_tools.extend(TOOLS.values())
            else:
                logger.info('Invalid failure code: %s', self.FAILURE)
                assert(False)
        else:
            my_tools.extend(TOOLS.values())
        
        if self.with_lang_server:
            my_tools.extend(LANG_SERVER_TOOLS.values())
            
        if self.with_codeql_server:
            my_tools.extend(CODEQL_TOOLS.values())
        
        # if Config.crs_mode == CRSMode.DELTA and Config.use_diff_tool_for_delta:
        #     my_tools.extend([get_diff_snippet, list_changed_functions])
            
        return my_tools

    def get_output_parser(self):
        return MyParser(programmer_guy=self)
