import logging
import re
from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction, SaveLoadObject
from agentlib import AgentWithHistory, LocalObject, ObjectParser, Field, tools, Agent
from agentlib.lib.common.parsers import BaseParser

from ..toolbox.peek_src import get_functions_by_file, show_file_at
from ..toolbox.peek_dbg import check_coverage_for, check_value_of_variable_at
from ..toolbox import lookup_symbol
from ..toolbox.code_ql_ops import get_function_callers, get_struct_definition, get_struct_definition_location
from typing import Optional, Any

logger = logging.getLogger('ExploitDeveloper')

class SeedParser(BaseParser):
    # recover_with = 'gpt-4o-mini'
    recover_with = 'gpt-o4-mini'
    # recover_with = 'claude-4-sonnet'
    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/JimmyPwn/SeedGenerator.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exp_dev = kwargs.get('exp_dev')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.exp_dev.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        if current_language == "c" or current_language == "c++":
            suffix = "c"
        else:
            suffix = "java"
        patch_report_template = open(f'/src/discoveryguy/prompts/JimmyPwn/extras-lang/exploits_reports/report.{suffix}', 'r').read()
        output_format = output_format.replace('<PLACEHOLDER_FOR_EXAMPLE_REPORTS_BY_LANGUAGE>', patch_report_template)
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def extract_exploit_dev_report(self, report:str) -> dict:
        exploit_script = re.search(r'<exploit_script>(.*?)</exploit_script>', report, re.DOTALL)
        if not exploit_script:
            raise Exception('No exploit_script found in the report!')
        exploit_script = exploit_script.group(1).strip() if exploit_script else None

        # Combine everything into a final dictionary
        exploit_dev_report = {
            "exploit_script": exploit_script
        }

        return exploit_dev_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<report>([\s\S]*?)</report>', text)
            if m:
                try:
                    exploit_script = self.extract_exploit_dev_report(m.group(0))
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the exploit analysis report from the output!')
                    return exploit_script
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the exploit analysis report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the exploit analysis report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1

class MyParser(BaseParser):
    # The model used to recover the format of the patch report
    # recover_with = 'claude-4-sonnet'
    recover_with = "gpt-o4-mini"
    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/JimmyPwn/JimmyPwn.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exp_dev = kwargs.get('exp_dev')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<report>([\s\S]*?)</report>', text)
            if m:
                try:
                    exploit_report = m.group(0)
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the exploit analysis report from the output!')
                    return exploit_report
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the exploit analysis report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the exploit analysis report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1


class SeedGenerationModel(AgentWithHistory[dict, str]):
    # __LLM_MODEL__ = "gpt-4.1"
    __LLM_MODEL__ = "gpt-o4-mini"
    # __LLM_MODEL__ = "gpt-o3"
    __SYSTEM_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/seed.system.j2"
    __USER_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/seed.user.j2"
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 5

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    __MAX_TOOL_ITERATIONS__ = 50

    LANGUAGE_EXPERTISE : str = None
    HARNESSES : list = None
    REPORT : str = None
    SINK_FUNCTION: str = None
    FEEDBACK: str = None
    BAD_SCRIPTS: list = None
    FAILED_SCRIPTS: list = None
    FIRST_ATTEMPT: bool = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.LANGUAGE_EXPERTISE = kwargs["LANGUAGE_EXPERTISE"]
        self.HARNESSES = kwargs["HARNESSES"]
        self.REPORT = kwargs["REPORT"]
        self.SINK_FUNCTION = kwargs["SINK_FUNCTION"]
        self.FEEDBACK = kwargs["FEEDBACK"]
        self.BAD_SCRIPTS = kwargs["BAD_SCRIPTS"]
        self.FAILED_SCRIPTS = kwargs["FAILED_SCRIPTS"]
        self.FIRST_ATTEMPT = kwargs["FIRST_ATTEMPT"]

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            HARNESSES=self.HARNESSES,
            REPORT=self.REPORT,
            SINK_FUNCTION=self.SINK_FUNCTION,
            FEEDBACK=self.FEEDBACK,
            BAD_SCRIPTS=self.BAD_SCRIPTS,
            FAILED_SCRIPTS=self.FAILED_SCRIPTS,
            FIRST_ATTEMPT=self.FIRST_ATTEMPT
        )
        return vars

    def get_output_parser(self):
        return SeedParser(exp_dev=self)


class simpleParser(BaseParser):
    def get_format_instructions(self) -> str:
        return "Just output the output"
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg['output'])
    def parse(self, text: str):
        return text.chat_messages[-1].content

class JimmyPwn(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = "claude-4-sonnet"
    __LLM_ARGS__ = {
        'max_tokens': 10240,
    }

    __SYSTEM_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/system.j2"
    __USER_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/user.j2"

    __MAX_TOOL_ITERATIONS__ = 75
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 8
    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    __OUTPUT_PARSER__ = MyParser

    LANGUAGE_EXPERTISE : str = None
    PROJECT_NAME : str = None
    FUNCTION_INDEX : str = None
    FUNCTION_NAME : str = None
    FILE_NAME : str = None
    CODE : str = None
    CODE_DIFF : str = None
    HARNESSES : list = None
    NODES_OPTIMIZED : list = None
    NOTICE : str = None
    FEEDBACK : str = None
    WITH_DIFF : bool = False
    WITH_PATH: bool = False
    # WITH_BENIGN_TEMPLATE: str = None
    # LAST_BENIGN_FUNC_REACHED: str = None
    LAST_CHANCE: bool = False
    DIFF_SUMMARY: str = None

    # This is for the sarif mode
    WITH_SARIF_SUMMARY: Optional[str] = None

    # This is to chat with the model at the end to get extra infos (e.g., a summary of what happened)
    HUMAN_MSG: Optional[str] = None



    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.LANGUAGE_EXPERTISE = kwargs["LANGUAGE_EXPERTISE"]
        self.PROJECT_NAME = kwargs["PROJECT_NAME"]
        self.FUNCTION_INDEX = kwargs["FUNCTION_INDEX"]
        self.FUNCTION_NAME = kwargs["FUNCTION_NAME"]
        self.FILE_NAME = kwargs["FILE_NAME"]
        self.CODE = kwargs["CODE"]
        self.CODE_DIFF = kwargs["CODE_DIFF"]
        self.HARNESSES = kwargs["HARNESSES"]
        self.NODES_OPTIMIZED = kwargs["NODES_OPTIMIZED"]
        self.NOTICE = kwargs["NOTICE"]
        self.FEEDBACK = kwargs["FEEDBACK"]
        self.WITH_DIFF = kwargs["WITH_DIFF"]
        self.WITH_PATH = kwargs["WITH_PATH"]
        self.DIFF_SUMMARY = kwargs["DIFF_SUMMARY"]
        # self.WITH_BENIGN_TEMPLATE = kwargs["WITH_BENIGN_TEMPLATE"]
        # self.LAST_BENIGN_FUNC_REACHED = kwargs["LAST_BENIGN_FUNC_REACHED"]
        self.LAST_CHANCE = kwargs["LAST_CHANCE"]

        self.WITH_SARIF_SUMMARY = kwargs.get("WITH_SARIF_SUMMARY", None)

    def add_sarif_summary(self, summary: str):
        self.WITH_SARIF_SUMMARY = summary

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            PROJECT_NAME=self.PROJECT_NAME,
            FUNCTION_INDEX=self.FUNCTION_INDEX,
            FUNCTION_NAME=self.FUNCTION_NAME,
            FILE_NAME=self.FILE_NAME,
            CODE=self.CODE,
            CODE_DIFF=self.CODE_DIFF,
            HARNESSES=self.HARNESSES,
            NODES_OPTIMIZED=self.NODES_OPTIMIZED,
            NOTICE=self.NOTICE,
            FEEDBACK=self.FEEDBACK,
            WITH_DIFF=self.WITH_DIFF,
            WITH_PATH=self.WITH_PATH,
            # WITH_BENIGN_TEMPLATE=self.WITH_BENIGN_TEMPLATE,
            # LAST_BENIGN_FUNC_REACHED=self.LAST_BENIGN_FUNC_REACHED,
            WITH_SARIF_SUMMARY=self.WITH_SARIF_SUMMARY,
            HUMAN_MSG=self.HUMAN_MSG,
            LAST_CHANCE=self.LAST_CHANCE,
            DIFF_SUMMARY=self.DIFF_SUMMARY
        )
        return vars

    def set_human_msg(self, human_msg: str):
        self.HUMAN_MSG = human_msg
        JimmyPwn.__OUTPUT_PARSER__ = simpleParser

    def get_available_tools(self):
        # import ipdb; ipdb.set_trace()
        return [lookup_symbol]

    def get_output_parser(self):
        return MyParser(exp_dev=self)


class HoneyListParser(BaseParser):
    # The model used to recover the format of the patch report
    # recover_with = 'claude-4-sonnet'
    recover_with = "gpt-o4-mini"
    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = '/src/discoveryguy/prompts/JimmyPwn/HarnessList.output.txt'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exp_dev = kwargs.get('exp_dev')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        return output_format

    def invoke(self, msg, *args, **kwargs):
        return self.parse(msg.content)

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=True,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )

        return fixed_text

    def parse(self, text: str):
        try_itr = 1

        while try_itr <= 5:
            harnesses = re.findall(r'<harness_index>([\s\S]*?)</harness_index>', text)
            # import ipdb; ipdb.set_trace()
            harness_list = []
            if 0 < len(harnesses) < 6:
                try:
                    for harness in harnesses:
                        if harness:
                            harness_list.append(harness)
                    logger.info(f'✅ Regexp-Parser: Successfully parsed the exploit analysis report from the output!')
                    return harness_list
                except Exception as e:
                    logger.info(f'🤡 Regexp-Error: Error parsing the exploit analysis report - {e}')
                    logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                logger.info(f'🤡 Regexp-Error: Could not parse the exploit analysis report from the ouput!')
                logger.info(f'🤡 Regexp-Error: Trying to fix the format of the exploit analysis report... Attempt {try_itr}!')
                text = self.fix_format(text)
            try_itr+=1



class HoneySelectAgent(Agent[dict, str]):
    """
    This agent is used to select the best harness for JimmyPwn based on the provided information.
    """
    __LLM_MODEL__ = "claude-4-sonnet"
    # __LLM_MODEL__ = "gpt-4o-mini"

    __SYSTEM_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/harness.system.j2"
    __USER_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/harness.user.j2"

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.LANGUAGE_EXPERTISE = kwargs["LANGUAGE_EXPERTISE"]
        self.PROJECT_NAME = kwargs["PROJECT_NAME"]
        self.FUNCTION_INDEX = kwargs["FUNCTION_INDEX"]
        self.FILE_NAME = kwargs["FILE_NAME"]
        self.FUNCTION_NAME = kwargs["FUNCTION_NAME"]
        self.CODE = kwargs["CODE"]
        self.HARNESSES = kwargs["HARNESSES"]


    def get_output_parser(self):
        return HoneyListParser(exp_dev=self)

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            PROJECT_NAME=self.PROJECT_NAME,
            FUNCTION_INDEX=self.FUNCTION_INDEX,
            FUNCTION_NAME=self.FUNCTION_NAME,
            FILE_NAME=self.FILE_NAME,
            CODE=self.CODE,
            HARNESSES=self.HARNESSES
        )
        return vars




class SummaryParser(BaseParser):
    def get_format_instructions(self) -> str:
        return "Just output the output"
    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg)
    def parse(self, text: str):
        return text.content

class SummaryAgent(Agent[dict,str]):

    __LLM_MODEL__ = "claude-4-sonnet"
    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True
    __SYSTEM_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/summary.system.j2"
    __USER_PROMPT_TEMPLATE__ = "/src/discoveryguy/prompts/JimmyPwn/summary.user.j2"


    LANGUAGE_EXPERTISE : str = None
    PROJECT_NAME : str = None
    DIFF : str = None


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.LANGUAGE_EXPERTISE = kwargs["LANGUAGE_EXPERTISE"]
        self.PROJECT_NAME = kwargs["PROJECT_NAME"]
        self.DIFF = kwargs["DIFF"]

    def get_output_parser(self):
        return SummaryParser(exp_dev=self)

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
                    LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
                    PROJECT_NAME=self.PROJECT_NAME,
                    DIFF=self.DIFF
                )
        return vars