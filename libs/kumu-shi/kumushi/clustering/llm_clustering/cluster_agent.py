import re
import logging

from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser, ParsesFromString
from typing import Optional, Any

from .prompts import CLUSTER_USR_PROMPT, CLUSTER_SYS_PROMPT, ROOT_CAUSE_OUTPUT

_l = logging.getLogger(__name__)

class MyParser(ParsesFromString):
    # The model used to recover the format of the patch report
    recover_with = 'claude-3.7-sonnet'

    # This is the template used to recover the format of the root cause report if the parsing fails
    __ROOT_CAUSE_FORMAT_RECOVERY_TEMPLATE = '/src/patcherq/prompts/triageGuy/extras/root_cause_format_recovery.j2'

    # This is the output format that describes the output of triageGuy
    __OUTPUT_DESCRIPTION = ROOT_CAUSE_OUTPUT

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.triage_guy = kwargs.get('triage_guy')

    def get_format_instructions(self) -> str:
        # This string is used in the user prompt as {{output_format}}
        output_format = open(self.__OUTPUT_DESCRIPTION, 'r').read()
        current_language = self.triage_guy.LANGUAGE_EXPERTISE
        # Let's template the report example based on the current language
        # patch_report_template = open(
        #     f'/src/patcherq/prompts/triageGuy/extras-lang/rca_reports/report.{current_language}', 'r').read()
        # output_format = output_format.replace('<PLACEHOLDER_FOR_EXAMPLE_REPORTS_BY_LANGUAGE>', patch_report_template)
        return output_format

    # def invoke(self, msg, *args, **kwargs) -> dict:
    #     return self.parse(msg['output'])
    # def parse(self, output: str) -> str:
    #     return output

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current root cause report according to the format instructions.\n\n# CURRENT ROOT CAUSE REPORT\n{{ info.current_rc }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model=self.recover_with,
            use_loggers=False,
            temperature=0.0,
            include_usage=True
        )
        fixed_text, usage = fix_llm(
            info=dict(
                current_rc=text,
                output_format=self.get_format_instructions()
            )
        )

        return fixed_text

    def extract_root_cause(self, report: str) -> dict:
        import re
        # Extract all clusters from the report
        function_sections = re.findall(r'<function>(.*?)</function>', report, re.DOTALL)

        if not function_sections:
            raise Exception('No function sections found in the root cause report!')

        cluster = []
        for func_section in function_sections:
            # Extract description from this cluster
            func_name_match = re.search(r'<name>(.*?)</name>', func_section, re.DOTALL)
            if not func_name_match:
                continue  # Skip clusters without descriptions

            func_name = func_name_match.group(1).strip()
            cluster.append(func_name)

        # search for the root cause description
        rca_description = None
        rca_description_match = re.search(r'<description>(.*?)</description>', report, re.DOTALL)
        if rca_description_match:
            rca_description = rca_description_match.group(1).strip()

        if not cluster:
            raise Exception('No valid functions found in the root cause report!')
        if not rca_description:
            raise Exception('No description found in the root cause report!')

        root_cause_report = {
            "cluster": cluster,
            "description": rca_description
        }

        return root_cause_report

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= 3:
            m = re.search(r'<root_cause_report>([\s\S]*?)</root_cause_report>', text)
            if m:
                try:
                    root_cause = self.extract_root_cause(m.group(0))
                    _l.info('✅ Regexp-Parser: Successfully parsed the root cause report from the output!')
                    return root_cause
                except Exception as e:
                    _l.info('🤡 Regexp-Error: Error parsing the root cause report - %s', e)
                    _l.info('🤡 Regexp-Error: Trying to fix the format of the root cause report... Attempt %d!',
                            try_itr)
                    text = self.fix_format(text)
            else:
                # Technically, this should never happen
                # the parser should make sure that the output is always in the format.
                # logger.info(f'🤡 Regexp-Error: Could not parse the root cause report from the ouput!')
                _l.info(' Detected invalid format of the root cause report, fixing... (attempt: %d)', try_itr)
                text = self.fix_format(text)
            try_itr += 1

        return None


class ClusterAgent(Agent[dict, str]):
    __LLM_MODEL__ = 'claude-4-opus'

    __SYSTEM_PROMPT_TEMPLATE__ = str(CLUSTER_SYS_PROMPT)
    __USER_PROMPT_TEMPLATE__ = str(CLUSTER_USR_PROMPT)
    __OUTPUT_PARSER__ = MyParser

    __LLM_ARGS__ = dict(
        temperature=0.0,
        thinking={"type": "enabled", "budget_tokens": 10000}
        # reasoning_effort="high",
    )

    INITIAL_CONTEXT_REPORT: Optional[str]
    LANGUAGE_EXPERTISE: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # ================
        # Prompt variables
        # ================
        self.INITIAL_CONTEXT_REPORT = kwargs.get('init_context')
        self.LANGUAGE_EXPERTISE = kwargs.get('project_language')
        self.valid_functions = kwargs.get('valid_functions', set())

        # ================
        # State variables
        # ================
        # This is used to determine if the agent should use the invariants tool
        # self.with_invariants = kwargs.get('with_invariants', False)
        # self.with_codeql_server = kwargs.get('with_codeql_server', False)
        # self.with_lang_server = kwargs.get('with_lang_server', False)

    def get_input_vars(self, *args, **kw):
        # Any returned dict will be use as an input to template the prompts
        # of this agent.
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            INITIAL_CONTEXT_REPORT=self.INITIAL_CONTEXT_REPORT,
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
        )
        return vars

    def get_output_parser(self):
        return MyParser(triage_guy=self)
