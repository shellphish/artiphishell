import logging
import re

from agentlib import LocalObject, ObjectParser, Field, tools, LLMFunction
from agentlib.lib.agents import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from langchain_core.output_parsers import PydanticOutputParser
from typing import Optional, Any, List, Dict


logger = logging.getLogger('DetectorGuy')
logger.setLevel(logging.INFO)


class DetectorGuy(AgentWithHistory[dict,str]):

    # Choose a language model to use (default gpt-4-turbo)
    # __LLM_MODEL__ = 'o1-preview'
    # __LLM_MODEL__ = 'gpt-4o'
    # __LLM_MODEL__ = 'gpt-4o'
    #__LLM_MODEL__ = "claude-3.5-sonnet"
    __LLM_MODEL__ = "gpt-4.1-mini"

    __SYSTEM_PROMPT_TEMPLATE__ = '/src/backdoorguy/prompts/Detector/system.j2'
    __USER_PROMPT_TEMPLATE__ = '/src/backdoorguy/prompts/Detector/user.j2'

    __RAISE_ON_BUDGET_EXCEPTION__ = True

    LANGUAGE_EXPERTISE: Optional[str]
    PROJECT_NAME: Optional[str]
    ENTROPY_VALUE: Optional[str]
    FUNCTION_NAME: Optional[str]
    CODE: Optional[str]

    __LOGGER__ = logging.getLogger('Detector')
    __LOGGER__.setLevel(logging.ERROR)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.LANGUAGE_EXPERTISE = kwargs.get('language')
        self.FUNCTION_NAME = kwargs.get('function_name')
        self.PROJECT_NAME = kwargs.get('project_name')
        self.ENTROPY_VALUE = kwargs.get('entropy_value')
        self.CODE = kwargs.get('code')

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            LANGUAGE_EXPERTISE=self.LANGUAGE_EXPERTISE,
            FUNCTION_NAME=self.FUNCTION_NAME,
            PROJECT_NAME=self.PROJECT_NAME,
            ENTROPY_VALUE=self.ENTROPY_VALUE,
            CODE=self.CODE
        )
        return vars
    