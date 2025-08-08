#!/usr/bin/env python3
import logging
import os
from pathlib import Path
from typing import Optional, List, Tuple, Union


from agentlib import (
    AgentPlanStep,
    SaveLoadObject,
    Field,
)

from .base_agent import BaseAgent
_l = logging.getLogger(__name__)


class SiOutput(SaveLoadObject):
    """
    This object describes the identified sinks.
    """

    identified_sinks: list = Field(
        default=[], description="""
        This should be a list of identified  vulnerable sinks.
        Each item in this list should be a string that has the class name and the method name of the sink.
        For example, if the sink is `MyClass.myMethod`, then the string should be `MyClass.myMethod`.
        """
    )


class SinkIdentifierAgent(BaseAgent):
    """
    This agent will follow the steps above.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_dir = os.path.join(current_dir, "prompts")
    _l.debug(f"llm folder is {prompt_dir}")
    system_prompt = os.path.join(prompt_dir, "si.system.j2")
    user_prompt = os.path.join(prompt_dir, "generic.user.j2")

    __SYSTEM_PROMPT_TEMPLATE__ = system_prompt
    __USER_PROMPT_TEMPLATE__ = user_prompt
    __LLM_ARGS__ = {"temperature": 0,
                    "max_tokens": 8192}

    methods: List[str]
    sanitizer_name: str


    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            methods=self.methods,
            sanitizer_name = self.sanitizer_name
        )