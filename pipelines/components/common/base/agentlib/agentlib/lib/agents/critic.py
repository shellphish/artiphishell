import os
import json
import subprocess
from typing import Union, Optional, Any, Dict, List, Generic

from langchain_core.pydantic_v1 import Field
from langchain_core.runnables.utils import Input, Output
from langchain_core.output_parsers import PydanticOutputParser

from .agent import ChildAgent, Agent
from ..common.object import LocalObject

class CriticReview(LocalObject):
    """ A review of if the given task was complete """
    success: bool = Field(
        default=False,
        description='Set this to true if and only if the task has been completed successfully to your satisfaction.'
    )
    feedback: str = Field(
        default=None,
        description='If the task was not completed to your satisfaction, give feedback on how it can be fixed.'
    )
    give_up: bool = Field(
        default=False,
        description='Set this to true if you want to give up on the task. This cannot be undone.'
    )

    def is_success(self):
        return self.success

class Critic(ChildAgent[Input, CriticReview]):
    __LLM_ARGS__ = dict( json = True )
    __OUTPUT_PARSER__ = PydanticOutputParser(pydantic_object=CriticReview)
    """
    Critic agents evaluate code
    """
    def review_result(self, result: Input, **kw) -> CriticReview:
        args = dict(
            result=result,
            parent=self.parent
        )
        args.update(**kw)
        resp = self.get_single_agent_response(args)
        return resp.value

    def invoke_agent(self, input: dict, **kwargs: Any) -> CriticReview:
        return self.review_result(input, **kwargs)