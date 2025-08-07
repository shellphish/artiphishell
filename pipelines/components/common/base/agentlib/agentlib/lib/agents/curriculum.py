import os
import json
import subprocess
from typing import Union, Optional, Any, Dict, List, Generic

from langchain_core.runnables.utils import Input, Output

from .agent import ChildAgent

class Curriculum(ChildAgent[Input, Output]):
    def invoke_agent(self, question: Input, **kwargs: Any) -> Output:
        if type(question) is str:
            question = dict(question=question)
        self.runnable_config = kwargs.get('config', self.runnable_config)
        self.info(f"Curriculum invoked with question `{question}`")

        return super().invoke_agent(question, **kwargs)
