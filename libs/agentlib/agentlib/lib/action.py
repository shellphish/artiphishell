from langchain.pydantic_v1 import BaseModel, Field
from langchain.tools import BaseTool, StructuredTool, tool
from langchain_core.runnables import RunnableSerializable
from typing import Dict, Any, Union


class Skill(BaseTool):
    pass

from .common.base import BaseRunnable


class Action(BaseRunnable):
    def __init__(self, name, query):
        super().__init__()
        self.name = name

    def __repr__(self):
        return f'Action(name={self.name}, query={self.query})'
