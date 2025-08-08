from functools import wraps
from typing import Callable, Union, Dict
from pydantic import Field

from langchain.tools import tool as tool_raw, BaseTool, StructuredTool

from ..common import SaveLoadObject

TOOL_REGISTRY: Dict[str, BaseTool] = {}

class SerializedTool(SaveLoadObject):
    """
    This is a serialized representation of a @agentlib.tools.tool decorated function.
    Don't pass this to langchain, instead get the actual tool first by calling t.get_tool()
    Or if you have a list of SerializedTool, call agentlib.tools.tool_wrapper.get_langchain_tools() to get the list of actual tools.
    """
    module: str
    name: str

    def get_cache_key(self) -> str:
        return f'{self.module}.{self.name}'

    def _add_to_registry(self, tool: BaseTool):
        key = self.get_cache_key()
        if key in TOOL_REGISTRY:
            raise ValueError(f'Tool {key} already exists in tool registry. This means more than one tools named {self.name} is defined in {self.module}.')
        TOOL_REGISTRY[key] = tool

    def get_tool(self) -> BaseTool:
        key = self.get_cache_key()
        if key in TOOL_REGISTRY:
            return TOOL_REGISTRY[key]
        raise ValueError(f'Tool {key} not found in registry, make sure you have imported {self.module} and that {self.name} is defined in it and using @tools.tool decorator.')

    def __call__(self, *args, **kwargs):
        return self.get_tool()(*args, **kwargs)


def get_langchain_tools(tools: list[Union[BaseTool, SerializedTool]]) -> list[BaseTool]:
    loaded_tools = []
    for tool in tools:
        if isinstance(tool, SerializedTool):
            tool = tool.get_tool()
        
        loaded_tools.append(tool)
    
    return loaded_tools

def include_param_descriptions(tool: StructuredTool):
    for k,v in tool.args_schema.__fields__.items():
        f = Field(
            name = v.name,
            type = v.type,
            required = v.required,
            #default = v.default,
            description = v.field_info.description
        )



def tool(func: Callable) -> Callable:
    func_module = func.__module__
    func_name = func.__name__
    tool_obj = SerializedTool(module=func_module, name=func_name)

    base_tool = tool_raw(func)
    #include_param_descriptions(base_tool) # TODO parse out arg descriptions

    tool_obj._add_to_registry(base_tool) 
    return tool_obj