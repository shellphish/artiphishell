import re
import ast
import astunparse
from typing import List, Optional, Any, Type

from langchain_core.runnables.utils import Input, Output
from langchain_core.output_parsers import BaseOutputParser
from langchain_core.load.serializable import Serializable
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser

from .code import Code
from .base import BaseObject
from .object import SaveLoadObject, SerializableType

class GeneratedCode(Code):
    pass

class BaseParser(SaveLoadObject, BaseOutputParser[Output]):
    def get_format_instructions(self) -> str:
        return 'Output the output and avoid extraneous text'

class JSONParser(BaseParser[Output]):
    """This parser is used to parse JSON objects. Make sure to include `output_format` in your template to use this parser."""

    use_fallback: Optional[bool] = False
    """If true, when the output fails to parse, uses gpt-4-turbo try and rewrite it to match the expected schema"""

    object_mode: Optional[bool] = True

    def get_parser(self) -> JsonOutputParser:
        return JsonOutputParser()
    
    def invoke(self, *args, **kwargs) -> Output:
        try:
            return self.get_parser().invoke(*args, **kwargs)
        except Exception as e:
            self.warn(f'Failed to parse with {self.get_parser()}')

            if '\\0' in args[0].content:
                self.warn('Detected incorrectly escaped null character, attempting to fix...')
                args[0].content = args[0].content.replace('\\0', '\\u0000')
                try:
                    return self.get_parser().invoke(*args, **kwargs)
                except Exception as e:
                    self.warn(f'Failed to parse with {self.get_parser()}')

            return self.parse_fallback(
                args[0].content,
                exp=e,
                config=args[1]
                    if len(args) > 1
                    else None
            )

    def parse_fallback(self, text: str, exp=None, config=None) -> Output:
        text = text.strip()
        json_pattern = re.compile(r"```(?:json)(.*?)```", re.DOTALL)
        data = json_pattern.findall(text)
        if len(data) > 0:
            data = data[0]
            try:
                return self.get_parser().parse(data)
            except Exception as e:
                self.warn(f'Failed to parse with {self.get_parser()} after extracting json from ```json...')
                exp = e
        
        json_pattern = re.compile(r"```(.*?)```", re.DOTALL)
        data = json_pattern.findall(text)
        if len(data) > 0:
            data = data[0]
            try:
                return self.get_parser().parse(data)
            except Exception as e:
                self.warn(f'Failed to parse with {self.get_parser()} after extracting json from ```...')
                exp = e
        
        if self.use_fallback:
            return self.fallback_gpt4_formatter(text, config=config)

        if exp:
            raise exp
        raise ValueError('Failed to parse the provided output with the JSON parser')

        
    def parse(self, text: str) -> Output:
        try:
            return self.get_parser().parse(text)
        except Exception as e:
            self.warn(f'Failed to parse with {self.get_parser()}')
            return self.parse_fallback(text, exp=e)

    def get_format_instructions(self) -> str:
        return self.get_parser().get_format_instructions() + '\nThe json object should be surrounded by triple backticks like this:\n```json\n{...\n}\n```'

    def fallback_gpt4_formatter(self, text: str, config=None) -> Output:
        from ..agents import LLMFunction
        f = LLMFunction.create(
'''
# Task
The provided output does not match the expected schema. You must recreate the output to match the expected schema with as little modification as possible. You must follow the output schema exactly or the output will be rejected!
# Output Schema
{{ output_format }}
''',
'''
# Original Response
{{ input }}
''',
            model='gpt-4o',
            output=self.get_parser(),
            temperature=0.0,
            config=config,
            json=self.object_mode,
        )
        return f(
            output_format=self.get_format_instructions(),
            input=text,
        )

class ObjectParser(JSONParser[Output]):
    """This parser uses Pydantic to give the LLM a schema of any LocalObject or SaveLoadObject (or other Pydantic object). Make sure to include `output_format` in your template to use this parser.""" 

    object_type: Optional[SerializableType]
    use_fallback: Optional[bool] = False
    """If true, when the output fails to parse, uses gpt-4-turbo try and rewrite it to match the expected schema"""

    def __init__(
        self,
        object_type: Type[Serializable] = None,
        **kwargs
    ):
        kwargs['object_type'] = object_type
        if (
            object_type is not None
            and not isinstance(object_type, SerializableType)
        ):
            kwargs['object_type'] = SerializableType(object_type)

        super().__init__(**kwargs)
        self._pydantic_parser = None

    def get_parser(self) -> PydanticOutputParser:
        if self._pydantic_parser:
            return self._pydantic_parser

        assert(self.object_type is not None)

        obj_type = self.object_type.get_type()

        assert(obj_type is not None)

        self._pydantic_parser = PydanticOutputParser(
            pydantic_object=obj_type
        )
        return self._pydantic_parser

class ParsesFromString(BaseParser[Output]):
    def invoke(self, input: str, config=None, **kwargs: Any) -> GeneratedCode:
        kwargs['config'] = config
        if type(input) is dict:
            if 'output' in input:
                input = input['output']
            elif 'text' in input:
                input = input['text']
            elif 'log' in input:
                input = input['log']
            else:
                raise ValueError(f"Invalid input: {input}")
        return super().invoke(input, **kwargs)

class PlainTextOutputParser(ParsesFromString[str]):
    @staticmethod
    def parse_code_from_message(message: str) -> str:
        return message

    def parse(self, text: str) -> str:
        return self.parse_code_from_message(text)

class CodeExtractor(ParsesFromString[GeneratedCode]):
    language: Optional[str]

    @classmethod
    def parse_code_from_message(cls, message: str) -> GeneratedCode:
        code_pattern = re.compile(r"```(?:\w*)(.*?)```", re.DOTALL)
        code = "\n".join(code_pattern.findall(message))
        return GeneratedCode.from_generic_source(code)

    def parse(self, text: str) -> GeneratedCode:
        return self.parse_code_from_message(text)

    def get_format_instructions(self) -> str:
        ln = self.language or 'langname'
        return f'Output the required {self.language or ""} code block, surrounded by triple backticks, like this:\n```{ln}\n...\n```'


class PythonCodeExtractor(CodeExtractor):
    __DO_PARSE__: bool = True
    language: str = 'python'

    @classmethod
    def parse_code_from_message(cls, message: str) -> GeneratedCode:
        code_pattern = re.compile(r"```(?:python|py)(.*?)```", re.DOTALL)
        code = "\n".join(code_pattern.findall(message))
        if not cls.__DO_PARSE__:
            return GeneratedCode.from_generic_source(code)
        return GeneratedCode.from_python_source(code)


class JavaCodeExtractor(CodeExtractor):
    __DO_PARSE__: bool = False
    language: str = 'java'

    @classmethod
    def parse_code_from_message(cls, message: str) -> GeneratedCode:
        code_pattern = re.compile(r"```(?:java)(.*?)```", re.DOTALL)
        code = "\n".join(code_pattern.findall(message))
        if not cls.__DO_PARSE__:
            return GeneratedCode.from_generic_source(code)
        return GeneratedCode.from_java_source(code)
