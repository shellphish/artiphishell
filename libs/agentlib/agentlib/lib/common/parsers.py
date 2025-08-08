import re
import ast
import json
import astunparse
from typing import List, Optional, Any, Type

from langchain_core.runnables.utils import Input, Output
from langchain_core.output_parsers import BaseOutputParser
from langchain_core.load.serializable import Serializable
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser

from .code import Code
from .base import BaseObject, ContinueConversationException
from .object import SaveLoadObject, SerializableType

class GeneratedCode(Code):
    pass

class BaseParser(SaveLoadObject, BaseOutputParser[Output]):
    __SUPPORTS_JSON_SCHEMA__: bool = False

    def get_format_instructions(self) -> str:
        return 'Output the output and avoid extraneous text'

class JSONParser(BaseParser[Output]):
    """This parser is used to parse JSON objects. Make sure to include `output_format` in your template to use this parser."""

    __SUPPORTS_STRUCTURED_OUTPUT__: bool = True

    use_fallback: Optional[bool] = False
    """If true, when the output fails to parse, uses gpt-4o try and rewrite it to match the expected schema"""

    object_mode: Optional[bool] = True

    def should_use_structured_output(self) -> bool:
        return self.object_mode

    def get_parser(self) -> JsonOutputParser:
        return JsonOutputParser()
    
    def invoke(self, *args, **kwargs) -> Output:
        args = list(args)
        val = args[0]

        
        if type(val) is dict:
            # This is probably a structured output
            raw = val.get('raw') or val.get('output') or None

            if raw:
                args[0] = raw
            
            parsed = val.get('parsed', None)
            if parsed:
                # lite TODO there is probably a better way
                return self.parse(json.dumps(parsed))
            
            if not raw:
                raise ValueError('Unexpected structured output format')

        exp = None
        try:
            return self.get_parser().invoke(*args, **kwargs)
        except Exception as e:
            self.warn(f'Failed to parse with {self.get_parser()}')
            exp = e

        content = args[0]
        if not isinstance(content, str):
            content = content.content
        
        try:
            if '\\0' in content:
                self.warn('Detected incorrectly escaped null character, attempting to fix...')
                content = content.replace('\\0', '\\u0000')
                args[0] = content
                return self.get_parser().invoke(*args, **kwargs)
        except Exception as e:
            self.warn(f'Failed to parse with {self.get_parser()}')
            exp = e
            
        return self.parse_fallback(
            content,
            exp=exp or None,
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
        # TODO use strucutred outputs to do this when we have a schema
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

    __SUPPORTS_STRUCTURED_OUTPUT__: bool = True
    __SUPPORTS_JSON_SCHEMA__: bool = True

    object_type: Optional[SerializableType]
    use_fallback: Optional[bool] = False
    use_structured_output: Optional[bool] = False
    strict: Optional[bool] = False
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

    def should_use_structured_output(self) -> bool:
        return self.use_structured_output

    def should_use_strict_mode(self) -> bool:
        return self.strict

    def get_json_schema(self) -> dict[str, Any]:
        parser = self.get_parser()
        return parser._get_schema(self.object_type.get_type())

    def uses_strict_mode(self) -> bool:
        return self.use_strict_mode

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
        results = code_pattern.findall(message)
        if len(results) == 0:
            if '```' in message:
                code_pattern = re.compile(r"```(?:\w*)(.*)", re.DOTALL)
                results = code_pattern.findall(message)
                if len(results) == 0:
                    raise NoCodeFoundException(message)
                else:
                    raise CodeCutoffException(results[0], message)
            raise NoCodeFoundException(message)
        code = "\n".join(results)
        return GeneratedCode.from_generic_source(code)

    def parse(self, text: str) -> GeneratedCode:
        return self.parse_code_from_message(text)

    def get_format_instructions(self) -> str:
        ln = self.language or 'langname'
        return f'Output the required {self.language or ""} code block, surrounded by triple backticks, like this:\n```{ln}\n...\n```'

class CodeCutoffException(ContinueConversationException):
    source_code: str
    raw_message: str

    def __init__(self, source_code: str, raw_message: str):
        self.source_code = source_code
        self.raw_message = raw_message

class NoCodeFoundException(ContinueConversationException):
    raw_message: str

    def __init__(self, raw_message: str):
        self.raw_message = raw_message

class PythonCodeExtractor(CodeExtractor):
    __DO_PARSE__: bool = True
    language: str = 'python'

    @classmethod
    def parse_code_from_message(cls, message: str) -> GeneratedCode:
        code_pattern = re.compile(r"```(?:python|py)(.*?)```", re.DOTALL)
        results = code_pattern.findall(message)
        if len(results) == 0:
            if '```' in message:
                code_pattern = re.compile(r"```(?:python|py)(.*)", re.DOTALL)
                results = code_pattern.findall(message)
                if len(results) == 0:
                    raise NoCodeFoundException(message)
                else:
                    raise CodeCutoffException(results[0], message)
            raise NoCodeFoundException(message)
        code = "\n".join(results)
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
