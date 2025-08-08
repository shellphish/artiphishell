import os
import re
from pathlib import Path
from typing import List, Optional, Any, Dict

import jinja2
from langchain.agents import AgentExecutor
from langchain_core.runnables import (
    Runnable, RunnableAssign,
    RunnableSequence, RunnableParallel,
    RunnableLambda
)
from langchain_core.runnables.utils import Input, Output
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import JsonOutputParser, PydanticOutputParser
from langchain_core.prompts import (
    PromptTemplate, SystemMessagePromptTemplate,
    HumanMessagePromptTemplate, AIMessagePromptTemplate
)
from pydantic import BaseModel, Field

from .logger import BaseLogger
from .available_llms import ModelRegistry, USE_LLM_API

DEFAULT_TEMPERATURE = 0

def render_jinja2_template_string(template: str, **kwargs):
    return jinja2.Template(template).render(**kwargs)

class BaseObject(BaseLogger):
    @classmethod
    def get_class_name(cls):
        return cls.__name__

    def get_simple_json(self):
        return f'<{self.get_class_name()}>'

    @classmethod
    def __all_subclasses__(cls):
        for subcls in cls.__subclasses__():
            yield subcls
            for subsubcls in subcls.__all_subclasses__():
                yield subsubcls
    @classmethod
    def __all_subclasses_map__(cls):
        return {
            sc.__name__: sc
            for sc in cls.__all_subclasses__()
        }


import logging
log = logging.getLogger(__name__)

class BasePromptTemplate(BaseObject, PromptTemplate):
    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

class PromptFileTemplate(BasePromptTemplate):
    loaded_from: Optional[str] = None

from langchain_core.runnables import config as runnables_config
from langchain_core.callbacks import manager as callback_manager_mod

class BaseRunnable(BaseLogger, Runnable[Input, Output]):
    # These models support the response_format=json_object param
    __SUPPORTS_JSON_MODELS__ = [
        'gpt-4o',
        'gpt-4-turbo-preview',
        'gpt-4-turbo',
        'gpt-3.5-turbo'
    ]

    def __init__(self):
        super().__init__()
        self.runnable_config = None

    def trigger_callback_event(self, event_name, *args, config=None, **kwargs):
        """
        Trigger a callback.
        Built in langchain callbacks: https://python.langchain.com/docs/modules/callbacks/
        Or any custom function you define on a common.base.CustomCallbackHandler subclass.
        """
        config = config or self.runnable_config
        config = runnables_config.ensure_config(config)

        callback_manager = runnables_config.get_callback_manager_for_config(config)

        # Trigger a built-in event
        if hasattr(callback_manager, event_name):
            return getattr(callback_manager, event_name)(*args, **kwargs)
        
        # Manually trigger a custom event
        kwargs['run_id'] = ''
        kwargs['parent_run_id'] = callback_manager.parent_run_id
        kwargs['tags'] = (
            kwargs.get('tags', []) +
            (callback_manager.tags or [])
        )
        handlers = [
            h for h in callback_manager.handlers
            if isinstance(h, CustomCallbackHandler)
            and hasattr(h, event_name)
        ]
        if len(handlers) == 0:
            return

        return callback_manager_mod.handle_event(
            handlers,
            event_name, None,
            # Args for the event
            *args, **kwargs
        )


    @classmethod
    def get_llm_by_name(cls, name, **kwargs):
        v = ModelRegistry.get_llm_class_by_name(name)

        mn, co = v

        model_kwargs = dict(
            raise_on_budget_exception=kwargs.pop('raise_on_budget_exception', True),
            raise_on_rate_limit_exception=kwargs.pop('raise_on_rate_limit_exception', False),
        )
        kwargs['model_kwargs'] = model_kwargs


        if 'o1' in mn or 'o3' in mn or 'o4' in mn:
            # temp not supported on o series models
            kwargs['temperature'] = 1
            if 'max_tokens' in kwargs:
                kwargs['max_completion_tokens'] = kwargs.pop('max_tokens')
        else:
            kwargs['temperature'] = kwargs.get('temperature', DEFAULT_TEMPERATURE)

        is_json = kwargs.pop('json', False)
        if is_json:
            if mn not in cls.__SUPPORTS_JSON_MODELS__:
                cls.warn_static(f'Model {mn} does not support JSON Object mode, syntax will not be enforced')
            else:
                model_kwargs['response_format'] = dict(type='json_object')

        # If not using the llm api, we will strip special kwargs
        if not USE_LLM_API:
            model_kwargs.pop('raise_on_budget_exception', None)
            model_kwargs.pop('raise_on_rate_limit_exception', None)

        return co(model=mn, **kwargs)

    @classmethod
    def load_prompt(
            cls,
            template: str|None = None,
            role: str|None = 'system',
            default: str|None = None,
            must_exist = True
    ):
        loaded_from_file = None
        if isinstance(template, PromptTemplate):
            pass
        elif isinstance(template, str):
            if re.match(r'^[a-zA-Z0-9_\-/.]+$', template):
                template_file_name = template
                f_template = load_prompt_template_from_file(
                    template, must_exist=False
                )
                if f_template:
                    template = f_template
                elif must_exist and (
                    '.' in template
                    or '/' in template
                ):
                    raise ValueError(f'Prompt template file not found: {template}')
                loaded_from_file = template_file_name
            
            # Otherwise treat the template as the string itself

        if not template and default:
            cls.log_error_static(f'No {role} prompt template found for runnable {cls.__name__}, using provided default')

            # If we don't have a template, try to load the default
            template = cls.load_prompt(
                template=default,
                role=role,
                default=None,
                must_exist=False
            )
            if template:
                return template

        if not template and must_exist:
            raise ValueError(f'No {role} prompt template found for agent {cls.__name__}')
        if not template:
            return None
        
        if isinstance(template, tuple):
            if len(template) == 2 and template[0] in ['user', 'human', 'USER', 'HUMAN']:
                template = template[1]
        elif isinstance(template, list):
            if len(template) == 2 and template[0] in ['user', 'human', 'USER', 'HUMAN']:
                template = template[1]

        if isinstance(template, PromptTemplate):
            pass
        elif type(template) is str:
            template: PromptFileTemplate = PromptFileTemplate.from_template(
                template,
                template_format='jinja2' # XXX Force jinja2 for now
            )
            if loaded_from_file:
                template.loaded_from = loaded_from_file

        if role == 'system':
            return SystemMessagePromptTemplate(prompt = template)
        elif role == 'user':
            return HumanMessagePromptTemplate(prompt = template)
        elif role == 'assistant' or role == 'agent' or role == 'bot':
            return AIMessagePromptTemplate(prompt = template)

        return template



PROMPT_SEARCH_PATHS = [
    Path(__file__).parent.parent.parent / 'prompts',
]

def add_prompt_search_path(path):
    if isinstance(path, str):
        path = Path(path)
    PROMPT_SEARCH_PATHS.append(path.resolve())
    
def find_prompt_template(
    fname,
    must_exist=True
) -> Path:
    if isinstance(fname, Path):
        if fname.exists():
            return fname

    checked_files: List[Path] = []

    search_path = PROMPT_SEARCH_PATHS.copy()
    search_path.append(Path.cwd())
    search_path.append(Path.cwd() / 'prompts')
    search_path.append(Path.cwd() / 'templates')
    search_path.append(Path.cwd() / 'templates' / 'prompts')

    for d in search_path:
        abs_dir = d.absolute()
        possible_path: Path = abs_dir / fname
        checked_files.append(possible_path)

        for ext in [None, '.txt','.j2','.md','.html']:
            if ext:
                full_path = possible_path.with_suffix(ext)
            else:
                full_path = possible_path
            if full_path.exists():
                return full_path

    for c in checked_files:
        print(f'Checking for prompt template: {c}')

    print(f'Prompt template not found: {fname}')

    if must_exist:
        raise ValueError(f'Prompt template not found: {fname}')
    return None

def load_prompt_template_from_file(
        fname,
        directory=None,
        must_exist=True,
        **kwargs
):
    fpath: Path = find_prompt_template(
        fname,
        must_exist=True
    )
    if not fpath or not fpath.exists():
        if not must_exist:
            return None
        raise ValueError(f'Prompt template not found: {fname}')

    if fpath.suffix in ['.j2','.jinja2', '.py'] or True:
        return PromptTemplate.from_file(
            template_file=fpath,
            template_format='jinja2'
        )
    return PromptTemplate.from_file(fpath, **kwargs)

from langchain_core.messages import BaseMessage, AIMessage,AIMessageChunk

class CustomCallbackHandler(BaseCallbackHandler, BaseLogger):
    pass

class LangChainLogger(CustomCallbackHandler):
    class CurrentChain(BaseLogger):
        def __init__(self, name=None, inputs=None, serialized=None):
            self.name = name
            self.inputs = inputs
            self.serialized = serialized
            self._actual_class = None

        def get_class(self):
            if self._actual_class:
                return self._actual_class
            self._actual_class = self.get_class_uncached()
            return self._actual_class

        def get_class_uncached(self):
            if self.name == 'RunnableSequence':
                return RunnableSequence
            if self.name == 'AgentExecutor':
                return AgentExecutor
            if self.name == 'ChatPromptTemplate':
                return ChatPromptTemplate
            if self.name == 'JsonOutputParser':
                return JsonOutputParser
            if self.name.startswith('RunnableAssign'):
                return RunnableAssign
            if self.name.startswith('RunnableParallel'):
                return RunnableParallel
            if self.name.startswith('RunnableLambda'):
                return RunnableLambda
            if self.name.startswith('PydanticOutputParser'):
                return PydanticOutputParser
            # TODO RunnableParallel

            from .object import BaseObject
            return (
                BaseObject.__all_subclasses_map__()
                .get(self.name)
            )

        def save(self):
            pass

    class CurrentLLMCall(BaseLogger):
        def __init__(self, prompt: List[BaseMessage]=None, output: BaseMessage=None):
            self.prompt = prompt
            self.output = None

        def save(self):
            pass
    
    class CurrentTool(BaseLogger):
        def __init__(self, serialized=None, input_str=None):
            self.serialized = serialized
            self.input_str = input_str
        
        def save(self):
            pass

    class ExceptionTag(object):
        def __init__(self, tag):
            self.tag = tag
        def save(self):
            pass

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.current_llm_call: LangChainLogger.CurrentLLMCall = None
        self.chain_stack: List[LangChainLogger.CurrentChain] = []
        self.tool_stack: List[LangChainLogger.CurrentTool] = []

    @property
    def current_chain(self) -> CurrentChain:
        return next((
            x for x in self.chain_stack[::-1]
            if not isinstance(x, self.ExceptionTag)
        ), None)
    
    @property
    def current_tool(self) -> CurrentTool:
        return next((
            x for x in self.tool_stack[::-1]
            if not isinstance(x, self.ExceptionTag)
        ), None)


    def tag_for_exception(self, tag: str, **kwargs):
        tag = self.ExceptionTag(tag)
        self.chain_stack.append(tag)
        self.tool_stack.append(tag)
        return True

    def reset_to_tag(self, tag:str, keep_tag=False) -> tuple[List[CurrentChain], List[CurrentTool]]:

        def slice_stack(stack, tag, keep_tag) -> tuple[List, List]:
            to_remove = []
            for i in range(len(stack)-1, -1, -1):
                val = stack[i]
                if isinstance(val, self.ExceptionTag):
                    if not val.tag == tag:
                        continue
                    # Found our tag
                    slice_ind = i + 1 if keep_tag else i
                    return stack[:slice_ind], to_remove
                to_remove.append(val)
            return stack, []

        self.chain_stack, chain_remove = slice_stack(self.chain_stack, tag, keep_tag)
        self.tool_stack, tool_remove = slice_stack(self.tool_stack, tag, keep_tag)
        return chain_remove, tool_remove
    
    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        self.current_llm_call = self.CurrentLLMCall(
            prompt=prompts
        )
        model = (
            serialized.get('kwargs', {}).get('model_name')
            or serialized.get('kwargs', {}).get('model')
            or serialized.get('repr', 'Unknown Model')
        )

        cls = self.find_best_logging_class()

        logf = cls.info_static if os.environ.get('LOG_LLM') else cls.debug_static

        cls.info_static(f'.---=== Inferencing with {model} on ~{sum(map(len, prompts))} bytes')

        for p in prompts:
            for line in p.split('\n'):
                line_s = line.strip()
                if (
                    line_s.startswith('Human:')
                    or line_s.startswith('AI:')
                    or line_s.startswith('System:')
                ):
                    name, line = line.split(': ', 1)
                    logf(f'|---[{name}]---===========================')
                logf(f'|  {line}')
            logf('|')
            logf(f'|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            logf(f'|')
            logf(f'|  WAITING ON LLM API...')
            logf(f'|')



    def find_best_logging_class(self, cls=None):
        if cls and hasattr(cls, 'info_static'):
            return cls

        for c in self.chain_stack[::-1]:
            if isinstance(c, self.ExceptionTag):
                continue
            cls = c.get_class()
            if cls and hasattr(cls, 'info_static'):
                return cls
        return self.__class__
    
    def on_llm_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        gen = outputs.generations[0][0]

        cls = self.find_best_logging_class()

        logf = cls.info_static if os.environ.get('LOG_LLM') else cls.debug_static
        
        logf(f'|---[AI]---===========================')
        for line in gen.text.split('\n'):
            logf(f'|  {line}')
        cls.info_static(f'\'---=== Received inference of ~{len(gen.text)} bytes\n\n\n')



    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], *args, **kwargs: Any
    ) -> None:
        """Print out that we are entering a chain."""
        if serialized is None:
            serialized = {}
        class_name = kwargs.get('name') or serialized.get("name", serialized.get("id", ["<unknown>"])[-1])
        current_chain = self.CurrentChain(
            name=class_name,
            inputs=inputs,
            serialized=serialized
        )
        self.chain_stack.append(current_chain)
        #cls = self.find_best_logging_class()
        #cls.debug_static(f"\n\n\033[1m> Entering new {class_name} chain...\033[0m")

    def on_chain_end(self, outputs: Dict[str, Any], *args, **kwargs: Any) -> None:
        """Print out that we finished a chain."""
        #cls = self.find_best_logging_class()
        #cls.debug_static("\n\033[1m> Finished chain.\033[0m")

        lc = None
        if self.chain_stack and len(self.chain_stack) > 0:
            lc = self.chain_stack.pop()
        if lc:
            lc.save()

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str,**kwargs: Any) -> Any:
        name = serialized.get('name')

        current_tool = self.CurrentTool(
            serialized=serialized,
            input_str=input_str
        )
        self.tool_stack.append(current_tool)

        cls = self.find_best_logging_class()
        cls.info_static(f"\n\033[1m> Starting tool: {name}\033[0m")

    def on_tool_end(self, output: Any, **kwargs: Any) -> Any:
        """Print out that we finished a tool."""
        cls = self.find_best_logging_class()
        cls.info_static("\n\033[1m> Finished tool.\033[0m")

        lc = None
        if self.tool_stack and len(self.tool_stack) > 0:
            lc = self.tool_stack.pop()
        if lc:
            lc.save()
    
    def on_agent_annotation(self, **kwargs):
        pass

class ContinueConversationException(Exception):
    """
    Subclass this exception to raise an exception which still allows the last message to be saved in the conversation history.
    For example if a parser wants to give the model a chance to retry, it will want to save the raw message in the cov history.
    To make use of this feature use an AgentWithHistory subclass.
    """
    pass

