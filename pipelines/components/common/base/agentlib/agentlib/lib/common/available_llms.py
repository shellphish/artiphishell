import os
from typing import Type, Tuple
import logging
log = logging.getLogger(__name__)

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.language_models.chat_models import BaseChatModel

USE_LLM_API = os.getenv('USE_LLM_API', '0')
USE_LLM_API = USE_LLM_API.lower() not in (
    '0', 'false', 'no', 'off', 'disable',
    'disabled', 'nope', 'nah', 'n', ''
)
USE_LLM_API = True # Always use LLM API during competition

if USE_LLM_API:
    if not os.getenv('AIXCC_LITELLM_HOSTNAME',''):
        raise ValueError('USE_LLM_API is enabled but AIXCC_LITELLM_HOSTNAME is not set')
    if not os.getenv('LITELLM_KEY',''):
        raise ValueError('USE_LLM_API is enabled but LITELLM_KEY is not set')

model_entry = Tuple[str, Type[BaseChatModel]]

class AgentLibLLM(object):
    __SUPPORTS_TOOL_CALLS__ = False

    def create_tools_agent(self, *args, **kwargs):
        raise NotImplementedError('This model does not support tool calls')

class ModelRegistry(object):
    __USING_LLM_API__ = USE_LLM_API
    __MODEL_NAME_TO_CLASS__: dict[str, model_entry] = {}
    __OPENAI_MODEL_CLASS__ = None
    __ANTHROPIC_MODEL_CLASS__ = None

    __CHAT_PROMPT_TEMPLATE_CLASS__ = ChatPromptTemplate

    @classmethod
    def get_prompt_template_class(cls) -> Type[ChatPromptTemplate]:
        if len(cls.__MODEL_NAME_TO_CLASS__) == 0:
            cls.init_all_models()
        return cls.__CHAT_PROMPT_TEMPLATE_CLASS__

    @classmethod
    def get_llm_class_by_name(cls, name) -> model_entry:
        if len(cls.__MODEL_NAME_TO_CLASS__) == 0:
            cls.init_all_models()

        target = cls.__MODEL_NAME_TO_CLASS__.get(name)
        if not target:
            raise ValueError(f'No model found with name: {name}, see https://github.com/shellphish-support-syndicate/agentlib/tree/main/agentlib/lib/common/available_llms.py for all available models')

        # Resolve model aliases
        seen = set()
        while type(target) == str:
            if target in seen:
                raise ValueError(f'Invalid model alias: {name}, recursive aliasing detected')
            n_v = cls.__MODEL_NAME_TO_CLASS__.get(target)
            if not n_v:
                raise ValueError(f'Invalid model alias: {name}, no model found for alias: {target}, Please report this issue as something is wrong with the model registry.')
            seen.add(target)
            target = n_v

        return target

    @classmethod
    def __init_openai(cls):
        pfx = ''
        if cls.__USING_LLM_API__:
            from .llm_api import ChatApiOpenAi
            cls.__OPENAI_MODEL_CLASS__= ChatApiOpenAi
            pfx = 'oai-'
        else:
            from langchain_openai import ChatOpenAI
            from langchain.agents import create_openai_tools_agent

            class ChatOpenAIAgentLib(ChatOpenAI, AgentLibLLM):
                __SUPPORTS_TOOL_CALLS__ = True
                def create_tools_agent(self, *args, **kwargs):
                    return create_openai_tools_agent(self, *args, **kwargs)

            cls.__OPENAI_MODEL_CLASS__ = ChatOpenAIAgentLib

        mcls = cls.__OPENAI_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({
            # gpt-4o
            'openai/gpt-4o': (f'{pfx}gpt-4o', mcls),
            'gpt-4o': 'openai/gpt-4o',

            # gpt-4-turbo
            'openai/gpt-4-turbo-preview': (
                f'{pfx}gpt-4-turbo-preview', mcls
            ),
            'openai/gpt-4-turbo': (
                f'{pfx}gpt-4-turbo', mcls
            ),
            'gpt-4-turbo': 'openai/gpt-4-turbo',

            # gpt-4
            'openai/gpt-4': (f'{pfx}gpt-4', mcls),
            'gpt-4': 'openai/gpt-4',

            # gpt-3.5-turbo
            'openai/gpt-3.5-turbo': (f'{pfx}gpt-3.5-turbo', mcls),
            'gpt-3.5-turbo': 'openai/gpt-3.5-turbo',
        })

    @classmethod
    def __init_anthropic(cls):
        pfx = ''
        if cls.__USING_LLM_API__:
            from .llm_api import ChatApiAnthropic
            cls.__ANTHROPIC_MODEL_CLASS__ = ChatApiAnthropic
        else:
            from langchain_anthropic import ChatAnthropic
            from .anthropic_agent import create_anthropic_tools_agent

            class ChatAnthropicAgentLib(ChatAnthropic, AgentLibLLM):
                __SUPPORTS_TOOL_CALLS__ = True

                def create_tools_agent(self, *args, **kwargs):
                    return create_anthropic_tools_agent(self, *args, **kwargs)

            cls.__ANTHROPIC_MODEL_CLASS__ = ChatAnthropicAgentLib

        mcls = cls.__ANTHROPIC_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({
            # claude-3.5-sonnet
            'anthropic/claude-3.5-sonnet-20240620': (
                'claude-3.5-sonnet'
                    if cls.__USING_LLM_API__ else
                'claude-3.5-sonnet-20240620',
                mcls
            ),
            'anthropic/claude-3.5-sonnet': 'anthropic/claude-3.5-sonnet-20240620',
            'claude-3.5-sonnet': 'anthropic/claude-3.5-sonnet',

            # claude-3-opus
            'anthropic/claude-3-opus-20240229': (
                'claude-3-opus'
                    if cls.__USING_LLM_API__ else
                'claude-3-opus-20240229',
                mcls
            ),
            'anthropic/claude-3-opus': 'anthropic/claude-3-opus-20240229',
            'claude-3-opus': 'anthropic/claude-3-opus',

            # claude-3-sonnet
            'anthropic/claude-3-sonnet-20240229': (
                f'claude-3-sonnet'
                    if cls.__USING_LLM_API__ else
                f'claude-3-sonnet-20240229',
                mcls
            ),
            'anthropic/claude-3-sonnet': 'anthropic/claude-3-sonnet-20240229',
            'claude-3-sonnet': 'anthropic/claude-3-sonnet',

            # claude-3-haiku
            'anthropic/claude-3-haiku-20240307': (
                f'claude-3-haiku'
                    if cls.__USING_LLM_API__ else
                f'claude-3-haiku-20240307',
                mcls
            ),
            'anthropic/claude-3-haiku': 'anthropic/claude-3-haiku-20240307',
            'claude-3-haiku': 'anthropic/claude-3-haiku',
        })

    @classmethod
    def init_all_models(cls):
        if cls.__USING_LLM_API__:
            from .llm_api import ApiChatPromptTemplate
            cls.__CHAT_PROMPT_TEMPLATE_CLASS__ = ApiChatPromptTemplate

        try:
            cls.__init_openai()
        except Exception as e:
            log.warning(f'Failed to import langchain_openai No gpt models will be available: {e}')

        try:
            cls.__init_anthropic()
        except Exception as e:
            log.warning(f'Failed to import langchain_anthropic No claude models will be available: {e}')
