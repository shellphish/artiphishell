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
            raise ValueError(f'No model found with name: {name}, see https://github.com/shellphish-support-syndicate/artiphishell/blob/main/libs/agentlib/agentlib/lib/common/available_llms.py#L117 for all available models')

        # Resolve model aliases
        seen = set()
        while isinstance(target, str):
            if target in seen:
                raise ValueError(f'Invalid model alias: {name}, recursive aliasing detected')
            n_v = cls.__MODEL_NAME_TO_CLASS__.get(target)
            if not n_v:
                raise ValueError(f'Invalid model alias: {name}, no model found for alias: {target}, Please report this issue as something is wrong with the model registry.')
            seen.add(target)
            target = n_v

        return target

    @classmethod
    def __init_google(cls):
        pfx = ''
        if cls.__USING_LLM_API__:
            from .llm_api import ChatApiGoogle
            cls.__GOOGLE_MODEL_CLASS__ = ChatApiGoogle
            pfx = ''
        
        else:
            from langchain_google_genai import ChatGoogleGenerativeAI
            from .langchain_agent.google_agent import create_google_tools_agent

            class ChatGoogleAgentLib(ChatGoogleGenerativeAI, AgentLibLLM):
                __SUPPORTS_TOOL_CALLS__ = True
                __SUPPORTS_STRUCTURED_OUTPUT__ = False

                def create_tools_agent(self, *args, **kwargs):
                    return create_google_tools_agent(self, *args, **kwargs)

            cls.__GOOGLE_MODEL_CLASS__ = ChatGoogleAgentLib

        mcls = cls.__GOOGLE_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({
            'google/gemini-2.5-pro-preview': (
                'gemini-2.5-pro-preview'
                    if cls.__USING_LLM_API__ else
                'models/gemini-2.5-pro-preview-05-06',
                mcls
            ),
            'gemini-2.5-pro-preview': 'google/gemini-2.5-pro-preview',
            'gemini-2-5-pro-preview': 'google/gemini-2.5-pro-preview',

            # gemini-2.5-pro
            'google/gemini-2.5-pro': (
                'gemini-2.5-pro'
                    if cls.__USING_LLM_API__ else
                'models/gemini-2.5-pro',
                mcls
            ),
            'gemini-2.5-pro': 'google/gemini-2.5-pro',
            'gemini-2-5-pro': 'google/gemini-2.5-pro',

            # gemini-2.0-flash
            'google/gemini-2.0-flash': (
                'gemini-2.0-flash'
                    if cls.__USING_LLM_API__ else
                'models/gemini-2.0-flash',
                mcls
            ),
            'gemini-2.0-flash': 'google/gemini-2.0-flash',
            'gemini-2-0-flash': 'google/gemini-2.0-flash',

            # gemini-2.0-flash-lite
            'google/gemini-2.0-flash-lite': (
                'gemini-2.0-flash-lite'
                    if cls.__USING_LLM_API__ else
                'models/gemini-2.0-flash-lite',
                mcls
            ),
            'gemini-2.0-flash-lite': 'google/gemini-2.0-flash-lite',
            'gemini-2-0-flash-lite': 'google/gemini-2.0-flash-lite',

            # gemini-1.5-flash
            'google/gemini-1.5-flash': (
                'gemini-1.5-flash'
                    if cls.__USING_LLM_API__ else
                'models/gemini-1.5-flash',
                mcls
            ),
            'gemini-1.5-flash': 'google/gemini-1.5-flash',
            'gemini-1-5-flash': 'google/gemini-1.5-flash',
            # gemini-1.5-flash-8b
            'google/gemini-1.5-flash-8b': (
                'gemini-1.5-flash-8b'
                    if cls.__USING_LLM_API__ else
                'models/gemini-1.5-flash-8b',
                mcls
            ),
            'gemini-1.5-flash-8b': 'google/gemini-1.5-flash-8b',
            'gemini-1-5-flash-8b': 'google/gemini-1.5-flash-8b',
            # gemini-1.5-pro
            'google/gemini-1.5-pro': (
                'gemini-1.5-pro'
                    if cls.__USING_LLM_API__ else
                'models/gemini-1.5-pro',
                mcls
            ),
            'gemini-1.5-pro': 'google/gemini-1.5-pro',
            'gemini-1-5-pro': 'google/gemini-1.5-pro',
        })
        
    @classmethod
    def __init_vllm_model(cls):
        from .llm_api import ChatVllmModel
        cls.__VLLM_MODEL_CLASS__ = ChatVllmModel
        mcls = cls.__VLLM_MODEL_CLASS__
        assert(mcls)
        cls.__MODEL_NAME_TO_CLASS__.update(
            {
                'secmlr/best_n_no_rationale_poc_agent_final_model_agent_train': (
                    'openai//models/best_n_no_rationale_poc_agent_final_model_agent_train',
                    mcls,
                ),
                'best_n_no_rationale_poc_agent_final_model_agent_train': 'secmlr/best_n_no_rationale_poc_agent_final_model_agent_train',
                'secmlr/best_n_rationale_poc_agent_final_model_agent_train': (
                    'openai//models/best_n_rationale_poc_agent_final_model_agent_train',
                    mcls,
                ),
                'best_n_rationale_poc_agent_final_model_agent_train': 'secmlr/best_n_rationale_poc_agent_final_model_agent_train',
                'secmlr/best_n_rationale_poc_agent_withjava_final_model_agent': (
                    'openai//models/best_n_rationale_poc_agent_withjava_final_model_agent',
                    mcls,
                ),
                'best_n_rationale_poc_agent_withjava_final_model_agent': 'secmlr/best_n_rationale_poc_agent_withjava_final_model_agent',
                'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent': (
                    'openai//models/best_n_no_rationale_poc_agent_withjava_final_model_agent',
                    mcls,
                ),
                'best_n_no_rationale_poc_agent_withjava_final_model_agent': 'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent',
                'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100': (
                    'openai//models/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100',
                    mcls,
                ),
                'best_n_no_rationale_poc_agent_withjava_final_model_agent_h100': 'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100',
                'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100_64step_5epoch': (
                    'openai//models/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100_64step_5epoch',
                    mcls,
                ),
                'best_n_no_rationale_poc_agent_withjava_final_model_agent_h100_64step_5epoch': 'secmlr/best_n_no_rationale_poc_agent_withjava_final_model_agent_h100_64step_5epoch',
            }
        )


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
                __SUPPORTS_STRUCTURED_OUTPUT__ = True

                def with_structured_output(self, output_parser=None, **kwargs):
                    if not output_parser:
                        return super().with_structured_output(**kwargs)

                    if (
                        not hasattr(output_parser, '__SUPPORTS_STRUCTURED_OUTPUT__')
                        or not output_parser.__SUPPORTS_STRUCTURED_OUTPUT__
                        or not output_parser.should_use_structured_output()
                    ):
                        return self

                    # Detect if we have a json schema we can use
                    # Or fallback to json_object
                    mode = 'json_object'
                    schema = None
                    strict = False
                    if (
                        hasattr(output_parser, '__SUPPORTS_JSON_SCHEMA__')
                        and output_parser.__SUPPORTS_JSON_SCHEMA__
                    ):
                        mode = 'json_schema'
                        schema = output_parser.get_json_schema()
                        strict = output_parser.should_use_strict_mode()
                    
                    return super().with_structured_output(
                        method=mode,
                        schema=schema,
                        strict=strict,
                        **kwargs
                    )
                
                def create_tools_agent(self, *args, **kwargs):
                    return create_openai_tools_agent(self, *args, **kwargs)

            cls.__OPENAI_MODEL_CLASS__ = ChatOpenAIAgentLib

        mcls = cls.__OPENAI_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({

            # gpt-o4-mini
            'openai/o4-mini': (
                f'{pfx}gpt-o4-mini'
                    if cls.__USING_LLM_API__ else
                'o4-mini',
                mcls
            ),
            'o4-mini': 'openai/o4-mini',
            'gpt-o4-mini': 'openai/o4-mini',

            # gpt-o3
            'openai/o3': (
                f'{pfx}gpt-o3'
                    if cls.__USING_LLM_API__ else
                'o3',
                mcls
            ),
            'o3': 'openai/o3',
            'gpt-o3': 'openai/o3',

            # gpt-o3-mini
            'openai/o3-mini': (
                f'{pfx}gpt-o3-mini'
                    if cls.__USING_LLM_API__ else
                'o3-mini',
                mcls
            ),
            'o3-mini': 'openai/o3-mini',
            'gpt-o3-mini': 'openai/o3-mini',

            # gpt-o1
            'openai/o1': (
                f'{pfx}gpt-o1'
                    if cls.__USING_LLM_API__ else
                'o1',
                mcls
            ),
            'o1': 'openai/o1',
            'gpt-o1': 'openai/o1',

            # gpt-o1-mini
            'openai/o1-mini': (
                f'{pfx}gpt-o1-mini'
                    if cls.__USING_LLM_API__ else
                'o1-mini',
                mcls
            ),
            'o1-mini': 'openai/o1-mini',
            'gpt-o1-mini': 'openai/o1-mini',

            # gpt-4.1
            'openai/gpt-4.1': (
                f'{pfx}gpt-4.1'
                    if cls.__USING_LLM_API__ else
                'gpt-4.1-2025-04-14',
                mcls
            ),
            'gpt-4.1-2025-04-14': 'openai/gpt-4.1',
            'gpt-4.1': 'openai/gpt-4.1',
            'gpt-4-1': 'openai/gpt-4.1',
            'gpt-4.1-latest': 'openai/gpt-4.1',
            'gpt-4-1-latest': 'openai/gpt-4.1',

            # gpt-4.1-nano
            'openai/gpt-4.1-nano': (
                f'{pfx}gpt-4.1-nano'
                    if cls.__USING_LLM_API__ else
                'gpt-4.1-nano-2025-04-14',
                mcls
            ),
            'gpt-4.1-nano': 'openai/gpt-4.1-nano',
            'gpt-4-1-nano': 'openai/gpt-4.1-nano',
            'gpt-4.1-nano-2025-04-14': 'openai/gpt-4.1-nano',
            'gpt-4.1-nano-latest': 'openai/gpt-4.1-nano',

            # gpt-4.1-mini
            'openai/gpt-4.1-mini': (
                f'{pfx}gpt-4.1-mini'
                    if cls.__USING_LLM_API__ else
                'gpt-4.1-mini-2025-04-14',
                mcls
            ),
            'gpt-4.1-mini': 'openai/gpt-4.1-mini',
            'gpt-4-1-mini': 'openai/gpt-4.1-mini',
            'gpt-4.1-mini-2025-04-14': 'openai/gpt-4.1-mini',
            'gpt-4.1-mini-latest': 'openai/gpt-4.1-mini',


            # gpt-4o
            'openai/gpt-4o': (f'{pfx}gpt-4o', mcls),
            'gpt-4o': 'openai/gpt-4o',
            'openai/gpt-4o-2024-11-20': (f'{pfx}gpt-4o-2024-11-20', mcls),
            'gpt-4o-2024-11-20': 'openai/gpt-4o-2024-11-20',
            'openai/gpt-4o-2024-08-06': (f'{pfx}gpt-4o-2024-08-06', mcls),
            'gpt-4o-2024-08-06': 'openai/gpt-4o-2024-08-06',
            'openai/gpt-4o-2024-05-13': (f'{pfx}gpt-4o-2024-05-13', mcls),
            'gpt-4o-2024-05-13': 'openai/gpt-4o-2024-05-13',
            'gpt-4o-latest': 'openai/gpt-4o-2024-11-20',

            # gpt-4o-mini
            'openai/gpt-4o-mini': (f'{pfx}gpt-4o-mini', mcls),
            'gpt-4o-mini': 'openai/gpt-4o-mini',

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
            from .langchain_agent.anthropic_agent import create_anthropic_tools_agent

            class ChatAnthropicAgentLib(ChatAnthropic, AgentLibLLM):
                __SUPPORTS_TOOL_CALLS__ = True
                __SUPPORTS_THINKING__ = True
                __SUPPORTS_CACHE__ = False

                def create_tools_agent(self, *args, **kwargs):
                    return create_anthropic_tools_agent(self, *args, **kwargs)

            cls.__ANTHROPIC_MODEL_CLASS__ = ChatAnthropicAgentLib

        mcls = cls.__ANTHROPIC_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({

            # claude-4-opus
            'anthropic/claude-4-opus-20250514': (
                'claude-4-opus'
                    if cls.__USING_LLM_API__ else
                'claude-opus-4-20250514',
                mcls
            ),
            'anthropic/claude-opus-4-20250514': 'anthropic/claude-4-opus-20250514',
            'anthropic/claude-opus-4': 'anthropic/claude-4-opus-20250514',
            'anthropic/claude-4-opus': 'anthropic/claude-4-opus-20250514',
            'claude-4-opus': 'anthropic/claude-4-opus',
            'claude-opus-4': 'anthropic/claude-4-opus',
            'claude-4-opus-latest': 'anthropic/claude-4-opus',
            'claude-opus-4-latest': 'anthropic/claude-4-opus',

            # claude-4-sonnet
            'anthropic/claude-4-sonnet-20250514': (
                'claude-4-sonnet'
                    if cls.__USING_LLM_API__ else
                'claude-sonnet-4-20250514',
                mcls
            ),
            'anthropic/claude-sonnet-4-20250514': 'anthropic/claude-4-sonnet-20250514',
            'anthropic/claude-sonnet-4': 'anthropic/claude-4-sonnet-20250514',
            'anthropic/claude-4-sonnet': 'anthropic/claude-4-sonnet-20250514',
            'claude-4-sonnet': 'anthropic/claude-4-sonnet',
            'claude-sonnet-4': 'anthropic/claude-4-sonnet',
            'claude-4-sonnet-latest': 'anthropic/claude-4-sonnet',
            'claude-sonnet-4-latest': 'anthropic/claude-4-sonnet',

            # claude-3.7-sonnet
            'anthropic/claude-3-7-sonnet-20250219': (
                'claude-3.7-sonnet'
                    if cls.__USING_LLM_API__ else
                'claude-3-7-sonnet-20250219',
                mcls
            ),
            'anthropic/claude-3-7-sonnet': 'anthropic/claude-3-7-sonnet-20250219',
            'claude-3.7-sonnet-20250219': 'anthropic/claude-3-7-sonnet-20250219',
            'claude-3.7-sonnet': 'anthropic/claude-3-7-sonnet',
            'claude-3-7-sonnet': 'anthropic/claude-3-7-sonnet',
            'claude-3.7-sonnet-latest': 'anthropic/claude-3-7-sonnet',

            # claude-3.5-sonnet
            'anthropic/claude-3-5-sonnet-20241022': (
                'claude-3.5-sonnet'
                    if cls.__USING_LLM_API__ else
                'claude-3-5-sonnet-20241022',
                mcls
            ),
            'anthropic/claude-3-5-sonnet': 'anthropic/claude-3-5-sonnet-20241022',
            'claude-3-5-sonnet-20241022': 'anthropic/claude-3-5-sonnet-20241022',
            'claude-3.5-sonnet': 'anthropic/claude-3-5-sonnet',
            'claude-3-5-sonnet': 'anthropic/claude-3-5-sonnet',
            'claude-3-5-sonnet-latest': 'anthropic/claude-3-5-sonnet',

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
    def __init_together(cls):
        pfx = ''
        if cls.__USING_LLM_API__:
            raise NotImplementedError('Together-ai models are not supported in the llm-api version yet')
            #from .llm_api import ChatApiGoogle
            #cls.__GOOGLE_MODEL_CLASS__ = ChatApiGoogle
            #pfx = 'gemini-'
            pass
        else:
            from langchain_together import ChatTogether
            from langchain.agents import create_openai_tools_agent

            class TogetherMockRootClient(object):
                def __init__(self, llm):
                    self.llm = llm

                @property
                def beta(self):
                    return self
                
                @property
                def chat(self):
                    return self

                @property
                def completions(self):
                    return self
                
                def parse(self, *args, **kwargs):
                    return self.llm.client.create(*args, **kwargs)

            class ChatTogetherAgentLib(ChatTogether, AgentLibLLM):
                __SUPPORTS_TOOL_CALLS__ = True

                # Seems like the together-ai api doesn't support structured output via the response_format parameter
                #__SUPPORTS_STRUCTURED_OUTPUT__ = True

                #def with_structured_output(self, output_parser=None, **kwargs):
                #    self.root_client = TogetherMockRootClient(self)

                #    if not output_parser:
                #        return super().with_structured_output(**kwargs)

                #    if (
                #        not hasattr(output_parser, '__SUPPORTS_STRUCTURED_OUTPUT__')
                #        or not output_parser.__SUPPORTS_STRUCTURED_OUTPUT__
                #        or not output_parser.should_use_structured_output()
                #    ):
                #        return self

                    # Detect if we have a json schema we can use
                    # Or fallback to json_object
                #    mode = 'json_object'
                #    schema = None
                #    strict = False
                #    if (
                #        hasattr(output_parser, '__SUPPORTS_JSON_SCHEMA__')
                #        and output_parser.__SUPPORTS_JSON_SCHEMA__
                #    ):
                #        mode = 'json_schema'
                #        schema = output_parser.get_json_schema()
                #        strict = output_parser.should_use_strict_mode()
                    
                #    return super().with_structured_output(
                #        method=mode,
                #        schema=schema,
                #        strict=strict,
                #        **kwargs
                #    )

                def create_tools_agent(self, *args, **kwargs):
                    # Support openai toolcall api
                    return create_openai_tools_agent(self, *args, **kwargs)

            cls.__TOGETHER_MODEL_CLASS__ = ChatTogetherAgentLib

        mcls = cls.__TOGETHER_MODEL_CLASS__
        assert(mcls)

        cls.__MODEL_NAME_TO_CLASS__.update({
            'meta-llama/Llama-3.3-70B-Instruct-Turbo-Free': (f'{pfx}meta-llama/Llama-3.3-70B-Instruct-Turbo-Free', mcls),
            'Llama-3.3-70B-Instruct-Turbo-Free': 'meta-llama/Llama-3.3-70B-Instruct-Turbo-Free',

            'meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo': (f'{pfx}meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo', mcls),
            'Meta-Llama-3.1-405B-Instruct-Turbo': 'meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo',
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
        
        try:
            cls.__init_google()
        except Exception as e:
            log.warning(f'Failed to import langchain-google-genai No gemini models will be available: {e}')

        try:
            cls.__init_together()
        except Exception as e:
            log.warning(f'Failed to import langchain-together No together-ai models will be available: {e}')

        try:
            cls.__init_vllm_model()
        except Exception as e:
            log.warning(f'Failed to import vllm No vllm models will be available: {e}')