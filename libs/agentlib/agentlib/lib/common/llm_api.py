import os
import json
import random
import time
import uuid
from typing import Callable, Optional, List, Any, Literal, Dict, Union, Sequence, Type
from collections import OrderedDict

import openai
from pydantic.v1.main import ModelMetaclass, BaseModel
from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder,
)
from langchain_core.tools import BaseTool
from langchain_core.prompts.chat import (
    MessageLikeRepresentation,
    BaseMessagePromptTemplate,
)
from langchain_core.outputs import ChatResult, ChatGeneration
from langchain_core.callbacks import (
    CallbackManagerForLLMRun,
)
from langchain_core.prompt_values import (
    ChatPromptValue,
    PromptValue,
)
from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    SystemMessage,
    AIMessage,
    ToolMessage,
    convert_to_messages,
)
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain_core.language_models.chat_models import (
    ChatPromptValue,
    SimpleChatModel,
    StringPromptValue,
)

import litellm
from litellm.exceptions import ContextWindowExceededError

from langchain_openai.chat_models.base import (
    _convert_dict_to_message as openai_convert_dict_to_message,
)

from .object import SaveLoadObject
from .logger import BaseLogger

class LiteLLMBudgetManager(SaveLoadObject):
    __BUDGET_NAME__ = None

    @classmethod
    def set_budget_name(cls, budget_name: str):
        cls.__BUDGET_NAME__ = budget_name

class LLMApiLogger(BaseLogger):
    pass


class LLMApiContextWindowExceededError(Exception):
    pass

class LLMApiMismatchedToolCallError(Exception):
    pass

class LLMApiBudgetExceededError(Exception):
    pass

class LLMApiRateLimitError(Exception):
    pass

# SECRET = '!!Shellphish!!'
SECRET = os.environ.get("LITELLM_KEY", "")

# API_ENDPOINT = 'http://beatty.unfiltered.seclab.cs.ucsb.edu:4269/completions'
API_ENDPOINT = os.environ.get("AIXCC_LITELLM_HOSTNAME", "")

LLM_API_CLIENT = (
    openai.OpenAI(api_key=SECRET, base_url=API_ENDPOINT)
    if API_ENDPOINT and SECRET
    else None
)


class ApiConversationIdTrait(SaveLoadObject):
    conversation_id: Optional[str] = None


ROLE_TRANSLATIONS = dict(
    system="system",
    human="user",
    ai="assistant",
    tool="tool",
)


# The message class includes the index id of the message in the conversation and the conversation id
class ApiMessageTrait(ApiConversationIdTrait):
    message_id: int

    def get_message_json(self):
        vals = dict(
            role=ROLE_TRANSLATIONS.get(self.type, self.type),
            content=self.content,
            message_id=self.message_id,
        )
        try:
            if self.additional_kwargs and (self.additional_kwargs.get("disable_cache", False) or self.additional_kwargs.get("disable_cache_one_time", False)):
                vals["disable_cache"] = True

            if self.additional_kwargs:
                self.additional_kwargs.pop("disable_cache_one_time", None)
        except Exception as e:
            import traceback
            traceback.print_exc()
            LLMApiLogger.warn_static(f"🤔 Error getting message json: {e}")
        return vals


class _DisallowIsInstanceForApiMessageBase(ModelMetaclass):
    # Override is instance as actual messages will subclass ApiMessageTrait instead of ApiMessageBase
    def __instancecheck__(self, *args, **kwargs):
        raise TypeError(
            f"isinstance() is not supported for type {self.__name__}. Please use isinstance(a, ApiMessageTrait) instead."
        )


class ApiMessageBase(
    BaseMessage, ApiMessageTrait, metaclass=_DisallowIsInstanceForApiMessageBase
):
    disable_cache: bool = False

    @classmethod
    def from_messages(
        cls,
        messages: List[BaseMessage],
        conversation_id: Optional[str] = None,
        start_index=0,
    ) -> List["ApiMessageTrait"]:
        for i, message in enumerate(messages):
            my_index = start_index + i
            if isinstance(message, ApiMessageTrait):
                cid = message.conversation_id
                if cid and conversation_id and conversation_id == cid:
                    # Only use the message id if it is from the same conversation
                    my_index = message.message_id

            api_message = ApiMessageBase.from_message(
                message, my_index, conversation_id=conversation_id
            )
            messages[i] = api_message

        return messages

    @classmethod
    def from_message(
        cls,
        message: BaseMessage,
        message_index: int,
        conversation_id: Optional[str] = None,
    ) -> "ApiMessageTrait":
        target_cls = cls
        if isinstance(message, HumanMessage):
            target_cls = HumanApiMessage
        elif isinstance(message, SystemMessage):
            target_cls = SystemApiMessage
        elif isinstance(message, AIMessage):
            target_cls = AIApiMessage
        elif isinstance(message, ToolMessage):
            target_cls = ToolApiMessage
        elif isinstance(message, SystemMessagePromptTemplate):
            target_cls = SystemApiPromptTemplate
        elif isinstance(message, HumanMessagePromptTemplate):
            target_cls = HumanApiPromptTemplate
        elif isinstance(message, MessagesPlaceholder):
            return message
        else:
            raise ValueError(f"Unsupported message type {type(message)}")

        if isinstance(message, target_cls):
            message.conversation_id = conversation_id
            message.message_id = message_index
            return message

        if isinstance(message, BaseMessagePromptTemplate):
            assert issubclass(target_cls, ApiPromptTemplateTrait)
            # We are a prompt template so can direct copy
            out = target_cls.from_pydantic(
                message,
                message_id=message_index,
                conversation_id=conversation_id,
            )
            return out

        if issubclass(target_cls, TemplateMessageTrait):
            # The target is a template, but the input is not, so we must copy the content
            template = message.content
            out = target_cls(
                content=template,
                prompt_template=template,
                message_id=message_index,
                conversation_id=conversation_id,
                prompt_args={},
            )
            return out

        # The target is not a template, so we can direct copy
        out = target_cls.from_pydantic(
            message,
            message_id=message_index,
            conversation_id=conversation_id,
        )
        return out


# These user/system messages to the server will be templated on the server backend rather than the client
class TemplateMessageTrait(ApiMessageTrait):
    prompt_template: str
    prompt_args: Dict[str, Any] = {}

    def get_message_json(self):
        res = super().get_message_json()
        res["prompt_template"] = self.prompt_template
        res["prompt_args"] = self.prompt_args
        return res


class SystemApiMessage(SystemMessage, TemplateMessageTrait):
    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True

    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

    @property
    def lc_attributes(self) -> Dict:
        res = super().lc_attributes
        res.update({k: getattr(self, k) for k, v in self.__fields__.items()})
        return res


class HumanApiMessage(HumanMessage, TemplateMessageTrait):
    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True

    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

    @property
    def lc_attributes(self) -> Dict:
        res = super().lc_attributes
        res.update({k: getattr(self, k) for k, v in self.__fields__.items()})
        return res


class AIApiMessage(AIMessage, ApiMessageTrait):
    tool_calls_raw: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    def get_message_json(self):
        res = super().get_message_json()
        if self.tool_calls_raw:
            res["tool_calls"] = self.tool_calls_raw or []
        return res

    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True

    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

    @property
    def lc_attributes(self) -> Dict:
        res = super().lc_attributes
        res.update({k: getattr(self, k) for k, v in self.__fields__.items()})
        return res


class ToolApiMessage(ToolMessage, ApiMessageTrait):
    def get_message_json(self):
        res = super().get_message_json()
        res["tool_call_id"] = self.tool_call_id
        res["name"] = self.tool_call_id  # TODO get actual tool name
        return res

    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True

    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

    @property
    def lc_attributes(self) -> Dict:
        res = super().lc_attributes
        res.update({k: getattr(self, k) for k, v in self.__fields__.items()})
        return res


def prep_value_for_api_call(thing: Any):
    if thing is None:
        return thing

    # TODO handle bytes???

    if type(thing) in [str, int, float, bool, None]:
        return thing

    if isinstance(thing, BaseModel):
        thing = {
            k: v
            for k, v in thing.dict().items()
            if not k.startswith("_")  # XXX is this too restrictive?
        }

    if isinstance(thing, dict):
        return {k: prep_value_for_api_call(v) for k, v in thing.items()}

    if isinstance(thing, list):
        return [prep_value_for_api_call(v) for v in thing]

    try:
        json.dumps(thing)
        return thing
    except:
        pass
    return str(thing)


class ApiPromptTemplateTrait(ApiMessageTrait):
    def convert_to_message(self, **kwargs) -> ApiMessageTrait:
        raise NotImplementedError

    def get_prompt_args(self, **kwargs):
        args = self.prompt.partial_variables.copy()
        args.update(dict(**kwargs))
        input_vars = self.prompt.input_variables
        all_vars = {
            k: prep_value_for_api_call(v) for k, v in args.items() if k in input_vars
        }
        return all_vars


class SystemApiPromptTemplate(SystemMessagePromptTemplate, ApiPromptTemplateTrait):
    def convert_to_message(self, **kwargs) -> SystemApiMessage:
        rendered_msg = self.format(**kwargs)
        return SystemApiMessage(
            content=rendered_msg.content,
            message_id=self.message_id,
            conversation_id=self.conversation_id,
            prompt_template=self.prompt.template,
            prompt_args=self.get_prompt_args(**kwargs),
        )


class HumanApiPromptTemplate(HumanMessagePromptTemplate, ApiPromptTemplateTrait):
    def convert_to_message(self, **kwargs) -> HumanApiMessage:
        rendered_msg = self.format(**kwargs)
        return HumanApiMessage(
            content=rendered_msg.content,
            message_id=self.message_id,
            conversation_id=self.conversation_id,
            prompt_template=self.prompt.template,
            prompt_args=self.get_prompt_args(**kwargs),
        )


# This class represents a set of historical messages from the current conversation
class ApiConversation(ApiConversationIdTrait):
    messages: list[ApiMessageTrait] = []

    def add_messages(self, messages: List[BaseMessage]):
        for message in messages:
            indx = len(self.messages)
            api_message = ApiMessageTrait.from_message(
                message, indx, conversation_id=self.conversation_id
            )
            self.messages.append(api_message)


# We also need a special prompt template which does not actually template anything before passing it into the model
# It will produce the ApiChatPromptValue when invoked
class ApiChatPromptTemplate(ChatPromptTemplate, ApiConversationIdTrait):
    """This is similar to ChatPromptTemplate, except it will not actually render the template, but instead produce the ApiChatPromptValue which can be passed to the API"""

    # Override to produce the ApiChatPromptValue and not actually render
    def _format_prompt_with_error_handling(self, inner_input: Dict) -> PromptValue:
        _inner_input = self._validate_input(inner_input)
        return self.format_prompt(**_inner_input)

    def format_prompt(self, **kwargs: Any) -> "ApiChatPromptValue":
        value_messages = []
        conversation_id = self.conversation_id
        for message in self.messages:
            if isinstance(message, ApiPromptTemplateTrait):
                message = message.convert_to_message(**kwargs)

            if not isinstance(message, MessagesPlaceholder):
                value_messages.append(message)
                continue

            # Expand message placeholders
            key = message.variable_name
            if key not in kwargs:
                if not message.optional:
                    raise ValueError(
                        f"Missing required placeholder message input variable {key} for message {message}"
                    )
                continue
            var_messages = kwargs[key]

            if not isinstance(var_messages, list):
                raise ValueError(
                    f"Expected a list of messages for placeholder {key}, got {var_messages}"
                )

            if len(var_messages) == 0:
                continue

            # When passing chat history, we want to see if it was a previous conversation
            if not conversation_id:
                for var_message in var_messages:
                    if not isinstance(var_message, ApiConversationIdTrait):
                        continue
                    conversation_id = var_message.conversation_id
                    if conversation_id:
                        break

            var_messages = ApiMessageBase.from_messages(
                var_messages,
                conversation_id=conversation_id,
                start_index=len(value_messages),
            )
            value_messages.extend(var_messages)

        return ApiChatPromptValue.from_messages(
            value_messages, conversation_id=conversation_id
        )

    @classmethod
    def from_messages(
        cls,
        messages: Sequence[MessageLikeRepresentation],
        template_format: Literal["f-string", "mustache"] = "f-string",
        conversation_id: Optional[str] = None,
    ) -> ChatPromptTemplate:
        template: ChatPromptTemplate = super().from_messages(
            messages, template_format=template_format
        )

        in_cid = conversation_id

        # Find the conversation id
        for message in template.messages:
            if not isinstance(message, ApiConversationIdTrait):
                continue

            m_con_id = message.conversation_id
            if not m_con_id:
                continue

            if conversation_id and conversation_id != m_con_id:
                # If the message is not from this conversation
                if in_cid:
                    # We will force this into the user provided conversation
                    message.conversation_id = None
                    continue

                raise ValueError(
                    f"Conversation id mismatch {conversation_id} != {m_con_id}, You are mixing and matching messages from different conversations. If you want a fresh conversation (TODO describe method)"
                )

            if not conversation_id:
                # Continue the existing conversation
                conversation_id = m_con_id
            continue

        msgs = ApiMessageBase.from_messages(
            template.messages, conversation_id=conversation_id
        )
        template.messages = msgs

        my_template = cls.from_pydantic(template, conversation_id=conversation_id)
        return my_template


# This wrapper for the ChatPromptValue will not actually have the template output. Instead it will be used to pass into the ChatAPI
# This is a set of messages that will be passed into the API
class ApiChatPromptValue(ChatPromptValue, SaveLoadObject):
    conversation_id: Optional[str] = None

    @classmethod
    def from_messages(
        cls, messages: List[BaseMessage], conversation_id: Optional[str] = None
    ) -> "ApiChatPromptValue":
        """Warning: If not conversation_id is provided, this will become a new conversation, resetting message ids"""
        messages = ApiMessageBase.from_messages(
            messages, conversation_id=conversation_id
        )

        return cls(messages=messages, conversation_id=conversation_id)


class ChatGenerationWithLLMOutput(ChatGeneration):
    llm_output: Optional[dict] = None


# This is the actual API model
# It takes a ApiChatPromptValue (or something that converts to it) and returns a ChatResult->ChatGeneration->AIApiMessage
class ChatApi(SimpleChatModel):
    __SUPPORTS_TOOL_CALLS__ = False

    model_name: str = Field(default="gpt-4.5-turbo", alias="model")
    """Model name to use."""
    temperature: float = 0
    """What sampling temperature to use."""
    max_tokens: Optional[int] = None
    """Maximum number of tokens to generate."""
    model_kwargs: Dict[str, Any] = Field(default_factory=dict)
    """Holds any model parameters valid for `create` call not explicitly specified."""
    stop: Optional[List[str]] = None
    """Stop tokens to use."""

    tools: Optional[Union[Dict[str, Any], Type, Callable, BaseTool]] = None
    callbacks: List[Any] = []
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    rate_limiter: Optional[Any] = None

    def get_provider_budget_user(self):
        return None

    def get_budget_user(self):
        if LiteLLMBudgetManager.__BUDGET_NAME__:
            return LiteLLMBudgetManager.__BUDGET_NAME__

        return self.get_provider_budget_user()

    def bind_tools(
        self,
        tools: Sequence[Union[Dict[str, Any], Type, Callable, BaseTool]],
        **kwargs: Any,
    ) -> "ChatApi":
        n = self.copy()
        # Convert tools into llm api compatible format
        tools_out = []
        for tool in tools:
            d = dict(
                type="function",
                function=dict(
                    name=tool.name,
                    description=tool.description,
                    parameters=tool.args,
                ),
            )
            tools_out.append(d)

        n.tools = tools_out
        return n

    class Config:
        """Configuration for this pydantic object."""

        allow_population_by_field_name = True

    @property
    def _llm_type(self) -> str:
        """Return type of chat model."""
        return "shellphish-llm-api"

    @property
    def model(self):
        return self.model_name

    @property
    def top_p(self):
        return None

    @property
    def top_k(self):
        return None

    def create_tools_agent(self, *args, **kwargs):
        raise NotImplementedError("This model does not support tool calls")

    def _convert_input(self, input: LanguageModelInput) -> PromptValue:
        """Overridden to convert to our Api message types."""
        if isinstance(input, ApiChatPromptValue):
            return input

        if isinstance(input, ChatPromptValue):
            input = input.messages
        if isinstance(input, StringPromptValue):
            input = input.text

        if isinstance(input, str):
            return ApiChatPromptValue(
                messages=[HumanApiMessage(content=input, message_id=0)]
            )

        if isinstance(input, Sequence):
            msgs = convert_to_messages(input)
            return ApiChatPromptValue.from_messages(msgs)

        raise ValueError(
            f"Invalid input type {type(input)}. "
            "Must be a ChatPromptValue, str, or list of BaseMessages."
        )

    def _generate(
        self,
        messages: List[ApiMessageBase],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        generation = self._call(messages, stop=stop, run_manager=run_manager, **kwargs)
        return ChatResult(
            generations=[generation],
            llm_output=generation.llm_output,
        )

    def preprocess_message_json(self, messages):
        for m in messages:
            m.pop("disable_cache", None)
        return messages

    def _call(
        self,
        messages: List[ApiMessageBase],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatGenerationWithLLMOutput:
        assert len(messages) > 0

        # TODO get a namespace for the conversation
        new_message_ind = len(messages)
        namespace = "agentlib.unknown"

        messages_json = []
        for message in messages:
            message_json = message.get_message_json()
            message_json["author"] = namespace  # More detailed namespace
            messages_json.append(message_json)

        params = dict(
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        raise_on_budget_exception = True
        raise_on_rate_limit_exception = False

        if self.model_kwargs:
            raise_on_budget_exception = self.model_kwargs.pop("raise_on_budget_exception", False)
            raise_on_rate_limit_exception = self.model_kwargs.pop("raise_on_rate_limit_exception", False)
            params.update(self.model_kwargs)

        if self.stop:
            params["stop"] = self.stop
        if stop:
            params["stop"] = stop

        attached_tools = kwargs.get("tools", self.tools)
        if attached_tools:
            params["tools"] = attached_tools

        messages_json = self.preprocess_message_json(messages_json)

        budget_user = self.get_budget_user()
        LLMApiLogger.debug_static(f"Budget user: {budget_user}")
        if budget_user:
            params["user"] = budget_user

        # We are going to sanity check the tool calls included in these messages. If we see a tool call without a corresponding tool result, we need to remove it

        try:
            message_indexes_to_remove = set()
            pending_tool_calls = OrderedDict()
            bad_tool_responses = OrderedDict()
            for i,message in enumerate(messages_json):
                calls = message.get('tool_calls', [])
                if calls:
                    for call in calls:
                        call_id = call.get('id')
                        pending_tool_calls[call_id] = i
                    continue
                res_id = message.get('tool_call_id')
                if res_id:
                    if res_id in pending_tool_calls:
                        pending_tool_calls.pop(res_id, None)
                    else:
                        bad_tool_responses[res_id] = i

            if len(pending_tool_calls) > 0 or len(bad_tool_responses) > 0:
                LLMApiLogger.warn_static(f"Sending to LLM API: {json.dumps(messages_json, indent=2)}")

            for call_id,i in pending_tool_calls.items():
                message = messages_json[i]
                message_indexes_to_remove.add(i)
                import traceback
                traceback.print_stack()
                LLMApiLogger.log_error_static(f"Tool call {call_id} without a corresponding tool result. Tool call is: {json.dumps(message, indent=2)}")
                LLMApiLogger.warn_static(f"Removing bad tool call from messages")
            
            for res_id,i in bad_tool_responses.items():
                message = messages_json[i]
                message_indexes_to_remove.add(i)
                import traceback
                traceback.print_stack()
                LLMApiLogger.log_error_static(f"Tool result {res_id} without a corresponding tool call. Tool result is: {json.dumps(message, indent=2)}")
                LLMApiLogger.warn_static(f"Removing bad tool result from messages")

            messages_json = [m for i,m in enumerate(messages_json) if i not in message_indexes_to_remove]
        except Exception as e:
            import traceback
            traceback.print_exc()
            LLMApiLogger.warn_static(f"Error checking tool calls: {str(e)}")
            pass

        #LLMApiLogger.debug_static(f"Sending to LLM API: {json.dumps(messages_json, indent=2)}")
        #LLMApiLogger.debug_static(f"Sending to LLM API: {json.dumps(params, indent=2)}")

        max_retries = -1 # infinite retries

        num_retries = 0
        last_exception = None

        while max_retries == -1 or num_retries < max_retries:
            num_retries += 1
            try:
                sleep_time = random.randint(60, 60 * 3)
            except:
                sleep_time = 30

            try:
                resp = LLM_API_CLIENT.chat.completions.create(
                    model=self.model_name,
                    messages=messages_json,
                    # base_url = API_ENDPOINT,
                    # api_key = SECRET,
                    **params,
                )
                # response_json = resp.json()
                response_json = json.loads(resp.json())
                break

            # More specific errors towards the top

            except (
                ContextWindowExceededError,
             ) as e:
                import traceback
                print('Context window exceeded error', type(e))
                #traceback.print_exc()
                LLMApiLogger.warn_static(f"🪟 Context window exceeded, raising ContextWindowExceededError")
                raise e

            except (
                openai.RateLimitError,
                litellm.exceptions.RateLimitError,
            ) as e:
                import traceback
                print('Ratelimit error', type(e))
                if raise_on_rate_limit_exception:
                    LLMApiLogger.warn_static(f"⏱️ Ratelimit error, raising LLMApiRateLimitError")
                    raise LLMApiRateLimitError(str(e))
                # Ratelimit timeouts get retried
                #traceback.print_exc()
                LLMApiLogger.warn_static(f"⏱️ Ratelimit error, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.PermissionDeniedError,
                openai.AuthenticationError,
                openai.UnprocessableEntityError,
                openai.NotFoundError,
                openai.APIResponseValidationError,
                litellm.exceptions.PermissionDeniedError,
                litellm.exceptions.AuthenticationError,
                litellm.exceptions.UnprocessableEntityError,
                litellm.exceptions.NotFoundError,
                litellm.exceptions.APIResponseValidationError,
            ) as e:
                import traceback
                print(type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🤔 LLM API returned a... strange... error, retrying in {sleep_time} seconds")
                max_retries = 20
                
                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.BadRequestError,
                litellm.exceptions.BadRequestError
            ) as e:
                # Client side errors
                try:
                    errm = (str(e) + repr(e)).lower()
                    if (
                        'contextwindowexceedederror' in errm
                        or 'context window' in errm
                        or 'prompt is too long' in errm
                    ):
                        LLMApiLogger.warn_static(f"🪟 Context window exceeded, raising LLMApiContextWindowExceededError")
                        raise LLMApiContextWindowExceededError('Context window exceeded')
                    elif (
                        'each `tool_use` block must have a corresponding `tool_result` block' in errm
                    ):
                        LLMApiLogger.warn_static(f"⛏️ Mismatched tool call, raising LLMApiMismatchedToolCallError")
                        raise LLMApiMismatchedToolCallError('Mismatched tool call')
                    elif (
                        'budget has been exceeded' in errm
                    ):
                        if raise_on_budget_exception:
                            LLMApiLogger.warn_static(f"💸 Budget has been exceeded, raising LLMApiBudgetExceededError: {str(e)}")
                            raise LLMApiBudgetExceededError(str(e))
                        LLMApiLogger.warn_static(f"💸 Budget has been exceeded, waiting for {sleep_time} seconds: {str(e)}")
                        last_exception = e
                        time.sleep(sleep_time)
                        continue


                except LLMApiContextWindowExceededError as e:
                    raise e
                except LLMApiMismatchedToolCallError as e:
                    raise e
                except LLMApiBudgetExceededError as e:
                    if raise_on_budget_exception:
                        raise e
                    LLMApiLogger.warn_static(f"💸 Budget has been exceeded, waiting for {sleep_time} seconds: {str(e)}")
                    last_exception = e
                    time.sleep(sleep_time)
                    continue
                except LLMApiRateLimitError as e:
                    if raise_on_rate_limit_exception:
                        raise e
                    LLMApiLogger.warn_static(f"⏱️ Ratelimit error, waiting for {sleep_time} seconds: {str(e)}")
                    last_exception = e
                    time.sleep(sleep_time)
                    continue

                except Exception as ee:
                    LLMApiLogger.warn_static(f"Failed to check for context window exceeded...")
                    import traceback
                    traceback.print_exc()

                import traceback
                print('Bad request error', type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🤔 LLM API client side error, retrying in {sleep_time} seconds")
                max_retries = 10

                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.APITimeoutError,
                openai.InternalServerError,
                openai.APIConnectionError,
                openai.APIError,
                openai.APIStatusError,

                litellm.exceptions.Timeout,
                litellm.exceptions.ServiceUnavailableError,
                litellm.exceptions.InternalServerError,
                litellm.exceptions.APIConnectionError,
                litellm.exceptions.APIError,
            ) as e:
                # Server side errors, just retry no matter what
                import traceback
                print('Server side error', type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🔥 LLM API server side error, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)


            except Exception as e:
                # Generic exception, just retry
                import traceback
                print('Generic exception', type(e))
                # import ipdb; ipdb.set_trace()
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🔥 LLM API generic exception, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)

        if max_retries != -1 and num_retries >= max_retries:
            LLMApiLogger.warn_static(f"🔥 LLM API generic exception, max retries reached")
            raise last_exception or Exception(f"LLM API generic exception, max retries reached")

        if len(response_json.get('choices', [])) == 0:
            response_json['choices'] = [{
                'message': {
                    'content': "",
                    'role': 'assistant'
                },
                'finish_reason': 'error'
            }]

        choice = response_json.get('choices', [{}])[0]
        message = choice.get('message')
        if choice.get('finish_reason') == 'stop':
            if not message.get('content'):
                message['content'] = ""
            stop = params.get('stop', [])
            if len(stop) == 1:
                message['content'] += stop[0]
        choice['message'] = message
        response_json['choices'] = [choice]

        #LLMApiLogger.warn_static(f"Response from LLM API: {json.dumps(response_json, indent=2)}")
        #LLMApiLogger.warn_static(f"[RAW-LLM-USAGE] [{self.model_name}] {json.dumps(response_json.get('usage', {}))}")

        conversation_id = str(uuid.uuid4())

        return self.parse_response_message(
            response_json, new_message_ind, conversation_id
        )

        """

        # TODO support some of `model_kwargs`
        post_data = dict(
            secret_key = SECRET,
            requested_model = self.model_name,
            messages = messages_json,
            tools = kwargs.get('tools', []),
            origin = namespace, # Top level of the namespace
            # All messages should be marked with the same conversation id
            # Which can be None for a new conversation
            chat_id = messages[0].conversation_id,
            response_message_id = new_message_ind,
        )
        #print("======= SENDING TO LLM API =======")
        #print(json.dumps(post_data, indent=2))

        while True:
            try:
                res = requests.post(
                    API_ENDPOINT,
                    json=post_data
                )

                if res.status_code != 200:
                    raise Exception(f"API request failed with status code {res.status_code}: {res.text}")

                response_json = res.json()
                print("======= RESPONSE FROM LLM API =======")
                print(json.dumps(response_json, indent=2))

                error = response_json.get('error')
                if error: # TODO only catch some errors as others might be our fault
                    raise Exception(f"API request failed with error: {error}")

                break
            except Exception as e:
                import traceback
                traceback.print_exc()
                time.sleep(1)

        conversation_id = response_json["chat_id"]


        return self.parse_response_message(
            response_json,
            new_message_ind,
            conversation_id
        )
        """

    def parse_response_message(
        self, gen_response: dict, new_message_ind: int, conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_msg_json = gen_response["choices"][0]["message"]
        # Generic llm that does not support tool calls
        gen_msg_content = gen_msg_json["content"]

        if gen_msg_content is None:
            gen_msg_content = ""

        message = AIApiMessage(
            content=gen_msg_content,
            message_id=new_message_ind,
            conversation_id=conversation_id,
        )
        return ChatGenerationWithLLMOutput(message=message, llm_output=gen_response)

    def preprocess_structured_output_schema(self, schema):
        return schema

    def with_structured_output(self, output_parser=None, **kwargs):
        if not output_parser:
            LLMApiLogger.warn_static(
                "No output parser provided, skipping structured output"
            )
            return self.copy()

        if (
            not hasattr(output_parser, "__SUPPORTS_STRUCTURED_OUTPUT__")
            or not output_parser.__SUPPORTS_STRUCTURED_OUTPUT__
            or not output_parser.should_use_structured_output()
        ):
            LLMApiLogger.warn_static(
                "Parser has no structured output support, skipping structured output (or structured output is not enabled)"
            )
            return self.copy()

        new_model = self.copy()

        # Detect if we have a json schema we can use
        # Or fallback to json_object
        mode = "json_object"
        schema = None
        strict = False
        if (
            hasattr(output_parser, "__SUPPORTS_JSON_SCHEMA__")
            and output_parser.__SUPPORTS_JSON_SCHEMA__
        ):
            mode = "json_schema"
            schema = output_parser.get_json_schema()
            strict = output_parser.should_use_strict_mode()

        if schema:
            schema = self.preprocess_structured_output_schema(schema)

        return new_model.set_response_format(
            mode=mode, schema=schema, strict=strict, **kwargs
        )


class ChatApiGoogle(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True
    __SUPPORTS_STRUCTURED_OUTPUT__ = True

    def get_provider_budget_user(self):
        return 'gemini-budget'

    def create_tools_agent(self, *args, **kwargs):
        from ..common.langchain_agent.google_agent import (
            create_google_tools_agent,
        )

        return create_google_tools_agent(self, *args, **kwargs)

    def parse_response_message(
        self, gen_response: dict, new_message_ind: int, conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_choice = gen_response["choices"][0]
        gen_msg_json = gen_choice["message"]


        tool_calls_raw = gen_msg_json.get("tool_calls", []) or []

        if len(tool_calls_raw) > 0:
            gen_choice["finish_reason"] = "tool_calls"
            #gen_msg_json["content"] = "I will do that now."

        #LLMApiLogger.debug_static(f"Google response: {json.dumps(gen_response, indent=2)}")

        message = openai_convert_dict_to_message(gen_msg_json)
        message = ApiMessageBase.from_message(
            message,
            new_message_ind,
            conversation_id=conversation_id,
        )
        if isinstance(message, AIApiMessage):
            message.tool_calls_raw = tool_calls_raw

        generation_info = dict(finish_reason=gen_choice.get("finish_reason"))

        return ChatGenerationWithLLMOutput(message=message, generation_info=generation_info, llm_output=gen_response)

    def bind_tools(
        self,
        tools: Sequence[Union[Dict[str, Any], Type, Callable, BaseTool]],
        **kwargs: Any,
    ) -> "ChatApi":
        n = self.copy()
        # Convert tools into llm api compatible format
        tools_out = n.tools or []
        for tool in tools:
            props = {}
            required = []
            schema = dict(type="object", properties=props)
            for k, v in tool.args.items():
                props[k] = v
                required.append(k)
            schema["required"] = required

            d = dict(
                name=tool.name,
                description=tool.description,
                parameters=schema,
            )
            tools_out.append(d)

        n.tools = tools_out
        return n

    def set_response_format(self, mode=None, schema=None, strict=False, **kwargs):
        self.model_kwargs = self.model_kwargs or {}
        if mode is None:
            del self.model_kwargs["response_format"]
            return self

        assert mode in ["json_object", "json_schema"]
        format = dict(type=mode)
        if schema:
            format["json_schema"] = dict(
                name=schema.get("name") or schema.get("title") or "response",
                schema=schema,
                strict=strict,
            )

        self.model_kwargs["response_format"] = format

        return self

    def preprocess_structured_output_schema(self, schema):
        def remove_additional_properties(d):
            for k, v in list(d.items()):
                if k == "additionalProperties":
                    del d[k]
                    props = v.get("properties",{}) or {}
                    if not props:
                        import traceback
                        traceback.print_stack()
                        LLMApiLogger.warn_static(f" ⚠️ Gemini does not support Dict[str, any] types! (ie all properties must be named!)")
                        props["response"] = dict(type="string")
                        d["properties"] = props

                elif isinstance(v, dict):
                    remove_additional_properties(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            remove_additional_properties(item)
        remove_additional_properties(schema)
        return schema



class ChatApiTogether(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True
    __SUPPORTS_STRUCTURED_OUTPUT__ = True

    # TODO

class ChatVllmModel(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True
    __SUPPORTS_STRUCTURED_OUTPUT__ = True

    def get_provider_budget_user(self):
        return 'aixcc-budget'

    def parse_response_message(
        self, gen_response: dict, new_message_ind: int, conversation_id: str
    ):
        gen_choice = gen_response["choices"][0]
        gen_msg_json = gen_choice["message"]

        message = openai_convert_dict_to_message(gen_msg_json)
        message = ApiMessageBase.from_message(
            message,
            new_message_ind,
            conversation_id=conversation_id,
        )
        if isinstance(message, AIApiMessage):
            message.tool_calls_raw = gen_msg_json.get("tool_calls", []) or []
        generation_info = dict(finish_reason=gen_choice.get("finish_reason"))
        return ChatGenerationWithLLMOutput(
            message=message, generation_info=generation_info, llm_output=gen_response
        )

    def create_tools_agent(self, *args, **kwargs):
        from langchain.agents import create_openai_tools_agent

        return create_openai_tools_agent(self, *args, **kwargs)

    def set_response_format(self, mode=None, schema=None, strict=False, **kwargs):
        self.model_kwargs = self.model_kwargs or {}
        if mode is None:
            del self.model_kwargs["response_format"]
            return self

        assert mode in ["json_object", "json_schema"]
        format = dict(type=mode)
        if schema:
            format["json_schema"] = dict(
                name=schema.get("name") or schema.get("title") or "response",
                schema=schema,
                strict=strict,
            )
        self.model_kwargs["response_format"] = format
        return self
    
    def _call(
        self,
        messages: List[ApiMessageBase],
        stop: Optional[List[str]] = None,
        run_manager: Optional["CallbackManagerForLLMRun"] = None,
        **kwargs: Any,
    ) -> ChatGenerationWithLLMOutput:
        assert len(messages) > 0

        new_message_ind = len(messages)
        namespace = "agentlib.unknown"

        messages_json = []
        for message in messages:
            message_json = message.get_message_json()
            message_json["author"] = namespace
            messages_json.append(message_json)

        params = dict(
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        if self.model_kwargs:
            raise_on_budget_exception = self.model_kwargs.pop("raise_on_budget_exception", False)
            params.update(self.model_kwargs)
        else:
            raise_on_budget_exception = True

        if self.stop:
            params["stop"] = self.stop
        if stop:
            params["stop"] = stop

        attached_tools = kwargs.get("tools", self.tools)
        if attached_tools:
            params["tools"] = attached_tools

        messages_json = self.preprocess_message_json(messages_json)

        budget_user = self.get_budget_user()
        if budget_user:
            params["user"] = budget_user

        try:
            message_indexes_to_remove = set()
            pending_tool_calls = OrderedDict()
            bad_tool_responses = OrderedDict()
            for i, message in enumerate(messages_json):
                calls = message.get('tool_calls', [])
                if calls:
                    for call in calls:
                        call_id = call.get('id')
                        pending_tool_calls[call_id] = i
                    continue
                res_id = message.get('tool_call_id')
                if res_id:
                    if res_id in pending_tool_calls:
                        pending_tool_calls.pop(res_id, None)
                    else:
                        bad_tool_responses[res_id] = i
            for call_id, i in pending_tool_calls.items():
                message_indexes_to_remove.add(i)
            for res_id, i in bad_tool_responses.items():
                message_indexes_to_remove.add(i)
            messages_json = [m for i, m in enumerate(messages_json) if i not in message_indexes_to_remove]
        except Exception as e:
            import traceback
            traceback.print_exc()

        api_base = os.environ.get("VLLM_HOSTNAME", "http://vllm-server:25002/v1")
        # -----------------------------------------------------

        max_retries = 3
        num_retries = 0
        last_exception = None

        while max_retries == -1 or num_retries < max_retries:
            num_retries += 1
            try:
                sleep_time = random.randint(5, 5 * 3)
            except:
                sleep_time = 8

            try:
                response_json = litellm.completion(
                    model=self.model_name,
                    messages=messages_json,
                    api_base=api_base,
                    api_key="dummy",
                    **params
                ).dict()
                break

            except (
                ContextWindowExceededError,
             ) as e:
                import traceback
                print('Context window exceeded error', type(e))
                #traceback.print_exc()
                LLMApiLogger.warn_static(f"🪟 Context window exceeded, raising ContextWindowExceededError")
                raise LLMApiContextWindowExceededError('Context window exceeded')

            except (
                openai.RateLimitError,
                litellm.exceptions.RateLimitError,
            ) as e:
                # Ratelimit timeouts get retried
                import traceback
                print('Ratelimit error', type(e))
                #traceback.print_exc()
                LLMApiLogger.warn_static(f"⏱️ Ratelimit error, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.PermissionDeniedError,
                openai.AuthenticationError,
                openai.UnprocessableEntityError,
                openai.NotFoundError,
                openai.APIResponseValidationError,
                litellm.exceptions.PermissionDeniedError,
                litellm.exceptions.AuthenticationError,
                litellm.exceptions.UnprocessableEntityError,
                litellm.exceptions.NotFoundError,
                litellm.exceptions.APIResponseValidationError,
            ) as e:
                import traceback
                print(type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🤔 LLM API returned a... strange... error, retrying in {sleep_time} seconds")
                max_retries = 20
                
                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.BadRequestError,
                litellm.exceptions.BadRequestError
            ) as e:
                # Client side errors
                try:
                    errm = (str(e) + repr(e)).lower()
                    if (
                        'contextwindowexceedederror' in errm
                        or 'context window' in errm
                        or 'prompt is too long' in errm
                    ):
                        LLMApiLogger.warn_static(f"🪟 Context window exceeded, raising LLMApiContextWindowExceededError")
                        raise LLMApiContextWindowExceededError('Context window exceeded')
                    elif (
                        'each `tool_use` block must have a corresponding `tool_result` block' in errm
                    ):
                        LLMApiLogger.warn_static(f"⛏️ Mismatched tool call, raising LLMApiMismatchedToolCallError")
                        raise LLMApiMismatchedToolCallError('Mismatched tool call')
                    elif (
                        'budget has been exceeded' in errm
                    ):
                        if raise_on_budget_exception:
                            LLMApiLogger.warn_static(f"💸 Budget has been exceeded, raising LLMApiBudgetExceededError: {str(e)}")
                            raise LLMApiBudgetExceededError(str(e))
                        LLMApiLogger.warn_static(f"💸 Budget has been exceeded, waiting for {sleep_time} seconds: {str(e)}")
                        last_exception = e
                        time.sleep(sleep_time)
                        continue


                except LLMApiContextWindowExceededError as e:
                    raise e
                except LLMApiMismatchedToolCallError as e:
                    raise e
                except LLMApiBudgetExceededError as e:
                    if raise_on_budget_exception:
                        raise e
                    LLMApiLogger.warn_static(f"💸 Budget has been exceeded, waiting for {sleep_time} seconds: {str(e)}")
                    last_exception = e
                    time.sleep(sleep_time)
                    continue

                except Exception as ee:
                    LLMApiLogger.warn_static(f"Failed to check for context window exceeded...")
                    import traceback
                    traceback.print_exc()

                import traceback
                print('Bad request error', type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🤔 LLM API client side error, retrying in {sleep_time} seconds")
                max_retries = 10

                last_exception = e
                time.sleep(sleep_time)

            except (
                openai.APITimeoutError,
                openai.InternalServerError,
                openai.APIConnectionError,
                openai.APIError,
                openai.APIStatusError,

                litellm.exceptions.Timeout,
                litellm.exceptions.ServiceUnavailableError,
                litellm.exceptions.InternalServerError,
                litellm.exceptions.APIConnectionError,
                litellm.exceptions.APIError,
            ) as e:
                # Server side errors, just retry no matter what
                import traceback
                print('Server side error', type(e))
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🔥 LLM API server side error, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)


            except Exception as e:
                # Generic exception, just retry
                import traceback
                print('Generic exception', type(e))
                # import ipdb; ipdb.set_trace()
                traceback.print_exc()
                LLMApiLogger.warn_static(f"🔥 LLM API generic exception, retrying in {sleep_time} seconds")
                last_exception = e
                time.sleep(sleep_time)

        if max_retries != -1 and num_retries >= max_retries:
            LLMApiLogger.warn_static(f"🔥 LLM API generic exception, max retries reached")
            raise last_exception or Exception(f"LLM API generic exception, max retries reached")

        if len(response_json.get('choices', [])) == 0:
            response_json['choices'] = [{
                'message': {
                    'content': "",
                    'role': 'assistant'
                },
                'finish_reason': 'error'
            }]

        choice = response_json.get('choices', [{}])[0]
        message = choice.get('message')
        if choice.get('finish_reason') == 'stop':
            if not message.get('content'):
                message['content'] = ""
            stop = params.get('stop', [])
            if len(stop) == 1:
                message['content'] += stop[0]
        choice['message'] = message
        response_json['choices'] = [choice]

        conversation_id = str(uuid.uuid4())

        return self.parse_response_message(
            response_json, new_message_ind, conversation_id
        )


class ChatApiOpenAi(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True
    __SUPPORTS_STRUCTURED_OUTPUT__ = True

    def get_provider_budget_user(self):
        return 'openai-budget'

    def parse_response_message(
        self, gen_response: dict, new_message_ind: int, conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_choice = gen_response["choices"][0]
        gen_msg_json = gen_choice["message"]

        message = openai_convert_dict_to_message(gen_msg_json)
        message = ApiMessageBase.from_message(
            message,
            new_message_ind,
            conversation_id=conversation_id,
        )
        if isinstance(message, AIApiMessage):
            message.tool_calls_raw = gen_msg_json.get("tool_calls", []) or []

        generation_info = dict(finish_reason=gen_choice.get("finish_reason"))
        return ChatGenerationWithLLMOutput(
            message=message, generation_info=generation_info, llm_output=gen_response
        )

    def create_tools_agent(self, *args, **kwargs):
        from langchain.agents import create_openai_tools_agent

        return create_openai_tools_agent(self, *args, **kwargs)

    def set_response_format(self, mode=None, schema=None, strict=False, **kwargs):
        self.model_kwargs = self.model_kwargs or {}
        if mode is None:
            del self.model_kwargs["response_format"]
            return self

        assert mode in ["json_object", "json_schema"]

        format = dict(type=mode)
        if schema:
            format["json_schema"] = dict(
                name=schema.get("name") or schema.get("title") or "response",
                schema=schema,
                strict=strict,
            )

        self.model_kwargs["response_format"] = format

        return self


class ChatApiAnthropic(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True
    __SUPPORTS_STRUCTURED_OUTPUT__ = True
    __SUPPORTS_THINKING__ = True
    __SUPPORTS_CACHE__ = True

    # Is this model using a tool call as an
    tool_as_output: Optional[str] = None
    use_cache: bool = False

    def get_provider_budget_user(self):
        return 'claude-budget'

    def create_tools_agent(self, *args, **kwargs):
        from ..common.langchain_agent.anthropic_agent import (
            create_anthropic_tools_agent,
        )

        return create_anthropic_tools_agent(self, *args, **kwargs)

    def with_cache(self, **kwargs):
        n = self.copy()
        n.use_cache = True
        return n

    def bind_tools(
        self,
        tools: Sequence[Union[Dict[str, Any], Type, Callable, BaseTool]],
        **kwargs: Any,
    ) -> "ChatApi":
        n = self.copy()
        # Convert tools into llm api compatible format
        tools_out = n.tools or []
        for tool in tools:
            props = {}
            required = []
            schema = dict(type="object", properties=props)
            for k, v in tool.args.items():
                props[k] = v
                required.append(k)
            schema["required"] = required

            d = dict(
                name=tool.name,
                description=tool.description,
                input_schema=schema,
            )
            tools_out.append(d)

        n.tools = tools_out
        return n

    def set_response_format(self, mode=None, schema=None, strict=False, **kwargs):
        self.model_kwargs = self.model_kwargs or {}

        name = "response"
        description = "The final response for this request"
        if schema:
            name = schema.get("name") or schema.get("title") or name
            description = schema.get("description") or description
        else:
            schema = dict(type="object")

        tools_out = self.tools or []
        if len(tools_out) > 0:
            LLMApiLogger.warn_static(
                "Binding additional tools along with structured output will cause the model to potentially ignore one or the other, output format may not be stable"
            )
            name = "final_response"
            description = "The final response for this request"

        tools_out.append(
            dict(
                name=name,
                description=description,
                input_schema=schema,
            )
        )

        self.tools = tools_out

        if len(tools_out) == 1 and False:
            # XXX LITE LLM IS NOT DOING THIS CORRECTLY
            self.model_kwargs["tool_choice"] = dict(type="tool", tool=dict(name=name))
        else:
            # Force it too choose so we don't entirely prevent tool calls in agents
            self.model_kwargs["tool_choice"] = "required"

        self.tool_as_output = name

        return self

    def parse_response_message(
        self, gen_response: dict, new_message_ind: int, conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_choice = gen_response["choices"][0]
        gen_msg_json = gen_choice["message"]

        #LLMApiLogger.debug_static(f"Anthropic response: {json.dumps(gen_response, indent=2)}")

        message = openai_convert_dict_to_message(gen_msg_json)
        message = ApiMessageBase.from_message(
            message,
            new_message_ind,
            conversation_id=conversation_id,
        )
        if isinstance(message, AIApiMessage):
            message.tool_calls_raw = gen_msg_json.get("tool_calls", []) or []

            tool_res = None
            if self.tool_as_output:
                if len(message.tool_calls_raw) > 1:
                    # Search for the tool call that matches the tool_as_output
                    tool_res = next(
                        [
                            tool_res
                            for tool_res in message.tool_calls_raw
                            if tool_res.get("function").get("name")
                            == self.tool_as_output
                        ]
                        + [None]
                    )
                if not tool_res and len(message.tool_calls_raw) > 0:
                    tool_res = message.tool_calls_raw[0]

                # Remove the tool response tool call
                message.tool_calls_raw = [
                    tool_res
                    for tool_res in message.tool_calls_raw
                    if tool_res.get("function").get("name") != self.tool_as_output
                ]

            if tool_res:
                message.content = tool_res.get("function").get("arguments")

        generation_info = dict(finish_reason=gen_choice.get("finish_reason"))
        return ChatGenerationWithLLMOutput(
            message=message, generation_info=generation_info, llm_output=gen_response
        )

    def preprocess_message_json(self, messages):
        if not self.__SUPPORTS_CACHE__:
            return super().preprocess_message_json(messages)
        if not self.use_cache:
            return super().preprocess_message_json(messages)

        index = -1
        for i, m in enumerate(messages):
            if m.get("disable_cache"):
                if i == 0:
                    LLMApiLogger.warn_static("👻 Disabling Prompt Cache to prevent cache churn! Probably due to blowing out the context window.")
                    return super().preprocess_message_json(messages)

                index = i - 1
                break

        if index != -1:
            LLMApiLogger.warn_static(f"👻 Disabling Prompt Cache from message #{index} onwards to prevent cache churn! Probably due to blowing out the context window.")

        # Put the cache marker on the last message
        if len(messages) > 0 and index < len(messages):
            messages[index]["cache_control"] = dict(type="ephemeral")
        for m in messages:
            if m.get("role") == "system":
                m["cache_control"] = dict(type="ephemeral")

        return super().preprocess_message_json(messages)