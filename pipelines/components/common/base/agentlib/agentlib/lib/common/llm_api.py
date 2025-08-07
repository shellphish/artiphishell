import os
import json
import random
import time
import uuid
from typing import Callable, Optional, List, Any, Literal, Dict, Union, Sequence, Type

import openai
import requests
from pydantic.v1.main import ModelMetaclass, BaseModel
from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder,
)
from langchain_core.tools import BaseTool
from langchain_core.prompts.chat import MessageLikeRepresentation, BaseMessagePromptTemplate
from langchain_core.outputs import ChatResult, ChatGeneration
from langchain_core.runnables import Runnable
from langchain_core.callbacks import (
    Callbacks, CallbackManagerForLLMRun,
)
from langchain_core.prompt_values import (
    ChatPromptValue, PromptValue,
)
from langchain_core.utils.function_calling import (
    convert_to_openai_tool,
)
from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import (
    BaseMessage, HumanMessage,
    SystemMessage, AIMessage,
    ToolMessage,
    convert_to_messages
)
from langchain_core.pydantic_v1 import BaseModel, Field, SecretStr, root_validator
from langchain_core.language_models.chat_models import (
    BaseChatModel, ChatPromptValue,
    SimpleChatModel, StringPromptValue
)

import litellm
litellm.set_verbose=True
from litellm import completion

from langchain_openai.chat_models.base import _convert_dict_to_message as openai_convert_dict_to_message

from .object import SaveLoadObject


#SECRET = '!!Shellphish!!'
SECRET = os.environ.get('LITELLM_KEY','')

#API_ENDPOINT = 'http://beatty.unfiltered.seclab.cs.ucsb.edu:4269/completions'
API_ENDPOINT = os.environ.get('AIXCC_LITELLM_HOSTNAME', '')

LLM_API_CLIENT = openai.OpenAI(
    api_key=SECRET,
    base_url=API_ENDPOINT
) if API_ENDPOINT and SECRET else None

class ApiConversationIdTrait(SaveLoadObject):
    conversation_id: Optional[str] = None

ROLE_TRANSLATIONS = dict(
    system = 'system',
    human = 'user',
    ai = 'assistant',
    tool = 'tool',
)

# The message class includes the index id of the message in the conversation and the conversation id
class ApiMessageTrait(ApiConversationIdTrait):
    message_id: int

    def get_message_json(self):
        return dict(
            role = ROLE_TRANSLATIONS.get(self.type, self.type),
            content = self.content,
            message_id = self.message_id,
        )

class _DisallowIsInstanceForApiMessageBase(ModelMetaclass):
    # Override is instance as actual messages will subclass ApiMessageTrait instead of ApiMessageBase
    def __instancecheck__(self, *args, **kwargs):
        raise TypeError(f"isinstance() is not supported for type {self.__name__}. Please use isinstance(a, ApiMessageTrait) instead.")

class ApiMessageBase(BaseMessage, ApiMessageTrait, metaclass=_DisallowIsInstanceForApiMessageBase):
    @classmethod
    def from_messages(
        cls,
        messages: List[BaseMessage],
        conversation_id: Optional[str] = None,
        start_index = 0
    ) -> List["ApiMessageTrait"]:
        for i, message in enumerate(messages):
            my_index = start_index + i
            if isinstance(message, ApiMessageTrait):
                cid = message.conversation_id
                if (
                    cid and conversation_id
                    and conversation_id == cid
                ):
                    # Only use the message id if it is from the same conversation
                    my_index = message.message_id

            api_message = ApiMessageBase.from_message(
                message, my_index,
                conversation_id=conversation_id
            )
            messages[i] = api_message

        return messages

    @classmethod
    def from_message(
        cls,
        message: BaseMessage,
        message_index:int,
        conversation_id: Optional[str] = None
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
            assert(issubclass(target_cls, ApiPromptTemplateTrait))
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
                prompt_template = template,
                message_id=message_index,
                conversation_id=conversation_id,
                prompt_args = {},
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
        res['prompt_template'] = self.prompt_template
        res['prompt_args'] = self.prompt_args
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
        res.update({
            k: getattr(self, k)
            for k, v in self.__fields__.items()
        })
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
        res.update({
            k: getattr(self, k)
            for k, v in self.__fields__.items()
        })
        return res

class AIApiMessage(AIMessage, ApiMessageTrait):
    tool_calls_raw: List[Dict[str, Any]] = []
    def get_message_json(self):
        res = super().get_message_json()
        if self.tool_calls_raw:
            res['tool_calls'] = self.tool_calls_raw or []
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
        res.update({
            k: getattr(self, k)
            for k, v in self.__fields__.items()
        })
        return res

class ToolApiMessage(ToolMessage, ApiMessageTrait):
    def get_message_json(self):
        res = super().get_message_json()
        res['tool_call_id'] = self.tool_call_id
        res['name'] = self.tool_call_id # TODO get actual tool name
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
        res.update({
            k: getattr(self, k)
            for k, v in self.__fields__.items()
        })
        return res

def prep_value_for_api_call(thing: Any):
    if thing is None:
        return thing

    # TODO handle bytes???

    if type(thing) in [str, int, float, bool, None]:
        return thing

    if isinstance(thing, BaseModel):
        thing = {
            k: v for k,v in thing.dict().items()
            if not k.startswith('_') # XXX is this too restrictive?
        }
    
    if isinstance(thing, dict):
        return {
            k: prep_value_for_api_call(v)
            for k, v in thing.items()
        }
    
    if isinstance(thing, list):
        return [
            prep_value_for_api_call(v)
            for v in thing
        ]
    
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
            k: prep_value_for_api_call(v)
            for k, v in args.items()
            if k in input_vars
        }
        return all_vars


class SystemApiPromptTemplate(SystemMessagePromptTemplate, ApiPromptTemplateTrait):
    def convert_to_message(self, **kwargs) -> SystemApiMessage:
        rendered_msg = self.format(**kwargs)
        return SystemApiMessage(
            content = rendered_msg.content,
            message_id = self.message_id,
            conversation_id = self.conversation_id,
            prompt_template = self.prompt.template,
            prompt_args = self.get_prompt_args(**kwargs),
        )



class HumanApiPromptTemplate(HumanMessagePromptTemplate, ApiPromptTemplateTrait):
    def convert_to_message(self, **kwargs) -> HumanApiMessage:
        rendered_msg = self.format(**kwargs)
        return HumanApiMessage(
            content = rendered_msg.content,
            message_id = self.message_id,
            conversation_id = self.conversation_id,
            prompt_template = self.prompt.template,
            prompt_args = self.get_prompt_args(**kwargs),
        )




# This class represents a set of historical messages from the current conversation
class ApiConversation(ApiConversationIdTrait):
    messages: list[ApiMessageTrait] = []

    def add_messages(self, messages: List[BaseMessage]):
        for message in messages:
            indx = len(self.messages)
            api_message = ApiMessageTrait.from_message(
                message, indx,
                conversation_id=self.conversation_id
            )
            self.messages.append(api_message)


# We also need a special prompt template which does not actually template anything before passing it into the model
# It will produce the ApiChatPromptValue when invoked
class ApiChatPromptTemplate(ChatPromptTemplate,ApiConversationIdTrait):
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
                message = message.convert_to_message(
                    **kwargs
                )

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
                start_index=len(value_messages)
            )
            value_messages.extend(var_messages)
                
        return ApiChatPromptValue.from_messages(
            value_messages,
            conversation_id=conversation_id
        )

    @classmethod
    def from_messages(
        cls,
        messages: Sequence[MessageLikeRepresentation],
        template_format: Literal["f-string", "mustache"] = "f-string",
        conversation_id: Optional[str] = None
    ) -> ChatPromptTemplate:
        template: ChatPromptTemplate = super().from_messages(
            messages,
            template_format=template_format
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
            template.messages,
            conversation_id=conversation_id
        )
        template.messages = msgs

        my_template = cls.from_pydantic(
            template,
            conversation_id=conversation_id
        )
        return my_template

# This wrapper for the ChatPromptValue will not actually have the template output. Instead it will be used to pass into the ChatAPI
# This is a set of messages that will be passed into the API
class ApiChatPromptValue(ChatPromptValue, SaveLoadObject):
    conversation_id: Optional[str] = None

    @classmethod
    def from_messages(
        cls,
        messages: List[BaseMessage],
        conversation_id: Optional[str] = None
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

    class Config:
        """Configuration for this pydantic object."""
        allow_population_by_field_name = True

    @property
    def _llm_type(self) -> str:
        """Return type of chat model."""
        return "shellphish-llm-api"

    def create_tools_agent(self, *args, **kwargs):
        raise NotImplementedError('This model does not support tool calls')

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
                messages=[
                    HumanApiMessage(content=input, message_id=0)
                ]
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
        generation = self._call(
            messages,
            stop=stop,
            run_manager=run_manager,
            **kwargs
        )
        return ChatResult(
            generations=[generation],
            llm_output = generation.llm_output,
        )
    
    def _call(
        self,
        messages: List[ApiMessageBase],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatGenerationWithLLMOutput:
        assert(len(messages) > 0)

        # TODO get a namespace for the conversation
        new_message_ind = len(messages)
        namespace = 'agentlib.unknown'

        messages_json = []
        for message in messages:
            message_json = message.get_message_json()
            message_json['author'] = namespace # More detailed namespace
            messages_json.append(message_json)

        params = dict(
            temperature = self.temperature,
            max_tokens = self.max_tokens,
        )

        if self.model_kwargs:
            params.update(self.model_kwargs)

        if kwargs.get('tools'):
            params['tools'] = kwargs['tools']

        while True:
            try:
                sleep_time = random.randint(60, 60*3)
            except:
                sleep_time = 30
            try:
                resp = LLM_API_CLIENT.chat.completions.create(
                    model=self.model_name,
                    messages=messages_json,
                    #base_url = API_ENDPOINT,
                    #api_key = SECRET,
                    **params
                )
                #response_json = resp.json()
                response_json = json.loads(resp.json())
                break
            except litellm.exceptions.RateLimitError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.ServiceUnavailableError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.InternalServerError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.APIConnectionError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.APIError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.BadRequestError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.PermissionDeniedError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.Timeout as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.UnprocessableEntityError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.NotFoundError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.AuthenticationError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except litellm.exceptions.APIResponseValidationError as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)
            except Exception as e:
                import traceback
                traceback.print_exc()
                time.sleep(sleep_time)

            



        conversation_id = str(uuid.uuid4())

        return self.parse_response_message(
            response_json,
            new_message_ind,
            conversation_id
        )

        '''

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
        '''


    def parse_response_message(
            self,
            gen_response: dict,
            new_message_ind: int,
            conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_msg_json = gen_response["choices"][0]["message"]
        # Generic llm that does not support tool calls
        gen_msg_content = gen_msg_json["content"]

        if gen_msg_content is None:
            gen_msg_content = ""

        message = AIApiMessage(
            content=gen_msg_content,
            message_id=new_message_ind,
            conversation_id=conversation_id
        )
        return ChatGenerationWithLLMOutput(
            message=message,
            llm_output = gen_response
        )
        
class ChatApiOpenAi(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = True

    def parse_response_message(
            self,
            gen_response: dict,
            new_message_ind: int,
            conversation_id: str
    ) -> ChatGenerationWithLLMOutput:
        gen_choice = gen_response["choices"][0]
        gen_msg_json = gen_choice["message"]

        message = openai_convert_dict_to_message(gen_msg_json)
        message = ApiMessageBase.from_message(
            message, new_message_ind,
            conversation_id=conversation_id,
        )
        if isinstance(message, AIApiMessage):
            message.tool_calls_raw = gen_msg_json.get("tool_calls", [])

        generation_info = dict(
            finish_reason = gen_choice.get("finish_reason")
        )
        return ChatGenerationWithLLMOutput(
            message=message,
            generation_info=generation_info,
            llm_output=gen_response
        )

    def create_tools_agent(self, *args, **kwargs):
        from langchain.agents import create_openai_tools_agent
        return create_openai_tools_agent(self, *args, **kwargs)
    

class ChatApiAnthropic(ChatApi):
    __SUPPORTS_TOOL_CALLS__ = False