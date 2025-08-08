import sys
import os
import json
import time
import inspect
from uuid import uuid4
from typing import Dict, Any, Union, Generic, Optional, List
from pathlib import Path


from langchain.tools import BaseTool
from langchain.chains import LLMChain
from langchain.pydantic_v1 import ValidationError
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.load.dump import dumpd
from langchain.agents import AgentExecutor
from langchain.agents.output_parsers.tools import ToolAgentAction
from langchain_core.callbacks import CallbackManager
from langchain_core.outputs import LLMResult
from langchain_core.runnables import Runnable
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence
from langchain_core.runnables.utils import Input, Output
from langchain_core.output_parsers import BaseOutputParser
from langchain_core.prompts.chat import BaseMessagePromptTemplate
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder


from langchain_core.output_parsers import XMLOutputParser
from langchain.agents import (
    create_openai_tools_agent,
    create_json_chat_agent,
)
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.agents import AgentAction, AgentFinish, AgentStep
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    AIMessageChunk,
    ToolMessage,
)

from ..tools import ToolSignal
from ..tools.tool_wrapper import get_langchain_tools
from ..common.base import BaseRunnable, BaseObject, Field
from ..common.base import LangChainLogger
from ..common.store import LocalObjectRepository
from ..common.parsers import PlainTextOutputParser, JSONParser
from ..common.object import LocalObject, RunnableLocalObject, SaveLoadObject
from ..common.available_llms import ModelRegistry
from ..common.llm_api import (
    ApiConversationIdTrait,
    ContextWindowExceededError,
    LLMApiBudgetExceededError,
    ChatApiOpenAi,
    ChatApiAnthropic,
    AIApiMessage,
    ApiMessageBase,
    ROLE_TRANSLATIONS,
)
from ..common.langchain_agent.anthropic_agent import create_anthropic_tools_agent
from ..common.base import ContinueConversationException
from ..common.llm_api import LLMApiContextWindowExceededError

global_token_usage = {}


class TokenUsage(SaveLoadObject):
    prompt_tokens: int = 0
    completion_tokens: int = 0

    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def get_dict(self):
        return dict(
            prompt_tokens=self.prompt_tokens, completion_tokens=self.completion_tokens
        )

    def get_costs(self, model: str):
        return self.calculate_costs(
            model,
            self.prompt_tokens,
            self.completion_tokens,
            self.cache_creation_input_tokens,
            self.cache_read_input_tokens,
        )

    @classmethod
    def calculate_costs(
        cls,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cache_creation_input_tokens: int = 0,
        cache_read_input_tokens: int = 0,
    ):
        if model is None:
            return dict(
                prompt_cost=0,
                completion_cost=0,
                total_cost=0,
                tcpm=0,
            )

        # 0.0001
        per_t_in = 0
        per_t_out = 0

        prompt_cost = 0
        completion_cost = 0

        per_t_in_cache_read = None
        per_t_in_cache_write = None

        if "o4-mini" in model:
            per_t_in = 1.10
            per_t_out = 4.40
            per_t_in_cache_read = 0.275
        elif "o3-mini" in model:
            per_t_in = 1.10
            per_t_out = 4.40
            per_t_in_cache_read = 0.55
        elif "o3" in model:
            per_t_in = 2
            per_t_out = 8
            per_t_in_cache_read = 0.50
        elif "o1-preview" in model:
            per_t_in = 15
            per_t_out = 60
            per_t_in_cache_read = 7.5
        elif "o1-mini" in model:
            per_t_in = 1.10
            per_t_out = 4.40
            per_t_in_cache_read = 0.55
        elif "o1" in model:
            per_t_in = 15
            per_t_out = 60
            per_t_in_cache_read = 7.5
        elif "gpt-4-turbo" in model:
            per_t_in = 10
            per_t_out = 30
        elif "gpt-4.1-nano" in model:
            per_t_in = 0.10
            per_t_out = 0.40
            per_t_in_cache_read = 0.025
        elif "gpt-4.1-mini" in model:
            per_t_in = 0.4
            per_t_out = 1.6
            per_t_in_cache_read = 0.10
        elif "gpt-4.1" in model:
            per_t_in = 2
            per_t_out = 8
            per_t_in_cache_read = 0.5
        elif "gpt-4o-mini" in model:
            per_t_in = 0.15
            per_t_out = 0.6
            per_t_in_cache_read = 0.075
        elif "gpt-4o" in model:
            if '05-13' in model:
                per_t_in = 5
                per_t_out = 15
                per_t_in_cache_read = 0
            else:
                per_t_in = 2.5
                per_t_out = 10
                per_t_in_cache_read = 1.25
        elif "gpt-4" in model:
            per_t_in = 30
            per_t_out = 60
        elif "gpt-3.5-turbo" in model or "gpt-3-5-turbo" in model:
            per_t_in = 1
            per_t_out = 2
        elif "claude-4-opus" in model or "claude-opus-4" in model:
            per_t_in = 15
            per_t_out = 75
            per_t_in_cache_read = 1.5
            per_t_in_cache_write = 18.75
        elif "claude-4-sonnet" in model or "claude-sonnet-4" in model:
            per_t_in = 3
            per_t_out = 15
            per_t_in_cache_read = 0.3
            per_t_in_cache_write = 3.75
        elif "claude-3.7-sonnet" in model or "claude-3-7-sonnet" in model:
            per_t_in = 3
            per_t_out = 15
            per_t_in_cache_read = 0.3
            per_t_in_cache_write = 3.75
        elif "claude-3.5-sonnet" in model or "claude-3-5-sonnet" in model:
            per_t_in = 3
            per_t_out = 15
            per_t_in_cache_read = 0.3
            per_t_in_cache_write = 3.75
        elif "claude-3-opus" in model:
            per_t_in = 15
            per_t_out = 75
            per_t_in_cache_read = 1.5
            per_t_in_cache_write = 18.75
        elif "claude-3-sonnet" in model:
            per_t_in = 3
            per_t_out = 15
            per_t_in_cache_read = 0.3
            per_t_in_cache_write = 3.75
        elif "claude-3.5-haiku" in model:
            per_t_in = 0.8
            per_t_out = 3.2
            per_t_in_cache_read = 0.08
            per_t_in_cache_write = 1
        elif "claude-3-haiku" in model:
            per_t_in = 0.25
            per_t_out = 1.25
            per_t_in_cache_read = 0.03
            per_t_in_cache_write = 0.3

        # https://ai.google.dev/gemini-api/docs/pricing
        elif "gemini-2.5-pro" in model:
            if prompt_tokens > 200000:
                per_t_in = 2.5
                per_t_out = 15
                per_t_in_cache_read = 0.625
            else:
                per_t_in = 1.25
                per_t_out = 10
                per_t_in_cache_read = 0.31

        elif "gemini-2.0-flash-lite" in model:
            per_t_in = 0.075
            per_t_out = 0.30
        elif "gemini-2.0-flash" in model:
            per_t_in = 0.10
            per_t_out = 0.40
        elif "gemini-1.5-flash-8b" in model:
            if prompt_tokens > 128000:
                per_t_in = 0.075
                per_t_out = 0.30
            else:
                per_t_in = 0.0375
                per_t_out = 0.15
        elif "gemini-1.5-flash" in model:
            if prompt_tokens > 128000:
                per_t_in = 0.15
                per_t_out = 0.60
            else:
                per_t_in = 0.075
                per_t_out = 0.30
        elif "gemini-1.5-pro" in model:
            if prompt_tokens > 128000:
                per_t_in = 2.50
                per_t_out = 10
            else:
                per_t_in = 1.25
                per_t_out = 5.00

        else:
            cls.warn_static(f"Cost not known for model: {model}, not counting")

        if cache_creation_input_tokens:
            prompt_tokens -= cache_creation_input_tokens
            prompt_cost += cache_creation_input_tokens * per_t_in_cache_write
            cls.debug_static(
                f"Prompt cache write: {cache_creation_input_tokens} tokens"
            )

        if cache_read_input_tokens:
            prompt_tokens -= cache_read_input_tokens
            prompt_cost += cache_read_input_tokens * per_t_in_cache_read
            cls.debug_static(f"Prompt cache read: {cache_read_input_tokens} tokens")

        prompt_cost += prompt_tokens * per_t_in
        completion_cost += completion_tokens * per_t_out

        total_cost = prompt_cost + completion_cost

        m = 1 / 1000000  # per million tokens

        return dict(
            prompt_cost=prompt_cost * m,
            completion_cost=completion_cost * m,
            total_cost=total_cost * m,
            tcpm=total_cost,
        )


class LLMEvent(SaveLoadObject):
    model: Optional[str]
    event_tag: Optional[str]
    token_usage: TokenUsage = TokenUsage()
    messages: List[dict] = []

    def get_dict(self):
        return dict(
            model=self.model,
            event=self.event_tag,
            token_usage=self.token_usage.get_dict(),
            cost=self.token_usage.get_costs(self.model),
            messages=self.messages,
        )


class SimpleUsageCollector(BaseCallbackHandler):
    def __init__(self, **kw):
        self.usage = TokenUsage()

    def on_llm_end(self, response: LLMResult, **kwargs):
        llm_output = response.llm_output or {}
        usage = llm_output.get("token_usage", llm_output.get("usage", {}))
        print("========", usage)
        self.usage.prompt_tokens += usage.get("prompt_tokens", 0)
        self.usage.completion_tokens += usage.get("completion_tokens", 0)


class EventDumper(SaveLoadObject):
    enabled: bool = False
    output_dir: Optional[Path] = None
    total_cost_per_million: int = 0

    enforce_budget_limit: bool = False
    budget_limit_per_million: int = 0
    kill_on_over_budget: bool = False

    def enable_event_dumping(self, output_dir: str | Path):
        self.enabled = True
        if not output_dir:
            self.log_error("No output dir provided for event dumping!")
            return

        self.output_dir = Path(output_dir).resolve()
        try:
            if not self.output_dir.exists():
                self.output_dir.mkdir(parents=True)
        except Exception as e:
            self.warn(
                f"Failed to create output dir: {self.output_dir}. Error: {str(e)}"
            )

        # Load all existing results from the directory and add them to the current total cost info

        for fn in self.output_dir.iterdir():
            if not fn.is_file():
                continue
            try:
                data = json.loads(fn.read_text())
                cost = data.get("cost", {})
                self.total_cost_per_million += cost.get("tcpm", 0)
            except Exception as e:
                self.warn(f"Failed to load file: {fn}. Error: {str(e)}")

        self.warn(
            f"Loaded existing llm history from {self.output_dir}. Budget use so far ${self.total_cost_per_million} / 1000000"
        )

    def record_llm_event(self, event: LLMEvent):
        costs = event.token_usage.get_costs(event.model)
        old_total_cost = self.total_cost_per_million
        self.total_cost_per_million += costs.get("tcpm", 0)
        self.warn(f"Recording llm event cost: {costs} for {event.model}... {old_total_cost} -> {self.total_cost_per_million}")

        if not self.enabled:
            return
        if not self.output_dir:
            return

        fn = f"{int(time.time())}_{event.event_tag}_llm_record.json"
        fp = self.output_dir / fn
        fp.write_text(json.dumps(event.get_dict(), indent=2))

    def check_if_over_budget(self):
        if not self.enforce_budget_limit:
            return
        if self.budget_limit_per_million == 0:
            return

        m = 1 / 1000000  # per million tokens
        self.warn(
            f"Total Budget Usage: ${self.total_cost_per_million * m} / ${self.budget_limit_per_million * m}"
        )

        if self.total_cost_per_million <= self.budget_limit_per_million:
            return

        if self.kill_on_over_budget:
            self.log_error("Application is over budget! Exiting...")
            os._exit(0)
            sys.exit(0)

        self.warn("Application is over budget!")

    def set_global_budget_limit(self, price_in_dollars=0, exit_on_over_budget=False, lite_llm_budget_name=None):
        self.enforce_budget_limit = True
        self.budget_limit_per_million = int(price_in_dollars * 1000000)
        self.kill_on_over_budget = exit_on_over_budget
        m = 1 / 1000000  # per million tokens
        if lite_llm_budget_name:
            from ..common.llm_api import LiteLLMBudgetManager
            LiteLLMBudgetManager.set_budget_name(lite_llm_budget_name)
            self.warn(f"Setting maximum LLM budget to ${self.budget_limit_per_million * m} under global litellm budget: `{lite_llm_budget_name}`")
        else:
            self.warn(f"Setting maximum LLM budget to ${self.budget_limit_per_million * m}")


global_event_dumper = EventDumper()


def enable_event_dumping(output_dir: str | Path):
    global_event_dumper.enable_event_dumping(output_dir)


def set_global_budget_limit(price_in_dollars=0, exit_on_over_budget=False, lite_llm_budget_name=None):
    global_event_dumper.set_global_budget_limit(
        price_in_dollars=price_in_dollars, exit_on_over_budget=exit_on_over_budget, lite_llm_budget_name=lite_llm_budget_name
    )


class LLMFunction(RunnableLocalObject[Input, Output]):
    chain: Optional[RunnableSequence] = None
    owner_id: Optional[LocalObject] = LocalObject.Weak()
    metadata: Optional[Dict[str, Any]] = None
    format_instructions: Optional[str] = None
    retries: int = 0
    include_usage: bool = False

    def __init__(
        self, chain=None, owner=None, retries=0, include_usage=False, **kwargs
    ):
        super().__init__(**kwargs)
        self.retries = retries
        if owner:
            self.owner = owner
            self._owner = owner  # Cached reference to prevent lookups
            self.runnable_config = self.owner.runnable_config
        if chain:
            self.chain = chain
        self.include_usage = include_usage

    def invoke(self, input: Input, **kwargs) -> Output:
        if type(input) is dict and self.format_instructions:
            input["format_instructions"] = self.format_instructions
            input["output_format"] = self.format_instructions
        kwargs["config"] = kwargs.get("config", self.runnable_config)

        usage_log = None
        if self.include_usage:
            usage_log = SimpleUsageCollector()
            if not kwargs["config"].get("callbacks"):
                kwargs["config"]["callbacks"] = []
            kwargs["config"]["callbacks"].append(usage_log)

        res = self.chain.invoke(input, **kwargs)
        if usage_log:
            return res, usage_log.usage

        return res

    def __call__(self, **kwargs) -> Output:
        if self.retries > 0:
            for i in range(self.retries):
                try:
                    return self.invoke(dict(**kwargs))
                except Exception as e:
                    import traceback

                    traceback.print_exc()
                    self.warn(
                        f"Failed to call LLM. Retries left {self.retries - i}. Error: {str(e)}"
                    )

        return self.invoke(dict(**kwargs))

    @classmethod
    def get_output_parser(cls, output, llm_args=None):
        if llm_args is None:
            llm_args = {}

        if output == "json":
            output = JSONParser()
        elif output == "json_object":
            output = JSONParser()
            llm_args["json"] = True
        elif output == "xml":
            output = XMLOutputParser()
        elif output is str:
            output = PlainTextOutputParser()
        elif type(output) is str and output.lower() in [
            "str",
            "string",
            "text",
            "plaintext",
        ]:
            output = PlainTextOutputParser()
        elif output is None:
            output = PlainTextOutputParser()
        elif inspect.isclass(output) and issubclass(output, Runnable):
            output = output()
            assert isinstance(output, Runnable)
        elif isinstance(output, Runnable):
            output = output
        else:
            raise ValueError(f"Unknown output type: {output}")
        return output

    @classmethod
    def convert_prompt_into_chat_template(cls, prompt, cls_context=None, model=None):
        cls_context = cls_context or cls
        prompt = list(prompt)
        if len(prompt) == 1:
            prompt = prompt[0]

        if type(prompt) is str or type(prompt) is tuple:
            prompt = [prompt]

        cls.debug_static(f"Prompt: {prompt}")

        if isinstance(prompt, ChatPromptTemplate):
            pass
        elif type(prompt) is list:
            prompt_msg = []
            count_num = 0
            for p in prompt:
                if isinstance(p, BaseMessagePromptTemplate):
                    prompt_msg.append(p)
                    # Doesn't count towards the system/user count
                    continue

                if type(p) is str:
                    # o1-preview and o1-mini do not support system messages
                    if len(prompt) == 1 or "o1-" in model:
                        p = ("user", p)
                    else:
                        p = (["system", "user"][count_num % 2], p)

                if type(p) is tuple:
                    role, template = p
                    p = cls_context.load_prompt(template, role=role)
                    prompt_msg.append(p)
                    count_num += 1
                    continue

                raise ValueError(f"Invalid prompt format: {type(p)}: {p}")
            prompt = ChatPromptTemplate.from_messages(prompt_msg)
        assert prompt
        return prompt

    @classmethod
    def create(
        cls,
        *prompt: list[tuple[str, str | PromptTemplate]],
        output: str = None,
        model: str = None,
        function_owner: BaseRunnable = None,
        config: dict = None,
        use_logging: bool = False,
        retries: int = 0,
        include_usage: bool = False,
        **llm_args,
    ):
        cls_context: BaseRunnable = function_owner or cls

        prompt = cls.convert_prompt_into_chat_template(prompt, cls_context, model=model)

        output_parser = cls.get_output_parser(output, llm_args)
        format_instructions = None
        if output_parser and hasattr(output_parser, "get_format_instructions"):
            format_instructions = output_parser.get_format_instructions()

        llm = cls_context.get_llm_by_name(model, **llm_args)

        if output_parser:
            chain = prompt | llm | output_parser
        else:
            chain = prompt | llm

        res = cls(
            chain=chain,
            owner=function_owner,
            retries=retries,
            include_usage=include_usage,
        )
        res.format_instructions = format_instructions

        if config:
            res.runnable_config = config
        elif (
            function_owner
            and hasattr(function_owner, "runnable_config")
            and function_owner.runnable_config
        ):
            res.runnable_config = function_owner.runnable_config
        else:
            res.runnable_config = {"callbacks": []}

        if use_logging:
            from ..web_console import WebConsoleLogger

            res.runnable_config["callbacks"].append(WebConsoleLogger())

        return res


class AgentRepository(LocalObjectRepository):
    __ROOT_DIR__ = Path("volumes/agents").resolve()


class AgentCallbackHandler(BaseCallbackHandler):
    def __init__(self, agent, **kw):
        self.agent: "Agent" = agent
        self.conversation: Optional[List] = None
        self.metadata = dict(**kw)
        self.event = LLMEvent()
        self.toolcall_metadata = {}

    def reset(self):
        self.conversation = None
        self.toolcall_metadata = {}
        self.reset_event()
    
    def reset_event(self):
        self.event = LLMEvent()

    def ensure_conversation(self):
        if self.conversation is None:
            self.conversation = []

    def get_last_ai_message(self):
        for m in reversed(self.conversation):
            if isinstance(m, AIMessage):
                return m
        return None

    def find_tool_call_by_id(self, call_id: str):
        for m in reversed(self.conversation):
            if isinstance(m, ToolMessage):
                if m.tool_call_id == call_id:
                    return m
        return None

    def on_llm_end(self, response: LLMResult, **kwargs):
        try:
            message = response.generations[0][0].message
            llm_output = response.llm_output or {}
            usage = llm_output.get("token_usage", llm_output.get("usage", {}))
            model_name = llm_output.get("model_name", llm_output.get("model"))
            if self.agent:
                if not self.agent.token_usage:
                    self.agent.token_usage = {}

                if not model_name:
                    model_name = self.agent.__LLM_MODEL__

                self.event.model = model_name
                self.event.event_tag = self.agent.get_name()

                agent_usage_sum = self.agent.token_usage.get(model_name, TokenUsage())

                agent_usage_sum.prompt_tokens += usage.get(
                    "prompt_tokens", usage.get("input_tokens", 0)
                )
                agent_usage_sum.completion_tokens += usage.get(
                    "completion_tokens", usage.get("output_tokens", 0)
                )

                self.agent.token_usage[model_name] = agent_usage_sum

            self.event.token_usage.prompt_tokens += usage.get(
                "prompt_tokens", usage.get("input_tokens", 0)
            )
            self.event.token_usage.completion_tokens += usage.get(
                "completion_tokens", usage.get("output_tokens", 0)
            )

            if "claude" in model_name:
                self.event.token_usage.cache_creation_input_tokens += usage.get(
                    "cache_creation_input_tokens", 0
                )
                self.event.token_usage.cache_read_input_tokens += usage.get(
                    "cache_read_input_tokens", 0
                )

            elif (usage.get("prompt_tokens_details", {}) or {}).get("cached_tokens"):
                self.event.token_usage.cache_read_input_tokens += (usage.get(
                    "prompt_tokens_details", {}
                ) or {}).get("cached_tokens", 0)

            if isinstance(message, AIMessageChunk):
                self.ensure_conversation()
                message = AIMessage(content=message.content)
                self.conversation.append(message)
            elif isinstance(message, AIMessage):
                self.ensure_conversation()
                self.conversation.append(message)
            elif message.type == "ai":
                self.ensure_conversation()
                self.conversation.append(message)
            else:
                return

            self.event.messages.append(
                dict(
                    role=ROLE_TRANSLATIONS.get(message.type, message.type),
                    content=message.content,
                )
            )

            if isinstance(message, ApiConversationIdTrait):
                conv_id = message.conversation_id
                if conv_id:
                    for m in self.conversation:
                        if not isinstance(m, ApiConversationIdTrait):
                            continue
                        m.conversation_id = conv_id
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error in on_llm_end: {e}")
            raise e

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        **kwargs: Any,
    ) -> Any:
        if len(messages) < 1:
            return
        messages = messages[0]

        messages_to_add_to_event = messages[len(self.event.messages) :]
        for message in messages_to_add_to_event:
            self.event.messages.append(
                dict(
                    role=ROLE_TRANSLATIONS.get(message.type, message.type),
                    content=message.content,
                )
            )

        if len(messages) < 1:
            return
        message: BaseMessage = messages[-1]

        if message.type == "human":
            self.ensure_conversation()
            self.conversation.append(message)

    def on_agent_action(self, action: AgentAction, *args: Any, **kwargs: Any) -> Any:
        return self.agent.on_agent_action(self, action, **kwargs)

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, *args: Any, **kwargs: Any
    ) -> Any:
        return self.agent.on_tool_start(self, serialized, input_str, **kwargs)

    def on_tool_end(self, output: str, *args, **kwargs: Any) -> Any:
        self.ensure_conversation()

        ai_message = self.get_last_ai_message()
        msg = None
        if not ai_message:
            msg = HumanMessage(content=output)
        else:
            tool_calls = ai_message.tool_calls
            for i, tool_call in enumerate(tool_calls):
                if self.find_tool_call_by_id(tool_call["id"]):
                    # Already accounted for
                    continue
                if output is None:
                    raise ValueError(
                        f"Tools may not return None! They must always return a string with feedback for the LLM. Returning None is not supported and must be fixed. Tool: {tool_call['name']}"
                    )
                # TODO tool name
                msg = ToolMessage(
                    content=output, tool_call_id=tool_call["id"], name=tool_call["name"]
                )

                if isinstance(ai_message, AIApiMessage):
                    msg = ApiMessageBase.from_message(
                        msg,
                        message_index=ai_message.message_id + 1 + i,
                        conversation_id=ai_message.conversation_id,
                    )

        if output is None:
            raise ValueError(
                "Tools may not return None! They must always return a string with feedback for the LLM. Returning None is not supported and must be fixed. Tool: unknown"
            )

        if msg:
            self.conversation.append(msg)

        return self.agent.on_tool_end(self, output, **kwargs)

    def on_agent_finish(self, finish: AgentFinish, *args: Any, **kwargs: Any) -> Any:
        return self.agent.on_agent_finish(self, finish, **kwargs)


class AgentResponse(Generic[Output], LocalObject):
    value: Optional[Output] = None
    """
    This is the final output of the agent.
    This will either be the raw output from the LLM, or the parsed output from the output parser (if one was specified).
    """
    error: Optional[str] = None
    error_raw: Optional[Exception] = Field(
        default=None, exclude=True, exclude_from_schema=True
    )
    """
    If an error was encountered during the LLM call, this will contain the error message.
    """
    chat_messages: List[Union[AIMessage, HumanMessage, ToolMessage]] = []
    """
    This is a list of all the chat messages that were used or generated during the agent's execution, including the final `AIMessage`.
    """
    signals: List[str] = []
    """
    When using toolcalls, a "signal" can be raised to end the toolcall chain early. If this happened, the signal will be listed here.
    """

    def is_success(self):
        return self.value and not self.error


class DisallowEmptyOutputFilter(RunnableLocalObject[Input, Input]):
    def invoke(self, input: Input, *args, **kwargs) -> Input:
        if self.is_response_empty(input):
            raise ValueError("Empty Response From LLM")
        return input

    def is_response_empty(self, resp: Any) -> bool:
        if isinstance(resp, dict):
            sub_resp = resp.get("content", resp.get("output"))
            if sub_resp is not None:
                resp = sub_resp
        if isinstance(resp, BaseMessage):
            resp = resp.content
        if type(resp) is str:
            resp = resp.strip()
        return not resp


class ExceptionHandlingAgentExecutor(AgentExecutor):
    retries_on_tool_validation_error: int = -1

    toolcall_metadata = {}

    raise_on_too_many_invalid_tool_calls: bool = False

    agent_callback_handler: AgentCallbackHandler = None

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.toolcall_metadata = {}
        if self.agent_callback_handler:
            self.agent_callback_handler.toolcall_metadata = self.toolcall_metadata

    def _perform_agent_action(
        self,
        name_to_tool_map: Dict[str, BaseTool],
        color_mapping: Dict[str, str],
        agent_action: AgentAction,
        run_manager: Optional[Any] = None,
    ) -> AgentStep:
        metadata = {}
        tool_name = None

        if self.agent_callback_handler:
            self.agent_callback_handler.toolcall_metadata = self.toolcall_metadata

        try:
            # print(repr(agent_action))

            if isinstance(agent_action, ToolAgentAction):
                tool_name = agent_action.tool

            metadata = self.toolcall_metadata.get(tool_name, {})
            metadata['tool_name'] = tool_name
            metadata['num_tool_calls'] = metadata.get('num_tool_calls', 0) + 1

            res = super()._perform_agent_action(
                name_to_tool_map, color_mapping, agent_action, run_manager
            )
            if tool_name:
                metadata['last_tool_call_valid'] = True
                metadata['last_tool_call_success'] = True
                metadata['num_invalid_tool_calls_in_a_row'] = 0
                metadata['num_successful_tool_calls'] = metadata.get('num_successful_tool_calls', 0) + 1
                self.toolcall_metadata[tool_name] = metadata
            return res
        except Exception as e:
            metadata['last_tool_call_success'] = False
            metadata['num_failed_tool_calls'] = metadata.get('num_failed_tool_calls', 0) + 1
            if isinstance(e, ValidationError):
                metadata['num_invalid_tool_calls'] = metadata.get('num_invalid_tool_calls', 0) + 1
                metadata['num_invalid_tool_calls_in_a_row'] = metadata.get('num_invalid_tool_calls_in_a_row', 0) + 1
                metadata['last_tool_call_valid'] = False
                if tool_name:
                    self.toolcall_metadata[tool_name] = metadata

                Agent.warn_static(f"Tool call {tool_name} failed with validation error: {e}\nTool History Metadata: {tool_name}={metadata}")

                if self.retries_on_tool_validation_error > 0:
                    if metadata.get('num_invalid_tool_calls_in_a_row', 0) > self.retries_on_tool_validation_error:
                        self.toolcall_metadata['__ended_due_to_too_many_invalid_tool_calls'] = metadata.copy()

                        if self.raise_on_too_many_invalid_tool_calls:
                            Agent.warn_static(f"Tool call {tool_name} failed with validation error too many times without any success.")
                            raise e

                        Agent.warn_static(f"Tool call {tool_name} failed with validation error too many times without any success. Ending tool call chain.")
                        self.max_iterations = 0
                    else:
                        Agent.warn_static(f"Giving agent feedback on validation error, attempt {metadata.get('num_invalid_tool_calls_in_a_row', 0)} / {self.retries_on_tool_validation_error}")
            else:
                metadata['num_invalid_tool_calls_in_a_row'] = 0
                metadata['last_tool_call_valid'] = True

            if tool_name:
                self.toolcall_metadata[tool_name] = metadata

            import traceback
            calltrace = traceback.format_exc()
            RESPONSE_STR = f"<function_call_error>\n{str(e)}\n</function_call_error>\n"
            
            if run_manager:
                callbacks = run_manager.get_child()
                callback_manager = CallbackManager.configure(
                    inheritable_callbacks=callbacks,
                )
                run_man = callback_manager.on_tool_start(None, "")
                run_man.on_tool_end(
                    output=RESPONSE_STR,
                )

            # We are going to return the exception as a tool response
            return AgentStep(
                action=agent_action,
                observation=RESPONSE_STR,
            )


class SmartPromptCache(BaseObject):
    seen = dict()

    @classmethod
    def add_seen(cls, prompt_hash: str):
        cls.seen[prompt_hash] = True

    @classmethod
    def is_seen(cls, prompt_hash: str):
        return prompt_hash in cls.seen


class Agent(RunnableLocalObject[Input, Output]):
    __REPO__ = AgentRepository("agents")
    """ Controls what local repo the agents are saved/loaded from"""

    __LLM_MODEL__ = "gpt-4-turbo"
    __LLM_ARGS__ = {}
    __HAS_MEMORY__ = False
    __OUTPUT_PARSER__: Any = None

    __SYSTEM_PROMPT_TEMPLATE__: str = None
    __USER_PROMPT_TEMPLATE__: str = None
    __MAX_TOOL_ITERATIONS__: Optional[int] = 15

    __CONTINUE_ON_EXCEPTION__ = False

    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 2
    __INVALID_TOOL_CALL_STRATEGY__: dict = dict(name="end_turn")
    """
    Possible values:
    - {"name":"end_turn"}: Simply end the turn with the validation error message as the last message
    - {"name":"throw_exception"}: Throw an exception

    """

    __RAISE_ON_BUDGET_EXCEPTION__ = False
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = False

    __USE_PROMPT_CACHE_IF_POSSIBLE__ = False
    __SMART_PROMPT_CACHE__ = True

    __RAW_OUTPUT_FILTER__ = DisallowEmptyOutputFilter

    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__: dict = dict(name="remove_turns")
    """
    Possible values:
    - {"name":"remove_turns", ...}: Remove the oldest turn from the conversation history until the request succeeds
        * Param `number_to_remove`: how many turns to remove, default is '1'
        * Param `preserve_history`: if true, .chat_history will be preserved
        * Param `disable_cache_for_next_turn`: if true, the cache will be disabled for the next turn
    - {"name":"throw_exception"}: Throw an exception
    - {"name":"summarize", ...}: Summarize the conversation history and continue. Provide param `number_of_turns_to_summarize` to control how many turns to summarize, default is '50%'.
    """

    token_usage: Optional[Dict[str, TokenUsage]] = {}

    def __init__(self, **kw):
        LocalObject.__init__(self, **kw)
        self.llm = self.get_llm_by_name(
            self.__LLM_MODEL__,
            raise_on_budget_exception=self.__RAISE_ON_BUDGET_EXCEPTION__,
            raise_on_rate_limit_exception=self.__RAISE_ON_RATE_LIMIT_EXCEPTION__,
            **self.__LLM_ARGS__
        )
        self.agent = None
        self.last_agent_llm_model = None
        self.executor = None
        self.available_tools = None
        self.runnable_config = None

    ####### Overridable methods ########

    def get_llm_for_output_parser(
        self, llm, output_parser: Optional[BaseOutputParser] = None
    ):
        if type(llm) is str:
            llm = self.get_llm_by_name(
                llm,
                raise_on_budget_exception=self.__RAISE_ON_BUDGET_EXCEPTION__,
                raise_on_rate_limit_exception=self.__RAISE_ON_RATE_LIMIT_EXCEPTION__,
                **self.__LLM_ARGS__
            )

        if (
            hasattr(output_parser, "__SUPPORTS_STRUCTURED_OUTPUT__")
            and output_parser.__SUPPORTS_STRUCTURED_OUTPUT__
            and output_parser.should_use_structured_output()
        ):
            if (
                hasattr(llm, "__SUPPORTS_STRUCTURED_OUTPUT__")
                and llm.__SUPPORTS_STRUCTURED_OUTPUT__
            ):
                return llm.with_structured_output(
                    output_parser=output_parser,
                    include_raw=True,
                )
            else:
                self.warn(f"LLM does not support structured output: {type(llm)}")

        if hasattr(llm, "__SUPPORTS_CACHE__") and llm.__SUPPORTS_CACHE__:
            use_prompt_cache = False

            use_prompt_cache = self.__USE_PROMPT_CACHE_IF_POSSIBLE__
            if not use_prompt_cache and self.__SMART_PROMPT_CACHE__:
                pass  # TODO detect if we use the same exact prompt twice

            if use_prompt_cache:
                llm = llm.with_cache()

        return llm

    def get_current_llm(self, output_parser: Optional[BaseOutputParser] = None):
        return self.get_llm_for_output_parser(self.llm, output_parser=output_parser)

    def find_all_available_tools(self) -> List[BaseTool]:
        return []

    def invoke_agent(
        self, input=None, config=None, **kwargs: Any
    ) -> AgentResponse[Output]:
        return self.get_single_agent_response(input, config=config, **kwargs)

    def get_input_vars(self, *args, **kw) -> Dict[str, Any]:
        return {**kw}

    def get_env(self) -> Dict[str, Any]:
        return {}

    def get_raw_output_filter(self):
        return self.get_runnable(self.__RAW_OUTPUT_FILTER__)

    def is_plaintext_parser(self, parser=None) -> bool:
        parser = parser or self.get_output_parser()
        if not parser:
            return True
        if isinstance(parser, PlainTextOutputParser):
            return True
        if type(parser) is str and parser.lower() in [
            "str",
            "string",
            "text",
            "plaintext",
        ]:
            return True
        return False

    def get_output_parser(self):
        op = LLMFunction.get_output_parser(self.__OUTPUT_PARSER__)
        return self.get_runnable(op)

    ####### Callbacks ########

    def on_agent_action(self, handler, action: AgentAction, **kwargs: Any) -> Any:
        pass

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        pass

    def on_tool_start(
        self, handler, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> Any:
        pass

    def on_tool_end(self, handler, output: str, **kwargs: Any) -> Any:
        pass

    ####### Internal Methods ########

    @classmethod
    def get_runnable(cls, run):
        if not run:
            return None
        if isinstance(run, Runnable):
            return run
        if inspect.isclass(run):
            if issubclass(run, Runnable):
                return run()
            return run()
        return run

    def invoke(
        self, input: Input = None, config=None, **kwargs: Any
    ) -> AgentResponse[Output]:
        """
        Invoke the agent's action in a chain.
        This method wraps `invoke_agent` and adds callbacks and context management.
        Do not override this, instead override `Agent.invoke_agent`
        """

        config = config or self.runnable_config

        self.trigger_callback_event(
            "on_chain_start",
            dumpd(self),
            input,
            name=(config and config.get("run_name")) or self.get_name(),
            config=config,
        )

        res = self.invoke_agent(input, config=config, **kwargs)

        self.trigger_callback_event("on_chain_end", res)

        return res

    def get_langchain_agent(self, output_parser: Optional[BaseOutputParser] = None):
        llm = self.get_current_llm(output_parser=output_parser)
        if not isinstance(llm, str):
            if hasattr(llm, "model_name"):
                llm_name = llm.model_name
            else:
                llm_name = llm.model

        if not self.agent or not self.last_agent_llm_model == llm_name:
            self.agent = self.create_langchain_agent(output_parser=output_parser)
        return self.agent

    def get_langchain_tool_executor(
        self, output_parser: Optional[BaseOutputParser] = None,
        agent_callback_handler: AgentCallbackHandler = None
    ):
        # TODO do we need cache
        self.executor = self.create_langchain_tool_executor(output_parser=output_parser, agent_callback_handler=agent_callback_handler)
        return self.executor

    def create_llm_function(
        self,
        *prompt: list[tuple[str, str | PromptTemplate]],
        output: str = None,
        model: str = None,
        **llm_args,
    ):
        """
        Create a callable LLM function with the provided templates.
        When you call it, you provide keyword arguments that match the template variables.
        """

        args = dict(
            raise_on_budget_exception=self.__RAISE_ON_BUDGET_EXCEPTION__,
            raise_on_rate_limit_exception=self.__RAISE_ON_RATE_LIMIT_EXCEPTION__,
            **self.__LLM_ARGS__
        )
        args.update(**llm_args)
        return LLMFunction.create(
            *prompt,
            output=output,
            model=model or self.__LLM_MODEL__,
            function_owner=self,
            **args,
        )

    def load_system_prompt(self, template, role="system", **kwargs):
        return self.load_prompt(template=template, role=role, **kwargs)

    def load_user_prompt(self, template, role="user", **kwargs):
        return self.load_prompt(template=template, role=role, **kwargs)

    def get_system_prompt(self, default=None) -> ChatPromptTemplate:
        return self.load_prompt(
            template=self.__SYSTEM_PROMPT_TEMPLATE__, role="system", default=default
        )

    def get_user_prompt(self, default=None) -> ChatPromptTemplate:
        return self.load_prompt(
            template=self.__USER_PROMPT_TEMPLATE__, role="user", default=default
        )

    def get_super_env_with(self, *args, **kwargs):
        env = self.get_env()
        env.update(*args, **kwargs)
        return env

    def get_env_as_md(self, env):
        out = ""
        for k, v in env.items():
            out += f"\n# {k}\n{v}\n"
        return out

    def get_available_tools(self):
        return self.find_all_available_tools()

    def get_system_prompt_prefix(self):
        return None

    def create_langchain_tool_executor(
        self,
        output_parser: Optional[BaseOutputParser] = None,
        agent_callback_handler: AgentCallbackHandler = None
    ):
        agent = self.get_langchain_agent(output_parser=output_parser)

        av_tools = self.get_available_tools()
        av_tools = get_langchain_tools(av_tools)

        if 'o1-mini' in self.__LLM_MODEL__ and len(av_tools) > 0:
            self.warn("o1-mini does not support tool calls")


        should_raise = False
        if not self.__INVALID_TOOL_CALL_STRATEGY__:
            pass
        elif self.__INVALID_TOOL_CALL_STRATEGY__.get("name") == "throw_exception":
            should_raise = True

        self.executor = ExceptionHandlingAgentExecutor(
            agent=agent,
            tools=av_tools,
            verbose=True,
            stream_runnable=False,
            handle_parsing_errors=True,
            max_iterations=self.__MAX_TOOL_ITERATIONS__ or 15,
            retries_on_tool_validation_error=self.__RETRIES_ON_TOOL_VALIDATION_ERROR__,
            raise_on_too_many_invalid_tool_calls=should_raise,
            agent_callback_handler=agent_callback_handler
        )
        return self.executor

    def create_langchain_agent(self, output_parser: Optional[BaseOutputParser] = None):
        llm = self.get_current_llm(output_parser=output_parser)
        if not llm:
            raise ValueError("No LLM model set")

        av_tools = self.get_available_tools()
        av_tools = get_langchain_tools(av_tools)

        system_prompt = self.get_system_prompt()
        user_prompt = self.get_user_prompt()

        prompt = self._get_prompt_template_class().from_messages(
            x
            for x in [
                system_prompt,
                MessagesPlaceholder("chat_history", optional=True),
                user_prompt,
                MessagesPlaceholder("agent_scratchpad"),
            ]
            if x
        )

        if hasattr(llm, "__SUPPORTS_TOOL_CALLS__"):
            if llm.__SUPPORTS_TOOL_CALLS__:
                return llm.create_tools_agent(av_tools, prompt)

        if isinstance(llm, ChatOpenAI) or isinstance(llm, ChatApiOpenAi):
            return create_openai_tools_agent(llm, av_tools, prompt)

        if isinstance(llm, ChatAnthropic) or isinstance(llm, ChatApiAnthropic):
            return create_anthropic_tools_agent(llm, av_tools, prompt)

        self.warn(
            f"LLM does not support tool calls: {type(llm)}, will fallback to JSONChatAgent"
        )
        prompt.partial_variables["output_format"] = """
When responding to me, please output a response in one of two formats:

**Option 1:**
Use this if you want the human to use a tool.
Markdown code snippet formatted in the following schema:

```json
{{
    "action": string, \\ The action to take. Must be one of the provided tool names
    "action_input": string \\ The input to the action
}}
```

**Option #2:**
Use this if you want to respond directly to the human. Markdown code snippet formatted in the following schema:

```json
{{
    "action": "Final Answer",
    "action_input": string \\ You should put what you want to return to use here
}}
```
"""
        return create_json_chat_agent(llm, av_tools, prompt)

    def _get_prompt_template_class(self):
        return ModelRegistry.get_prompt_template_class()

    def get_simple_response_executor(
        self, output_parser: Optional[BaseOutputParser] = None
    ) -> LLMChain:
        llm = self.get_current_llm(output_parser=output_parser)
        if not llm:
            raise ValueError("No LLM model set")

        system_prompt = self.get_system_prompt()
        user_prompt = self.get_user_prompt()

        prompt = self._get_prompt_template_class().from_messages(
            x
            for x in [
                system_prompt,
                MessagesPlaceholder("chat_history", optional=True),
                user_prompt,
            ]
            if x
        )
        return prompt | llm

    def get_format_instruction(self, output_parser):
        if not hasattr(output_parser, "get_format_instructions"):
            return "Use your best judgement"
        return output_parser.get_format_instructions()

    def get_single_agent_response(
        self,
        input=None,
        config=None,
        output_parser: Optional[BaseOutputParser] = None,
        **kwargs: Any,
    ) -> AgentResponse[Output]:
        if input is None:
            input = {}

        if type(input) is dict:
            env = self.get_env()
            input["env"] = env
            input["env_md"] = self.get_env_as_md(env)

        input_vars = self.get_input_vars()
        if input_vars:
            # input_vars is less important than direct input
            input_vars = dict(**input_vars)
            input_vars.update(input)
            input = input_vars

        prompt_prefix = self.get_system_prompt_prefix()
        input["system_prompt_prefix"] = prompt_prefix

        av_tools = self.get_available_tools()

        if not output_parser:
            output_parser = self.get_output_parser()
        if not output_parser:
            output_parser = PlainTextOutputParser()

        agent_callback_handler = AgentCallbackHandler(self)
        config = kwargs.get("config", self.runnable_config) or {}
        config = config.copy()

        if not av_tools or len(av_tools) == 0:
            chain = self.get_simple_response_executor(output_parser=output_parser)
        else:
            chain = self.get_langchain_tool_executor(output_parser=output_parser, agent_callback_handler=agent_callback_handler)

        filter = self.get_raw_output_filter()
        if filter:
            chain = chain | filter

        # Instructions on the output format
        output_inst = None

        if output_parser:
            # if hasattr(output_parser, 'get_format_instructions'):
            # prompt.partial_variables['output_format'] = output_parser.get_format_instructions()
            chain = chain | output_parser

            if hasattr(output_parser, "get_format_instructions"):
                output_inst = self.get_format_instruction(output_parser)
        else:
            output_inst = "Use your best judgement"

        if output_inst:
            input["format_instructions"] = output_inst
            input["output_format"] = output_inst


        config_callbacks = config.get("callbacks", [])
        config_callbacks = config_callbacks.copy()
        config_callbacks.append(agent_callback_handler)
        config["callbacks"] = config_callbacks

        kwargs["config"] = config

        tag_id = str(uuid4())

        # If we raised an exception, we need to fix the record logs
        if config and config.get("callbacks"):
            for cb in config["callbacks"]:
                if not isinstance(cb, LangChainLogger):
                    continue
                cb.tag_for_exception(tag_id)

        def pop_tag(config, tag_id):
            if not config:
                return
            if not config.get("callbacks"):
                return
            for cb in config["callbacks"]:
                if not isinstance(cb, LangChainLogger):
                    continue
                cb.reset_to_tag(tag_id)

        try:
            global_event_dumper.check_if_over_budget()
        except Exception as e:
            import traceback

            traceback.print_exc()
            self.warn(f"Failed to check budget, please tell amy: {str(e)}")

        def flush_event_dumper():
            try:
                global_event_dumper.record_llm_event(agent_callback_handler.event)
                agent_callback_handler.reset_event()
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.warn(f"Failed to record event! Please tell amy: {str(e)}")

        num_tries = 0
        while True:
            num_tries += 1
            # Reset the the callback handler so that we have a fresh state on retry
            agent_callback_handler.reset()

            try:

                output = chain.invoke(input, **kwargs)
            except (
                ContextWindowExceededError,
                LLMApiContextWindowExceededError
            ) as e:
                flush_event_dumper()

                # TODO XXX implement the context window exceeded strategy
                cws = self.__CONTEXT_WINDOW_EXCEEDED_STRATEGY__ or {}
                self.info("Context window exceeded, going to attempt strategy: %s", cws)
                if cws.get("name") == "remove_turns":
                    self.warn(
                        "Context window exceeded, removing oldest turns and trying again..."
                    )
                    if not isinstance(input, dict):
                        self.warn(
                            "Context window exceeded strategy 'remove_turns' requires a dictionary input"
                        )
                        raise e
                    chat_history = input.get("chat_history", [])
                    if not chat_history or len(chat_history) == 0:
                        self.warn("No more context history to prune!")
                        raise e

                    number_to_remove = cws.get("number_to_remove", 1)
                    number_of_turns = len([m for m in chat_history if m.type == "human"])
                    if isinstance(number_to_remove, str) and number_to_remove.endswith("%"):
                        percentage_to_remove = int(number_to_remove[:-1])
                        number_to_remove = int(number_of_turns * (percentage_to_remove / 100))
                        number_to_remove = max(1, number_to_remove)
                        number_to_remove = min(number_to_remove, number_of_turns)
                    elif not isinstance(number_to_remove, int):
                        self.warn("Context window exceeded strategy 'remove_turns.number_to_remove' requires a number or percentage. Using default value of 1")
                        number_to_remove = 1
                    self.info(f"Removing {number_to_remove} (out of {number_of_turns}) turns from chat history")

                    # Remove the oldest turns (first items) from the chat history
                    for i in range(number_to_remove):
                        num_removed = 0
                        while len(chat_history) > 0:
                            val = chat_history[0]
                            if val.type == "human" and num_removed > 0:
                                break
                            chat_history.pop(0)
                            num_removed += 1

                    if cws.get("disable_cache_for_next_turn", False):
                        for msg in chat_history:
                            if hasattr(msg, "additional_kwargs"):
                                if not msg.additional_kwargs:
                                    msg.additional_kwargs = {}
                                msg.additional_kwargs['disable_cache_one_time'] = True

                    input["chat_history"] = chat_history
                    if not cws.get("preserve_history") and hasattr(self, "chat_history"):
                        self.chat_history = chat_history
                        
                    time.sleep(1)
                    continue

                elif cws.get("name") == "summarize":
                    raise NotImplementedError(
                        "Summarizing chat history is not implemented yet"
                    )
                elif cws.get("name") == "throw_exception":
                    raise e
                else:
                    self.warn(
                        f"Unknown context window exceeded strategy: {cws.get('name')}"
                    )

                raise e

            except ToolSignal as e:
                pop_tag(config, tag_id)
                flush_event_dumper()
                return AgentResponse(
                    error="Interrupted by ToolSignal",
                    error_raw=ToolSignal,
                    chat_messages=agent_callback_handler.conversation or [],
                    signals=[e.__class__.__name__],
                )
            except LLMApiBudgetExceededError as e:
                flush_event_dumper()
                raise e
            except ValidationError as e:
                # Right now we just always raise on validation error
                # As it is handled by the ExceptionHandlingAgentExecutor
                flush_event_dumper()
                raise e
                if num_tries > self.__RETRIES_ON_TOOL_VALIDATION_ERROR__:
                    raise e
                import traceback

                traceback.print_exc()
                self.warn(
                    f"Tool validation error, retrying {num_tries}/{self.__RETRIES_ON_TOOL_VALIDATION_ERROR__}"
                )
                continue
            except Exception as e:
                import traceback

                if not isinstance(e, ContinueConversationException):
                    traceback.print_exc()

                pop_tag(config, tag_id)
                self.add_annotation(
                    name="agent_exception",
                    text=f"Error: {str(e)}",
                    severity="exception",
                )
                flush_event_dumper()

                self.trigger_callback_event("on_agent_error", e)

                if not self.__CONTINUE_ON_EXCEPTION__ and not isinstance(
                    e, ContinueConversationException
                ):
                    raise e
                return AgentResponse(
                    error=str(e),
                    error_raw=e,
                    chat_messages=agent_callback_handler.conversation or [],
                    signals=[],
                )
            break

        flush_event_dumper()

        resp  = AgentResponse(
            value=output if output_parser else output["content"],
            chat_messages=agent_callback_handler.conversation,
        )

        self.warn(f"================= {agent_callback_handler.toolcall_metadata}")

        # Check if we had a too many tool validation errors
        tcm = agent_callback_handler.toolcall_metadata or {}
        ended_due_to_tmitc = tcm.get('__ended_due_to_too_many_invalid_tool_calls')
        tcm = tcm.copy()
        tcm.pop('__ended_due_to_too_many_invalid_tool_calls', None)
        if ended_due_to_tmitc:
            self.on_too_many_tool_validation_errors(
                resp,
                ended_due_to_tmitc.get('tool_name'),
                ended_due_to_tmitc,
                tcm
            )

        pop_tag(config, tag_id)

        return resp

    def on_too_many_tool_validation_errors(self, resp: AgentResponse, name: str, tool_metadata: Dict, all_tool_metadata: Dict):
        self.warn(f"Tool call {name} had many validation errors and ended tool chain early ({tool_metadata.get('num_invalid_tool_calls')} failed validation attempts)")
        pass

    def use_web_logging_config(self, clear=False):
        if clear:
            self.clear_web_logging_session()

        from ..web_console import WebConsoleLogger

        config = {"callbacks": [WebConsoleLogger()]}
        self.runnable_config = config

        if clear:
            self.clear_web_logging_session()

        return config

    def clear_web_logging_session(self):
        from ..web_console import RecordSession

        ses = RecordSession.get("main")
        if ses:
            ses.delete_file()

    def add_annotation(self, *args, **kwargs):
        return self.trigger_callback_event("on_agent_annotation", *args, **kwargs)


class ChildAgent(Agent[Input, Output]):
    parent_id: Optional[str] = Agent.Weak("parent")

    def __init__(self, parent: Agent = None, **kw):
        super().__init__(**kw)
        if parent:
            self.runnable_config = parent.runnable_config
            self.parent = parent
            self._parent = parent  # Cached reference to prevent lookups

    def get_parent(self):
        return self.parent


class AgentWithHistory(Agent[Input, Output]):
    chat_history: list[BaseMessage] = []

    __USE_PROMPT_CACHE_IF_POSSIBLE__ = True

    def __init__(self, *args, **kw):
        if not kw.get("chat_history"):
            kw["chat_history"] = []
        super().__init__(*args, **kw)

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(chat_history=self.chat_history)
        return vars

    def invoke_agent(self, input: Input, **kw: Any) -> AgentResponse[Output]:
        res = super().invoke_agent(input, **kw)
        self.chat_history.extend(res.chat_messages)
        return res
