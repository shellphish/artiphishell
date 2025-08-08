import json
from typing import Sequence, Union, List, Tuple

from langchain_core.language_models import BaseLanguageModel
from langchain_core.prompts.chat import ChatPromptTemplate
from langchain_core.runnables import Runnable, RunnablePassthrough
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import BaseMessage, AIMessage, ToolMessage, ToolCall
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.outputs import ChatGeneration, Generation
from langchain.agents.agent import MultiActionAgentOutputParser
from langchain.agents.output_parsers.tools import ToolAgentAction

from ..llm_api import ChatApiGoogle

def get_text_content(message):
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        return "\n".join(
            m for m in map(
                get_text_content,
                message
            ) if m
        )
    if isinstance(message, dict):
        if message.get('type', 'text') != 'text':
            return None
        if not message.get('text'):
            return None
        return message['text']
    return None

def _extract_tool_calls_from_message(message: AIMessage) -> List[ToolCall]:
    """Extract tool calls from a list of content blocks."""
    if message.tool_calls:
        return message.tool_calls
    # lite TODO
    raise ValueError(f"No tool calls found in message: {message}")

class GoogleToolsAgentOutputParser(MultiActionAgentOutputParser):
    @property
    def _type(self) -> str:
        return "google-tools-agent-output-parser"
    
    def parse_result(
        self, result: List[Generation], *, partial: bool = False
    ) -> Union[List[AgentAction], AgentFinish]:
        print(f"parse_result {result} {partial}")
        # TODO get all non tool message content
        if not isinstance(result[0], ChatGeneration):
            raise ValueError("This output parser only works on ChatGeneration output")
        gen_msg = result[0].message

        # TODO implement this missing function
        target_tools = gen_msg.tool_calls

        content_msg = gen_msg.content or 'No Response'

        if len(target_tools) == 0:
            return AgentFinish(
                return_values={"output": content_msg or 'No Response'},
                log=str(content_msg)
            )
        

        actions = []
        for tool_call in target_tools:
            func_name = tool_call['name']
            tool_input = tool_call['args']
            log = f"\nInvoking: `{func_name}` with `{tool_input}`\n{content_msg}\n"
            actions.append(
                ToolAgentAction(
                    tool = func_name,
                    tool_input = tool_input,
                    log = log,
                    message_log = [gen_msg],
                    tool_call_id = tool_call["id"]
                )
            )
        return actions


    def parse(self, text: str) -> Union[List[AgentAction], AgentFinish]:
        raise ValueError("Can only parse messages")
    
def _create_tool_message(
    agent_action: ToolAgentAction, observation: str
) -> ToolMessage:
    """Convert agent action and observation into a function message.
    Args:
        agent_action: the tool invocation request from the agent
        observation: the result of the tool invocation
    Returns:
        FunctionMessage that corresponds to the original tool invocation
    """
    if not isinstance(observation, str):
        try:
            content = json.dumps(observation, ensure_ascii=False)
        except Exception:
            content = str(observation)
    else:
        content = observation
    return ToolMessage(
        tool_call_id=agent_action.tool_call_id,
        content=content,
        additional_kwargs={"name": agent_action.tool},
    )

def format_to_google_tool_messages(
    intermediate_steps: Sequence[Tuple[AgentAction, str]],
) -> List[BaseMessage]:
    messages = []
    for agent_action, observation in intermediate_steps:
        if isinstance(agent_action, ToolAgentAction):
            new_messages = list(agent_action.message_log) + [
                _create_tool_message(agent_action, observation)
            ]
            messages.extend([new for new in new_messages if new not in messages])
        else:
            messages.append(AIMessage(content=agent_action.log))
    return messages


def create_google_tools_agent(
    llm: BaseLanguageModel, tools: Sequence[BaseTool], prompt: ChatPromptTemplate
) -> Runnable:
    """Create an agent that uses Google tools.

    Args:
        llm: LLM to use as the agent.
        tools: Tools this agent has access to.
        prompt: The prompt to use. See Prompt section below for more on the expected
            input variables.
    
    Returns:
        A Runnable sequence representing an agent. It takes as input all the same input
        variables as the prompt passed in does. It returns as output either an
        AgentAction or AgentFinish.
    """

    missing_vars = {"agent_scratchpad"}.difference(
        prompt.input_variables + list(prompt.partial_variables)
    )
    if missing_vars:
        raise ValueError(f"Prompt missing required variables: {missing_vars}")
    
    assert(isinstance(llm, ChatGoogleGenerativeAI) or isinstance(llm, ChatApiGoogle))
    
    llm_with_tools = llm.bind_tools(tools)

    agent = (
        RunnablePassthrough.assign(
            agent_scratchpad=lambda x: format_to_google_tool_messages(
                x["intermediate_steps"]
            )
        )
        | prompt
        | llm_with_tools
        | GoogleToolsAgentOutputParser()
    )
    return agent
