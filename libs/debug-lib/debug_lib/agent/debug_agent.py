import logging
import pprint

from typing import Dict, Any

from pathlib import Path

from agentlib import AgentWithHistory
from langchain_core.agents import AgentAction, AgentFinish

from rich.logging import RichHandler
from rich.console import Console

from debug_lib.agent.engine import debug_helper, tool_calls

CUR_DIR = Path(__file__).absolute().parent

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=Console(width=200), rich_tracebacks=True)],
)

log = logging.getLogger("dyva-agent")


class DebugAgent(AgentWithHistory):
    __LLM_MODEL__ = "gpt-4.1-mini"
 
    __SYSTEM_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "debug_plan.system.j2").read_text()
    __USER_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "debug_plan.user.j2").read_text()

    def get_available_tools(self):
        return tool_calls.AVAILABLE_TOOLS

    def on_agent_action(self, handler, action: AgentAction, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
        log.info("Current Cost: $%.2f", total_cost)

        return super().on_agent_action(handler, action, **kwargs)

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))

        log.info("Total Cost: $%.2f", total_cost)
        return super().on_agent_finish(handler, finish, **kwargs)