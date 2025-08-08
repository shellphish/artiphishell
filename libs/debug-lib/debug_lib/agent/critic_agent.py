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


class CriticAgent(AgentWithHistory):
    __LLM_MODEL__ = "claude-3.7-sonnet"
    __LLM_ARGS__ = dict(
        max_tokens=64_000, # Need to set max tokens or defaults to 1024
        temperature=1,
        thinking={
            "type": "enabled",
            "budget_tokens": 48_000 # Eats out of the max token
        }
    )
  
    __SYSTEM_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "debug_critic.system.j2").read_text()
    __USER_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "debug_critic.user.j2").read_text()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.example_root_cause = (Path(__file__).parent / "prompts" / "example_root_cause.yaml").read_text()

    def get_available_tools(self):
        return tool_calls.AVAILABLE_TOOLS

    def get_input_vars(self):
        vars = super().get_input_vars()
        constant_vars = {
            "crash_report": pprint.pformat(debug_helper.DYVA_STATE.crash_report, indent=2),
            "example_root_cause": self.example_root_cause,
        }
        vars.update(constant_vars)
        return vars
 
    def on_agent_action(self, handler, action: AgentAction, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
        log.info("Current Cost: $%.2f", total_cost)

        return super().on_agent_action(handler, action, **kwargs)

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))

        log.info("Total Cost: $%.2f", total_cost)
        return super().on_agent_finish(handler, finish, **kwargs)