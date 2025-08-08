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
    format = "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d | %(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=Console(width=200), rich_tracebacks=True)],
)

log = logging.getLogger("dyva-agent")


class DyvaAgent(AgentWithHistory):
    # __LLM_MODEL__ = "gemini-2.5-pro"
    # __LLM_MODEL__ = "gpt-4.1-mini"
    # __LLM_MODEL__ = "gpt-4.1"
    # __LLM_MODEL__ = "claude-3.7-sonnet"
    # __LLM_ARGS__ = dict(
    #     max_tokens=64_000, # Need to set max tokens or defaults to 1024
    #     temperature=1,
    #     thinking={
    #         "type": "enabled",
    #         "budget_tokens": 48_000 # Eats out of the max token
    #     }
    # )
 
    __SYSTEM_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "root_cause.system.j2").read_text()
    __USER_PROMPT_TEMPLATE__ = (Path(__file__).parent / "prompts" / "root_cause.user.j2").read_text()

    def __init__(self, model: str = "gpt-4.1-mini",max_iterations: int = 15, *args, **kwargs):
        DyvaAgent.__LLM_MODEL__ = model
        super().__init__(*args, **kwargs)
        self.tools_used = set()
        self.tool_history = []
        self.max_iterations = max_iterations
        self.iterations_left = max_iterations
        self.example_root_cause = (Path(__file__).parent / "prompts" / "example_root_cause.yaml").read_text()

    def get_input_vars(self):
        vars = super().get_input_vars()
        force = False
        if len(self.chat_history) > 0:
            if "```yaml" in self.chat_history[-1].content:
                force = True
        constant_vars = {
            "crash_report": pprint.pformat(debug_helper.DYVA_STATE.crash_report, indent=2),
            "example_root_cause": self.example_root_cause,
            "max_iterations": self.max_iterations,
            "iterations_left": self.iterations_left,
            "retry": vars.get("retry", None),
            "tools_used": len(self.tools_used),
            "force": force,
        }
        vars.update(constant_vars)
        self.iterations_left -= 1
        return vars

    def get_available_tools(self):
        return tool_calls.AVAILABLE_TOOLS

    def on_agent_action(self, handler, action: AgentAction, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
        log.info("Current Cost: $%.2f", total_cost)
        log.info("Iterations %s of %s left", self.iterations_left, self.max_iterations)

        if self.iterations_left == 0:
            log.error("Max iterations reached")
            raise Exception("Max iterations reached")
        self.iterations_left -= 1
        return super().on_agent_action(handler, action, **kwargs)

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))

        log.info("Total Cost: $%.2f", total_cost)
        return super().on_agent_finish(handler, finish, **kwargs)

    def on_tool_start(self, handler, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> Any:
        tool_use = (serialized["name"], input_str)
        if tool_use in self.tools_used:
            return

        log.info("Tool use: %s - %s", tool_use[0], tool_use[1])
        if tool_use[0] == "propose_root_cause":
            # Just in case the LLM produces invalid yaml
            self.iterations_left += 1
        self.tools_used.add(tool_use)
        self.tool_history.append(tool_use)
        # TODO: REJECT if the tool has already been used with the same arguments
        # TODO: REJECT if finish_task is called without proposing a root cause
