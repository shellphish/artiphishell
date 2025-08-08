import logging

from typing import Any

from pathlib import Path

from agentlib import AgentWithHistory, set_global_budget_limit
from langchain_core.agents import AgentAction, AgentFinish

CUR_DIR = Path(__file__).absolute().parent
PROMPT_DIR = CUR_DIR.parent / "prompts"

log = logging.getLogger("aijon")


class AIJONJavaInstrumentorAgent(AgentWithHistory[str, str]):
    """
    AIJON Instrumentor Agent for code instrumentation.
    This agent is designed to return search and replace blocks with the replacements
    containing the original code with IJON instrumentation.
    """

    # __LLM_MODEL__ = "gpt-4.1"
    # __LLM_MODEL__ = "claude-3-5-sonnet"
    __LLM_MODEL__ = "claude-4-sonnet"
    __SYSTEM_PROMPT_TEMPLATE__ = (PROMPT_DIR / "aijon_java.system.j2").read_text()
    __USER_PROMPT_TEMPLATE__ = (PROMPT_DIR / "aijon_java.user.j2").read_text()
    llm_budget = 20.0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tools_used = set()
        self.ijon_example = (PROMPT_DIR / "artifacts" / "ijon_example.java").read_text()
        self.insert_output_format = (PROMPT_DIR / "artifacts" / "insert_output_format.txt").read_text()
        self.ijon_cheatsheet = (PROMPT_DIR / "artifacts" / "ijon_cheatsheet_java.txt").read_text()

        set_global_budget_limit(
            price_in_dollars=self.llm_budget,
            exit_on_over_budget=True,
        )

    def get_input_vars(self):
        vars = super().get_input_vars()
        constant_vars = {
            "ijon_example": self.ijon_example,
            "insert_output_format": self.insert_output_format,
            "ijon_cheatsheet": self.ijon_cheatsheet,
        }
        vars.update(constant_vars)
        return vars

    # def get_available_tools(self):
    #     return tool_calls.AVAILABLE_TOOLS

    def on_agent_action(self, handler, action: AgentAction, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
        log.info("Current Cost: $%.2f", total_cost)

        if self.iterations_left == 0:
            log.error("Max iterations reached")
            raise Exception("Max iterations reached")
        self.iterations_left -= 1
        return super().on_agent_action(handler, action, **kwargs)

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))

        log.info("Total Cost: $%.2f", total_cost)
        return super().on_agent_finish(handler, finish, **kwargs)
