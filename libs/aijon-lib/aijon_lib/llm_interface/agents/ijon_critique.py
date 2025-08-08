import logging

from typing import Any

from pathlib import Path

from agentlib import Agent, set_global_budget_limit
from langchain_core.agents import AgentFinish

CUR_DIR = Path(__file__).absolute().parent
PROMPT_DIR = CUR_DIR.parent / "prompts"

log = logging.getLogger("aijon")


class AIJONCritiqueAgent(Agent[str, str]):
    """
    AIJON Critique Agent for IJON code instrumentation.
    This agent is designed to return search and replace blocks with the replacements
    containing the IJON instrumentation and its replacement.
    """

    __LLM_MODEL__ = "gpt-o3"
    # __LLM_MODEL__ = "claude-3-5-sonnet"
    # __LLM_MODEL__ = "claude-4-sonnet"
    __SYSTEM_PROMPT_TEMPLATE__ = (PROMPT_DIR / "aijon-critique.system.j2").read_text()
    __USER_PROMPT_TEMPLATE__ = (PROMPT_DIR / "aijon-critique.user.j2").read_text()
    llm_budget = 5.0

    def __init__(self, *args, language: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tools_used = set()
        self.insert_output_format = (PROMPT_DIR / "artifacts" / "insert_output_format.txt").read_text()
        if language is None or language.lower() in ["c", "cpp", "c++"]:
            self.ijon_cheatsheet = (PROMPT_DIR / "artifacts" / "ijon_cheatsheet.txt").read_text()
        elif language.lower() in ["java", "jvm"]:
            self.ijon_cheatsheet = (PROMPT_DIR / "artifacts" / "ijon_cheatsheet_java.txt").read_text()
        else:
            raise ValueError(f"Unsupported language: {language}")

        set_global_budget_limit(
            price_in_dollars=self.llm_budget,
            exit_on_over_budget=True,
        )

    def get_input_vars(self):
        vars = super().get_input_vars()
        constant_vars = {
            "ijon_cheatsheet": self.ijon_cheatsheet,
            "insert_output_format": self.insert_output_format,
        }
        vars.update(constant_vars)
        return vars

    def on_agent_finish(self, handler, finish: AgentFinish, **kwargs: Any) -> Any:
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))

        log.info("Total Cost: $%.2f", total_cost)
        return super().on_agent_finish(handler, finish, **kwargs)
