import os
import json
import subprocess
from typing import Dict


from langchain_core.output_parsers import JsonOutputParser
from langchain.tools import BaseTool, StructuredTool, tool

from .agents.planning import AgentPlanStep, Planner, CriticalPlanExecutor, AgentPlanStepAttempt
from .skill import SkillBuilderCurriculum, SkillBuilder, SkillPlanner
from .skill import Skills_Neo4J
from .tools import run_shell_command, give_up_on_task
from .common.base import LangChainLogger
from .common.code import CodeExecutionEnvironment, Code
from .common.object import LocalObject

# Some agent that explores the codebase and generates facts about the codebase
# Some agent which identifies which vulnerability agents to engage
# Vulnerability agents identify specific files to review
# Then preform directed code review of the files

class WebGuy(CriticalPlanExecutor[str, str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'web_guy/run_step.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'web_guy/run_step.user.j2'
    """
    Web Guy answers questions about configuring web applications
    It plans how to answer the question 
    """

    def get_available_tools(self):
        return [
            run_shell_command,
            give_up_on_task
            # PythonScriptTool
            # ScriptBuilderTool
            # ScriptRunnerTool
            # FuzzyFinderTool
            # FileContentSearchTool
            # Launch Subtask
        ]
        # find . | query "config files"

    def get_step_input_vars(self, step: AgentPlanStep) -> Dict:
        return super().get_step_input_vars(step)

    @staticmethod
    def test(args=None):
        wg = None
        if os.path.exists('/tmp/wg.json'):  
            wg = WebGuy.from_file('/tmp/wg.json')
            wg = WebGuy.get_by_id(wg.id)
        if wg is None:
            wg = WebGuy()
        wg.save_to_path('/tmp/wg.json', force_json=True)

        from web_console import app, WebConsoleLogger
        config = {
            'callbacks' : [WebConsoleLogger()]
        }
        wg.runnable_config = config

        res = wg.invoke('Determine the primary language of the provided application as well as determine the primary http routing framework used. Output the final results ordered by their likelihood of being correct.')
        print(res)