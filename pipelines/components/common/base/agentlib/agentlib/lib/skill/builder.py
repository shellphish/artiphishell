import os
import json
import subprocess
from typing import Union, Optional, Any, Dict, List, Generic

from langchain_core.runnables.utils import Input, Output

from .skill import Skill, SkillRepository
from ..agents.critic import CriticReview
from ..agents.curriculum import Curriculum
from ..common.object import SaveLoadObject
from ..common.code import CodeExecutionEnvironment, CodeExecutionResult
from ..common.parsers import PythonCodeExtractor, GeneratedCode, Code
from ..agents.planning import (
    AgentPlan, Planner, CriticalPlanExecutor,
    AgentPlanStep, AgentPlanStepAttempt,
    AgentResponse, PlanStepResultCritic
)

class SkillPlanStep(AgentPlanStep):
    last_generated_code: Optional[GeneratedCode]

class SkillPlanner(Planner[Input]):
    __PLAN_STEP_CLASS__: SkillPlanStep

class SkillBuilderCritic(PlanStepResultCritic[CodeExecutionResult]):
    def review_result(
        self,
        result: CodeExecutionResult,
        **kw
    ) -> CriticReview:
        return super().review_result(result, **kw)

class SkillBuilderCurriculum(Curriculum[Input, Output]):
    """
    A curriculum agent which includes examples of related skill programs.
    ## Input Template Variables:
      - `example_programs`: `List[Skill]`: list of example programs
      - `example_programs_md` : `str` : Markdown string version
    """
    def invoke_agent(self, question: Input, **kwargs: Any) -> Output:
        if type(question) is str:
            question = dict(question=question)

        assert(isinstance(self.parent, SkillBuilder))
        related_skills = self.parent.get_related_skills()
        related_skills_md = self.parent.get_related_skills_as_md(related_skills)

        question['example_programs'] = related_skills
        question['example_programs_md'] = related_skills_md
        return super().invoke_agent(question, **kwargs)

class SkillBuilder(CriticalPlanExecutor[Input, str]):
    __PLANNER_CLASS__: SkillPlanner = SkillPlanner
    __CRITIC_CLASS__: SkillBuilderCritic = SkillBuilderCritic

    __SKILL_REPOSITORY__: SkillRepository = None
    __CURRICULUM_CLASS__: "SkillBuilderCurriculum" = None
    __CODE_EXTRACTOR__: PythonCodeExtractor = PythonCodeExtractor
    __CODE_EXECUTION_ENVIRONMENT__: CodeExecutionEnvironment = CodeExecutionEnvironment

    __FUNCTION_PROTOTYPE_PROMPT__: str = 'skill/function_prototype.j2'
    __RUN_TASK_STUB_PROMPT__: str = 'skill/function_call_for_task.j2'

    __WAIT_FOR_USER_INPUT__ = False

    __BASE_SKILLS__ = []

    """Code from the last completed step"""
    code_checkpoint: Optional[Code] = None
    """Current draft of the code for this step"""
    current_code: Optional[GeneratedCode] = None
    """The code that runs the function call for the task"""
    run_task_code: Optional[GeneratedCode] = None

    test_input_data: Optional[str] = None

    def ask_curriculum(self, question: str):
        if not self.__CURRICULUM_CLASS__:
            raise ValueError('No curriculum class set')
        
        curriculum: "SkillBuilderCurriculum" = self.__CURRICULUM_CLASS__(parent = self)
        curriculum.runnable_config = self.runnable_config
        return curriculum.invoke(dict(
            question=question
        ))

    def generate_run_task_stub(self, code: Code) -> Code:
        self.add_annotation(
            name='generate_run_task_stub',
            text='Generating task stub to call function',
            severity='task'
        )
        f = self.create_llm_function(
            self.__RUN_TASK_STUB_PROMPT__ or
                'skill/function_call_for_task.j2',
            '''
# Target Function Signature
```
{{signature}}
```
# Task Description
This is the goal which the provided function will accomplish:
```
{{goal}}
```
# Test Input Data
Here is some test data which you should put into this stub to test the function:
```
{{test_input_data}}
```
''',
            output = self.__CODE_EXTRACTOR__()
        )
        res = f(
            goal = self.goal,
            signature = code.get_main_function()['prototype'],
            test_input_data = self.test_input_data
        )
        return res


    def generate_function_prototype(self) -> GeneratedCode:
        self.add_annotation(
            name='generate_function_prototype',
            text='Generating skill function prototype for goal',
            severity='task'
        )
        f = self.create_llm_function(
            self.__FUNCTION_PROTOTYPE_PROMPT__ or 
                'skill/function_prototype.j2',
            '# Function Description\n```\n{{goal}}\n```\n',
            output = self.__CODE_EXTRACTOR__()
        )
        res = f(
            example_programs = self.get_related_skills(),
            goal = self.goal
        )
        return res

    def sanitize_for_comment(self, code: str):
        code = ''.join(
            c for c in code
            if c.isalnum() or c in ' !@#$%^&*()_-+=[]{}|;:,.<>?/\'"'
        )
        return code

    def reset_current_step(self, step: AgentPlanStep):
        super().reset_current_step(step)
        if self.code_checkpoint:
            self.current_code = self.code_checkpoint.copy()
            b = self.current_code.get_main_function()['body']
            # This part is whitespace sensitive
            b += f'''
    # STEP: {self.sanitize_for_comment(step.description)}
    # TODO Fill in this step of the function
   '''
            self.current_code.get_main_function()['body'] = b
        else:
            self.current_code = None

    def on_step_success(self, step: AgentPlanStep, res: Any):
        self.code_checkpoint = self.current_code.copy()
        super().on_step_success(step, res)
        self.save()

    def execute_current_code(self) -> CodeExecutionResult:
        self.add_annotation(
            name='execute_current_code',
            text='Executing current code',
            severity='code_exec',
        )
        env = self.__CODE_EXECUTION_ENVIRONMENT__()
        if self.run_task_code:
            self.current_code.exec_prefix = self.run_task_code.get_source()
        res = self.current_code.execute_code(
            code_exec_environment=env
        )
        if res.exception:
            self.add_annotation(
                name='execution_exception',
                text=f'Exception: {res.exception}',
                severity='exception'
            )
        else:
            self.add_annotation(
                name='execution_success',
                text=f'Code executed without exception',
                severity='success'
            )
        return res

    def execute_step_attempt(
        self,
        step: AgentPlanStep,
        attempt: AgentPlanStepAttempt,
        **kw
    ) -> AgentResponse[CodeExecutionResult]:
        # First we need to generate a function prototype to hold the code
        if not self.current_code:
            if self.code_checkpoint:
                self.current_code = self.code_checkpoint
            else:
                self.current_code = self.generate_function_prototype()
                self.code_checkpoint = self.current_code
            self.save()
            if self.__WAIT_FOR_USER_INPUT__:
                input('Finished generating function prototype, press enter to continue...')

        if not self.run_task_code:
            self.run_task_code = self.generate_run_task_stub(self.current_code)
            self.save()
            if self.__WAIT_FOR_USER_INPUT__:
                input('Finished generating run task stub, press enter to continue...')

        # Then we answer some questions about the task for context
        if self.__CURRICULUM_CLASS__ and not step.context:
            answer = self.ask_curriculum(f'How to {step.description}')
            context = f'Here are some web results for this task:\n{answer.value}'
            step.context = context
            self.save()
            if self.__WAIT_FOR_USER_INPUT__:
                input('Finished asking curriculum, press enter to continue...')

        if self.__WAIT_FOR_USER_INPUT__:
            input('About to execute skill building plan step, press enter to continue...')

        # Run the agent's plan step (calling LLM with code gen prompt)
        resp = super().execute_step_attempt(step, attempt, **kw)

        if not resp.is_success():
            return resp

        execution_result = None
        gen_code = None

        # Extract and parse the generated code
        try:
            gen_code = self.__CODE_EXTRACTOR__().invoke(resp.value)
            gen_code = self.process_generated_code(step, gen_code)
        except Exception as e:
            import traceback
            traceback.print_exc()
            execution_result = CodeExecutionResult.from_exception(e)
            self.add_annotation(
                name='code_extraction_validation_exception',
                text=f'Exception: {e}',
                severity='exception'
            )

        if gen_code:
            step.last_generated_code = gen_code
            self.current_code = gen_code
            self.save()

        if not execution_result:
            # Run the generated code with our target example
            execution_result = self.execute_current_code()
            # TODO this result does not capture prints. Maybe override print with capturing function?

        resp = resp.copy()

        try:
            execution_result = self.process_execution_result(
                step, execution_result
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            execution_result = CodeExecutionResult.from_exception(e)
            self.add_annotation(
                name='process_execution_result_exception',
                text=f'Exception: {e}',
                severity='exception'
            )

        resp.value = execution_result

        return resp

    def process_generated_code(self, step: AgentPlanStep, gen_code: Code) -> GeneratedCode:
        return gen_code
    
    def process_execution_result(self, step: AgentPlanStep, result: CodeExecutionResult):
        return result

    def get_step_input_vars(self, step: AgentPlanStep, **kw) -> dict:
        """
        Return template input variables to use with the user and system prompts based on the current step
        These key/vals will be used as inputs to the user and system prompts
        """
        inputs = super().get_step_input_vars(step)
        inputs.update(
            example_programs = self.get_related_skills(),
            critique = None,
            current_code = self.current_code,
            last_result = None,
        )
        return inputs

    def get_related_skills_as_md(self, skills=None):
        return '\n'.join(
            f'\n### Example `{skill.name}`\n' + 
            f'```\n{skill.get_source()}\n```'
            for skill in (skills or self.get_related_skills())
        ) or 'No related skills found'

    def get_related_skills(self, *args, **kwargs):
        # TODO retrieve related skills from vector db
        related_skills: list[Skill] = []
        base_skills: list[Skill] = [
            self.__SKILL_REPOSITORY__.get_by_name(s)
            for s in self.__BASE_SKILLS__
        ]
        # deduplicate by id
        all_skills = base_skills
        base_ids = set(x.id for x in base_skills)
        for skill in related_skills:
            if skill.id in base_ids:
                continue
            all_skills.append(skill)
        return all_skills

    # Just override the return typing of invoke for type hinting
    def invoke(self, input: Input=None, **kwargs: Any) -> AgentResponse[Skill]:
        return super().invoke(input, **kwargs)
    
