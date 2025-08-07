from agentlib.lib.common.code import GeneratedCode
from .verify import try_compile_grammar, CompilationConfig
from typing import Optional
from pathlib import Path
import os

from agentlib import enable_event_dumping, set_global_budget_limit
enable_event_dumping('/shared/syzgrammar-gen')
set_global_budget_limit(
    price_in_dollars=1,
    exit_on_over_budget=True
)

from agentlib import (
    PlanExecutor,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CodeExtractor
)

class GenSyzlang(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = os.path.dirname(__file__) + '/prompts/gen_syzlang_agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = os.path.dirname(__file__) + '/prompts/gen_syzlang_agent.user.j2'

    source: Optional[str]
    syzkaller_path: Path
    syzkaller_threads: int
    proposed_grammar: Optional[GeneratedCode]
    final_grammar: Optional[GeneratedCode]
    compilation_feedback: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            source = self.source,
            proposed_grammar = self.proposed_grammar,
            compilation_feedback = self.compilation_feedback
        )

    def process_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt
    ):
        super().process_step_result(step, attempt)
        res = attempt.result

        if step.name == 'propose_grammar':
            print('Initial Syzlang grammar:', repr(res))
            if res is not None:
                compile_result = try_compile_grammar(
                    CompilationConfig(self.syzkaller_path, self.syzkaller_threads),
                    res.get_source()
                )
                if not compile_result.success:
                    print("Compiler Output:", compile_result.output)
                    self.compilation_feedback = compile_result.output
                    return False
                else:
                    self.proposed_grammar = res
                    self.compilation_feedback = None
                    return True

        # If you modified the attempt, result, or step
        # step.save()
        return True # Final judgement on whether the step was successful

def run(compile_config: CompilationConfig, harness_code: str) -> Optional[str]:
    plan = AgentPlan(steps=[
        #AgentPlanStep(
        #    # Description can contain anything you want to describe the current step
        #    description='Determine what needs to be included in the syzkaller grammar, but do NOT generate a grammar yet. Focus on making a correct description of the types, sizes, and relations of fields in the input blob. Pay special attention to type casting done by the harness, it it reads four bytes of input and then casts it to a two byte type, that field still needs to be represented by a four byte type if it is included in a packed struct.',
        #    llm_model = 'claude-3-opus',
        #),
        AgentPlanStep(
            # Name allows you to quickly detect what step is being executed
            name='propose_grammar',
            description='Create a syzkaller grammar for the provided program that describes the input to the harness.',
            output_parser=CodeExtractor(),
            llm_model = 'claude-3-opus',
        ),
    ])

    # Path to save agent data to
    agent_path = '/tmp/syzlang_agent.json'
    plan = plan.save_copy()

    agent: GenSyzlang = GenSyzlang.reload_id_from_file_or_new(
        agent_path,
        source=harness_code,
        goal='generate syzlang',
        plan=plan,
        syzkaller_path=compile_config.syzkaller_path,
        syzkaller_threads=compile_config.max_threads
    )

    agent.use_web_logging_config()

    agent.warn(f'========== Agent\'s plan ==========\n')
    print(agent)
    print(agent.plan)
    agent.warn(f'========== Running agent ==========\n')

    res = agent.invoke()

    if res is None:
        return None
    else:
        extractor = CodeExtractor(language=None)
        code = extractor.parse(res).source_code
        return code
