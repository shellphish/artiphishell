# Standard Imports
import time
import logging
from typing import List
from datetime import datetime, timedelta, timezone

# Local Imports
from grammaroomba.globals import GLOBALS, wipe_memory
from grammaroomba.agents import mutator_grammar
from grammaroomba.functions import FunctionMeta, FunctionMetaStack

# Shellphish imports
# from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY # type: ignore
# from grammar_guy.common.generate import invoke_generator # type: ignore

class Grammaroomba:

    def __init__(self, tracer): # type: ignore
        self.log = logging.getLogger(f"grammaroomba.Grammaroomba.{id(self)}")
        self.function_stack: FunctionMetaStack = FunctionMetaStack()
        
        self.failed_mutations:      List[FunctionMeta]              = []
        self.successful_mutations:  List[FunctionMeta]              = []
        self.tracer                                                 = tracer
        self.grammar_mutator:       mutator_grammar.GrammarMutator  = mutator_grammar.GrammarMutator()
    
    def ready_to_run(self) -> bool:
        # Check if all agents are initialized and function stack is not empty
        self.log.info("Checking if Grammaroomba is ready to run...")
        ready_status = all([
                            self.tracer is not None,
                            self.function_stack.is_empty() == False,
                            ])
        return ready_status

    def run(self):
        # initial stack sort
        self.log.info(f'Running roomba.. for functions in {GLOBALS.cp_harness_name}')
        
        iteration = 0
        while True:
            iteration += 1
            wipe_memory()
            if iteration == 1:
                self.function_stack.update()
            
            empty_wait =  0
            while self.function_stack.is_empty():
                empty_wait += 1
                if empty_wait >= 10000:
                    self.log.info(f"The roomba has been waiting for {empty_wait} * 15 minutes. Giving up.")
                    return
                self.log.info(f"The roomba does not have functions to clean up. Waiting for {empty_wait} * 15 minutes to update stack and retrying.")
                time.sleep(900)
                self.function_stack.update()

            assert self.ready_to_run(), "Grammaroomba is not ready to run."
            if (datetime.now(timezone.utc) - self.function_stack.last_updated_time) > timedelta(minutes=15):
                self.log.info('Updating stack - it has been 15 minutes since last update! Here are the current stats: \n')
                self.log.info(f"######################################################################\n")
                self.log.info(f"We have so far updated {len(GLOBALS.seen_keys)}, with a success rate of {len(self.successful_mutations)} / {len(GLOBALS.seen_keys)}.")
                self.log.info(f"######################################################################\n")
                self.function_stack.update()
            
            self.log.info(f"Current iteration of Grammaroomba loop {iteration}. Function stack size: {len(self.function_stack.stack)}")
            current_function_meta: FunctionMeta = self.function_stack.pop()
            current_function_meta.source_code = GLOBALS.function_resolver.get(current_function_meta.function_index_key).code
            success, cov_indication = self.grammar_mutator.run(current_function_meta)
            self.grammar_mutator.chat_history.clear()
            if not success:
                self.log.warning(f"GrammarMutator did not improve coverage for {current_function_meta.function_index_key}.")
                self.failed_mutations.append(current_function_meta)
                GLOBALS.seen_keys.add(current_function_meta.function_index_key)
            else:
                if cov_indication == '':
                    self.log.info(f"GrammarMutator successfully improved coverage for {current_function_meta.function_index_key}.")
                    self.successful_mutations.append(current_function_meta)
                else:
                    self.log.info(f"GrammarMutator fully covered {current_function_meta.function_index_key}!")
                    self.successful_mutations.append(current_function_meta)
                GLOBALS.seen_keys.add(current_function_meta.function_index_key)
            