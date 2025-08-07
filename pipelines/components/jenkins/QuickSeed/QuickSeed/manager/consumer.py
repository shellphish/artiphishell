import os
import random
import string

from ..llm import harness_agent
from .task import HarnessTask
from QuickSeed.verifier import SeedTriage
from abc import ABC, abstractmethod

import logging
_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)

class BaseConsumer(ABC):
    def __init__(self, queue, name=None):
        self.queue = queue
        self.name = name or ''
    
    @abstractmethod
    def operate(self):
        pass

    @property
    @abstractmethod
    def task_type(self):
        pass

class HarnessConsumer(BaseConsumer):
    task_type = HarnessTask.__name__
    def __init__(self, model, queue, benign_seeds_dir, crash_seeds_dir, target_dir, name=None):
        super().__init__(queue, name)
        self.benign_seeds_dir = benign_seeds_dir
        self.crash_seeds_dir = crash_seeds_dir
        self.harness_code = ""
        random_filename = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
        self.target_dir = target_dir
        # TODO: is agent_path per agent or per task?
        self.agent_path = f"/tmp/{random_filename}.json"
        self.model = model

    def operate(self, task):

        _l.info(f"queue id is {id(self.queue)}")
        _l.warning(f"jazzer sanitizer descriptoin {task.jazzer_sanitizer_description}")
        
        genreated_seed = harness_agent(self.agent_path, task.harness_code, task.trace_info_prompt, task.jazzer_sanitizer_description, self.model)
        run_script_path = self.target_dir / "run.sh"
        if genreated_seed:
            seed_triage = SeedTriage(run_script_path, task.harness_filepath, self.benign_seeds_dir, self.crash_seeds_dir)

            # exit_type = 0 means that it exits safely. It probably pass the pov check, probably not 
            # exit_type = 1 means that there is internal error, which is bad
            # _l.debug(f"generate seed path is {genreated_seed_path}")
            exit_type = seed_triage.generates_alerts(genreated_seed)

