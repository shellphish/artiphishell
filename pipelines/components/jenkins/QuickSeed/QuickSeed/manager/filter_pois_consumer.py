import random
import string
import logging
import json

from .consumer import BaseConsumer
from .task import FilterPoisTask
from ..llm import harness_agent
from ..parser import TaintParser

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)


class FilterPoisConsumer(BaseConsumer):
    task_type = FilterPoisTask.__name__
    def __init__(
        self,
        queue,
        model,
        jazzer_json,
        taint_parser,
        benign_dir=None,
        crash_dir=None,
        name=None,
    ):
        super().__init__(queue, name)
        self.crash_dir = crash_dir
        self.benign_dir = benign_dir
        self.harness_code = ""
        random_filename = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
        # TODO: is agent_path per agent or per task?
        self.agent_path = f"/tmp/{random_filename}.json"
        self.model = model

        self.taint_parser = taint_parser

        with open(jazzer_json, "r") as f:
            self.jazzer_sanitizer_description = json.load(f)
            
    def convert_source_trace_to_prompt(self, source_and_traces) -> str: 
        prompt = ""
        count = 1
        for node_edge_info in source_and_traces[:-1]:
            src_code = node_edge_info["func_src"]
            linetexts = [lint for lint in node_edge_info["call_linetext"]]
            prompt += f"The source code of function {count} is: \n {src_code}\n"
            prompt += f"The lines of codes that call next function are: \n"
            for line in linetexts:
                prompt += f"{line}\n"
            count += 1       
        prompt += f"The possible sink points are the following calls in the last function: \n"
        for line in linetexts:
            prompt += f"{line}\n"
        return prompt

    def operate(self, task):
        _l.debug("we are runnning on filter consumers!!")

        no_harness_path = self.taint_parser.cut_harness_from_path(task.node_path)
        harness_filepath = self.taint_parser.retrieve_harness_source_for_path(no_harness_path)

        source_and_traces = self.taint_parser.retrieve_source_code_for_llm_from_path(
            task.node_path
        )
        if harness_filepath:
            with open (harness_filepath, "r") as f:
                self.harness_code = f.read()
        self.taint_parser.retrieve_harness_source_for_path(no_harness_path)
        _l.debug(f"source and traces is {source_and_traces}")
        trace_info_prompt = self.convert_source_trace_to_prompt(source_and_traces)
        generated_seed_path = harness_agent(
            self.agent_path,
            self.harness_code,
            trace_info_prompt,
            self.jazzer_sanitizer_description,
            self.model,
            task.reason
        )
        _l.info(f"queue id is {id(self.queue)}")
