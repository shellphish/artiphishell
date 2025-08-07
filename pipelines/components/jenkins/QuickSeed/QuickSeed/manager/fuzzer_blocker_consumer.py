import random
import string
import logging

from .consumer import BaseConsumer
from ..llm import pois_agent
from .task import PoisTask, FilterPoisTask

_l = logging.getLogger(__name__)


class FuzzerBlockerConsumer(BaseConsumer):
    task_type = PoisTask.__name__
    def __init__(self, queue, model, name=None):
        super().__init__(queue, name)
        self.model = model
        random_filename = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
        # TODO: is agent_path per agent or per task?
        self.agent_path = f"/tmp/{random_filename}.json"
        self.pois_code = ""
        
    def operate(self, task):
        ## TODO specify task object structure when ati finalize her part
        model_name = task.use_model_name
        node_path = task.node_path
        filter_pois, reason = pois_agent(self.agent_path, model_name, node_path)
        _l.debug(f"consuming item")
        _l.debug(f"we have generated some interesting pois {filter_pois}")
        _l.info(f"queue id is {id(self.queue)}")

        if len(filter_pois) > 0:
            _l.info("we are puting stuff back")
            _l.info(f"queue id is {id(self.queue)}")
            self.queue.put(FilterPoisTask(node_path, model_name, reason))

        # take a nap for now, because we are not doing anything yet
        import time
        time.sleep(1)
