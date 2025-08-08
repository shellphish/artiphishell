from abc import ABC, abstractmethod


class Worker(ABC):
    def __init__(self, queue, name=None):
        self.queue = queue
        self.name = name or ''

    @abstractmethod
    def operate(self):
        pass
