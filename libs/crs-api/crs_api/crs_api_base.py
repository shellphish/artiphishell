from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.aixcc_api import *
from abc import ABC, abstractmethod
from uuid import UUID


class CRSAPIBase(ShellphishBaseModel, ABC):
    @classmethod
    @abstractmethod
    def get_status(cls) -> Status:
        """
        Report the status of the CRS
        """
        pass

    @classmethod
    @abstractmethod
    def consume_sarif_broadcast(cls, sarif_broadcast: SARIFBroadcast) -> None:
        """
        Consume a submitted sarif broadcast
        """
        pass

    @classmethod
    @abstractmethod
    def consume_tasking(cls, tasking: Task) -> None:
        """
        Consume a submitted tasking
        """
        pass

    @classmethod
    @abstractmethod
    def cancel_task(cls, task_id: UUID) -> None:
        """
        Cancel a running task by uuid
        """
        pass
