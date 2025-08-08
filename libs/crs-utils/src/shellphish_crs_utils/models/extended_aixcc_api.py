from typing import List, Optional
from shellphish_crs_utils.models.aixcc_api import TaskDetail, Task
from shellphish_crs_utils.models.constraints import PDT_ID
from uuid import UUID

class ExtendedTaskDetail(TaskDetail):
    task_uuid: UUID
    task_sanitizer: str
    pdt_task_id: PDT_ID
    concurrent_target_num: Optional[int] = None
    fuzzing_pool_name: Optional[str] = None

class ExtendedTask(Task):
    tasks: List[ExtendedTaskDetail]
