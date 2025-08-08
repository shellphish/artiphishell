
from shellphish_crs_utils.models.base import ShellphishBaseModel
from agentlib.lib.common.logger import BaseLogger, StaticLogger

class BaseObject(ShellphishBaseModel, BaseLogger):
    pass