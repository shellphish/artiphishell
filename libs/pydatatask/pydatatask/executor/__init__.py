"""An executor is an environment in which a task can run.

Each executor should be able to host a variety of tasks.
"""

__all__ = (
    "Executor",
    "PodManager",
    "AbstractProcessManager",
    "LocalLinuxManager",
    "localhost_manager",
    "AbstractContainerManager",
    "DockerContainerManager",
    "KubeContainerManager",
    "docker_connect",
    "SSHLinuxManager",
    "InProcessLocalLinuxManager",
    "AbstractContainerSetManager",
    "DockerContainerSetManager",
    "KubeContainerSetManager",
)

from .base import Executor
from .pod_manager import PodManager
from .proc_manager import (
    AbstractProcessManager,
    LocalLinuxManager,
    localhost_manager,
    SSHLinuxManager,
    InProcessLocalLinuxManager,
)
from .container_manager import (
    AbstractContainerManager,
    DockerContainerManager,
    KubeContainerManager,
    docker_connect,
)
from .container_set_manager import (
    AbstractContainerSetManager,
    DockerContainerSetManager,
    KubeContainerSetManager,
)
