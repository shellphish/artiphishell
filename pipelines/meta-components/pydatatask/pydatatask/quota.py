"""Pydatatask defines the notion of resources, or numerical quantities of CPU and memory which can be allocated to a
given job. This is mediated through a :class:`QuotaManager`, an object which can atomically track increments and
decrements from a quota, and reject a request if it would break the quota.

Typical usage is to construct a :class:`QuotaManager` and pass it to a task constructor:

.. code:: python

    quota = pydatatask.QuotaManager(pydatatask.Quota.parse(cpu='1000m', mem='1Gi'))
    task = pydatatask.ProcessTask("my_task", localhost, quota, ...)

TODO REWRITE THIS GODDAMN SHIT
"""

from typing import Optional, Union
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum, auto

from kubernetes.utils import parse_quantity
from typing_extensions import Self
import psutil

__all__ = ("QuotaType", "Quota", "parse_quantity", "_MaxQuotaType", "MAX_QUOTA")


class QuotaType(Enum):
    """An enum class indicating a type of resource.

    Presently can be CPU or MEM.
    """

    CPU = auto()
    MEM = auto()


@dataclass(eq=False)
class Quota:
    """A dataclass containing a quantity of resources.

    Quotas can be summed:

    .. code:: python

        r = pydatatask.Quota.parse(1, 1)
        r += pydatatask.Quota.parse(2, 3)
        r -= pydatatask.Quota.parse(1, 1)
        assert r == pydatatask.Quota.parse(2, 3)
    """

    cpu: Decimal = field(default=Decimal(0))
    mem: Decimal = field(default=Decimal(0))

    @classmethod
    def parse(
        cls,
        cpu: Union[str, float, int, Decimal],
        mem: Union[str, float, int, Decimal],
    ) -> Self:
        """Construct a :class:`Quota` instance by parsing the given quantities of CPU and memory."""
        return cls(cpu=parse_quantity(cpu), mem=parse_quantity(mem))

    def __add__(self, other: Self):
        return type(self)(cpu=self.cpu + other.cpu, mem=self.mem + other.mem)

    def __mul__(self, other: Union[int, float, Decimal]):
        other_d = Decimal(other)
        return type(self)(cpu=self.cpu * other_d, mem=self.mem * other_d)

    def __sub__(self, other: Self):
        return self + other * -1

    def excess(self, limit: Self) -> Optional[QuotaType]:
        """Determine if these resources are over a given limit.

        :return: The QuotaType of the first resource that is over-limit, or None if self is under-limit.
        """
        if self.cpu > limit.cpu:
            return QuotaType.CPU
        elif self.mem > limit.mem:
            return QuotaType.MEM
        else:
            return None


LOCALHOST_QUOTA = Quota.parse(cpu=psutil.cpu_count(), mem=psutil.virtual_memory().total)


class _MaxQuotaType(float):
    pass


MAX_QUOTA = _MaxQuotaType(1.0)
