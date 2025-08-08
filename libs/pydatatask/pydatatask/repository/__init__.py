"""Repositories are arbitrary key-value stores. They are the data part of pydatatask. You can store your data in any
way you desire and as long as you can write a Repository class to describe it, it can be used to drive a pipeline.

The notion of the "value" part of the key-value store abstraction is defined very, very loosely. The repository base
class doesn't have an interface to get or store values, only to query for and delete keys. Instead, you have to know
which repository subclass you're working with, and use its interfaces. For example, `MetadataRepository` assumes that
its values are structured objects and loads them fully into memory, and `BlobRepository` provides a streaming interface
to a flat address space.
"""

from .base import *
from .bucket import *
from .docker import *
from .live import *
from .mongodb import *
from .filesystem import *
