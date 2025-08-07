import os
import json
import subprocess
from typing import Union, Optional, Any, Dict, List, Generic
from pathlib import Path

from langchain_core.runnables.utils import Input, Output

from ..common.parsers import Code
from ..common.object import NamedFileObject
from ..common.store import ObjectRepository

class Skill(NamedFileObject):
    description: Optional[str]
    source_ptr: Optional[str]

    def get_code(self) -> Code:
        return Code.from_python_source(self.get_source())

    def get_source(self) -> str:
        if self.source_ptr is None:
            return None
        # TODO separate func
        proto, src = self.source_ptr.split('://', 1)
        if proto == 'file':
            return open(src, 'r').read()
        raise ValueError(f'Unknown source protocol: {proto}')

class SkillRepository(ObjectRepository):
    __ROOT_DIR__ = Path('volumes/skills').resolve()
    __OBJECT_CLASS__ = Skill

    def add_skill(self, skill: Skill):
        self.upsert(skill)

