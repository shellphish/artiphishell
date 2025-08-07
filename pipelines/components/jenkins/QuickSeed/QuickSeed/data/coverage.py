from typing import Dict
from pydantic import BaseModel



class FileCoverage(BaseModel):
    file_name: str
    lines: Dict[int, bool]
    
class NodeCoverage(BaseModel):
    file_name: str
    lineno: int
    covered: bool