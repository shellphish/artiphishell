from pydantic import BaseModel, Field
from typing import List, Optional, Set
from pathlib import Path

class Node(BaseModel):
    id: int
    funcname: str
    filepath: Optional[Path] = None
    is_source: bool
    is_sink: bool
    is_harness: bool
    color: str
    func_src: Optional[str] = None
    next_nodes: List[int] = []
    covered: Optional[bool] = False
    func_startline: Optional[int] = None
    func_endline: Optional[int] = None


class Edge(BaseModel):
    id: int
    source: int
    target: int
    color: str = "black"
    lineno: int

    filepath: Optional[Path] = None

    linetext: Optional[str] = None

class Graph(BaseModel):
    nodes: List[Node]
    edges: List[Edge]


class Program(BaseModel):
    src_root: Path
    report: Path
    lang: str = "java"
