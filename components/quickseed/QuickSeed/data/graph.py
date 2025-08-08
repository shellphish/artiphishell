"""
Data models for the graph representation of the program, including call graphs and control flow graphs.
"""

from pathlib import Path
from typing import Optional, List
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


class CallGraphNode(BaseModel):
    """
    A node in the call graph.
    """
    model_config = ConfigDict(frozen=False) 
    id: UUID = Field(default_factory=uuid4)
    function_name: str
    filepath: Optional[Path] = None
    qualified_name: Optional[str] = None
    signature: Optional[str] = None # Unique signature of the function
    is_source: bool = False  # source must be defined explicitly, which should represent the entry point of the program
    is_sink: bool = False  # sink must be defined explicitly, which should represent the POI method we want to reach
    is_harness: bool = False
    color: str = 'blue'
    function_code: Optional[str] = None
    lineno: Optional[int] = None
    # next_nodes: List[UUID] = Field(default_factory=list)
    # previous_nodes: List[UUID] = Field(default_factory=list)
    covered: Optional[bool] = False
    function_startline: Optional[int] = None
    function_endline: Optional[int] = None
    class_name: Optional[str] = None
    identifier: Optional[str] = None  # Unique identifier for the function, can be used to resolve the function in the codebase

    def __repr__(self) -> str:
        filepath_str = str(self.filepath) if self.filepath else "None"
        return f"CallGraphNode(function_name='{self.function_name}', filepath='{filepath_str}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallGraphNode):
            return False
        if self.qualified_name and other.qualified_name:
            return self.qualified_name == other.qualified_name
        return (self.function_name == other.function_name and
                self.filepath.name == other.filepath.name)
    
    def __hash__(self):
        # Hash based on unique identifier(s)
        # Replace 'id' with whatever uniquely identifies your node
        return hash(self.identifier)

class CallGraphEdge(BaseModel):
    """
    An edge in the call graph.
    """
    model_config = ConfigDict(frozen=False) 
    id: UUID = Field(default_factory=uuid4)
    source: UUID
    target: UUID
    color: str = "black"
    filepath: Optional[Path] = None  # file where the source node calls the target node
    lineno: Optional[int] = None  # line number in the file where the source node calls the target node
    linetext: Optional[str] = None  # line text in the file where the source node calls the target node

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallGraphEdge):
            return False
        return (self.source == other.source and
                self.target == other.target)


# class Graph(BaseModel):
#     nodes: List[Node]
#     edges: List[Edge]


# class Program(BaseModel):
#     src_root: Path
#     report: Path
#     lang: str = "java"

class ControlFlowNode(BaseModel):
    id: int
    expr: str
    location: str
    startline: int = 0
    endline: int = 0
    next_nodes: List[int] = []
    previous_nodes: List[int] = []


class ControlFlowEdge(BaseModel):
    id: int
    source: int
    target: int
    label: Optional[bool] = None


class ControlFlowGraph(BaseModel):
    nodes: List[ControlFlowNode]
    edges: List[ControlFlowEdge]


class ReflectionCallNode(BaseModel):
    method_invoking_reflection: str
    reflection_call_location: str

class FlowNode(BaseModel):
    """
    A node in the flow graph.
    This does not need required a function name. It can be a variable or a statement. 
    We just need to know the location of the node in the code.
    """
    model_config = ConfigDict(frozen=False) 
    id: UUID = Field(default_factory=uuid4)
    filepath: Path
    startline: int
    endline: int
    