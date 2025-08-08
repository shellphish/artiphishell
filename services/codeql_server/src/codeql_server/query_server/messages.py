from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import IntEnum

class QueryResultType(IntEnum):
    SUCCESS = 0
    OTHER_ERROR = 1
    COMPILATION_ERROR = 2
    OOM = 3
    CANCELLATION = 4
    DBSCHEME_MISMATCH_NAME = 5
    DBSCHEME_NO_UPGRADE = 6

@dataclass
class Position:
    line: int
    column: int
    end_line: int
    end_column: int
    file_name: str

    def to_dict(self):
        return asdict(self)

@dataclass 
class QuickEvalOptions:
    quick_eval_pos: Optional[Position] = None
    count_only: bool = False

    def to_dict(self):
        d = asdict(self)
        if self.quick_eval_pos:
            d['quick_eval_pos'] = self.quick_eval_pos.to_dict()
        return {k: v for k, v in d.items() if v is not None}

@dataclass
class CompilationTarget:
    query: Optional[Dict] = None
    quick_eval: Optional[QuickEvalOptions] = None

    def to_dict(self):
        d = {}
        if self.query is not None:
            d['query'] = self.query
        if self.quick_eval is not None:
            d['quickEval'] = self.quick_eval.to_dict()
        return d

@dataclass
class RunQueryParams:
    query_path: str
    output_path: str
    db: str
    additional_packs: List[str]
    target: CompilationTarget
    external_inputs: Dict[str, str]
    singleton_external_inputs: Dict[str, str]
    dil_path: Optional[str] = None
    log_path: Optional[str] = None
    extension_packs: Optional[List[str]] = None

    def to_dict(self):
        d = {
            'queryPath': self.query_path,
            'outputPath': self.output_path,
            'db': self.db,
            'additionalPacks': self.additional_packs,
            'target': self.target.to_dict(),
            'externalInputs': self.external_inputs,
            'singletonExternalInputs': self.singleton_external_inputs
        }

        if self.dil_path:
            d['dilPath'] = self.dil_path
        if self.log_path:
            d['logPath'] = self.log_path
        if self.extension_packs:
            d['extensionPacks'] = self.extension_packs
        return d

@dataclass
class RunQueryResult:
    result_type: QueryResultType
    message: Optional[str]
    evaluation_time: float
    expected_dbscheme_name: Optional[str] = None

@dataclass
class ProgressParams:
    id: int
    step: int
    max_step: int
    message: str

@dataclass
class BqrsInfo:
    result_sets: List[Dict[str, Any]]
    
@dataclass
class BqrsResults:
    tuples: List[List[Any]]

@dataclass 
class DatabaseInfo:
    dbscheme: str
    
@dataclass
class RegisterDatabasesParams:
    databases: List[str]
    
@dataclass
class GetDatabaseInfoParams:
    db: str
    
@dataclass
class BqrsInfoParams:
    path: str
    
@dataclass
class BqrsDecodeParams:
    path: str
    result_set: str
