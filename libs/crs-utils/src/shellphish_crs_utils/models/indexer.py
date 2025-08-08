from enum import Enum
from typing import List, Optional, Any, Tuple, Dict, TypeAlias
from pathlib import Path

from pydantic import field_validator, ValidationInfo, Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.symbols import RelativePathKind

FUNCTION_INDEX_KEY: TypeAlias = str

class ReferenceBase(ShellphishBaseModel):
    unique_identifier: str = Field(description="A unique identifier of the reference")
    name: str = Field(description="The name of the reference")

class GlobalVariableReference(ReferenceBase):
    declaration: str = Field(description="The declaration of the global variable")
    raw_comment: Optional[str] = Field(description="The raw comment of the global variable")
    declaration_start_line: int = Field(description="The starting line of the declaration")
    declaration_end_line: int = Field(description="The ending line of the declaration")
    declaration_start_offset: int = Field(description="The starting offset of the declaration")
    declaration_end_offset: int = Field(description="The ending offset of the declaration")
    declaration_start_column: int = Field(description="The starting column of the declaration")
    declaration_end_column: int = Field(description="The ending column of the declaration")
    type: str = Field(description="The type of the global variable")

class FunctionReference(ReferenceBase):
    pass

class FunctionReferenceCall(FunctionReference):
    type: str = Field(description="The type of the function call")

class FunctionBase(ShellphishBaseModel):
    target_compile_args: Dict[str, Any] = Field(description="The compile arguments of the file this function resides in")
    was_directly_compiled: bool = Field(description="Whether the function was in a file that was compiled or not. If false, this file might have been excluded by the build-system or post-processed elsewhere before building.")
    is_generated_during_build: bool = Field(description="Whether the function is generated during build time or already exists in the project sources. This is really only set for things in the focus_repo.", default=False)

    unique_identifier: str = Field(description="A unique identifier of the function")
    code: str = Field(description="The source code of the function")
    hash: str = Field(description="The hash of the function source code")
    raw_comment: Optional[str] = Field(description="The raw comment of the function")
    start_line: int = Field(description="The starting line of the function")
    end_line: int = Field(description="The ending line of the function")
    start_offset: int = Field(description="The starting offset of the function")
    end_offset: int = Field(description="The ending offset of the function")
    start_column: int = Field(description="The starting column of the function")
    end_column: int = Field(description="The ending column of the function")
    global_variables: List[GlobalVariableReference] = Field(description="The global variables used in the function")
    signature: Optional[str] = Field(description="The signature of the function")
    target_container_path: Optional[Path] = Field(description="The path to the file containing the function. This is the absolute path as seen from in the target container.", examples=["/src/hiredis/hiredis.c"], default=None)
    focus_repo_relative_path: Optional[Path] = Field(description="The path to the file containing the function. This is the relative path as seen from the focus directory. If this is null, the function is *not* inside the focus repo.", examples=["hiredis.c"], default=None)


class FunctionInfo(FunctionBase):
    name: str = Field(description="The name of the function")
    mangled_name: str  = Field(description="The mangled name of the function")
    comment: Optional[str] = Field(description="The comments in the function (Not Implemented)")
    calls: List[FunctionReferenceCall] = Field(description="The list of function calls in the function")
    func_return_type: str = Field(description="The return type of the function")
    
class MethodInfo(FunctionBase):
    mangled_name: str = Field(description="The mangled name of the method")
    full_name: str = Field(description="The full name of the method (class_name::method_name)")
    method_name: str = Field(description="The name of the method")
    comment: Optional[str] = Field(description="The comments in the method (Not Implemented)")
    calls: List[FunctionReferenceCall] = Field(description="The list of function calls in the method")
    
class MacroInfo(FunctionBase):
    name: str = Field(description="The name of the macro")

class FunctionIndex(FunctionBase):
    funcname: str = Field(description="The name of the function")
    full_funcname: str = Field(description="The full name of the function (class_name::function_name if applicable)")
    func_return_type: str = Field(description="The return type of the function")
    signature: Optional[FUNCTION_INDEX_KEY] = Field(description="Raw function signature", default=None)
    arguments: List[str] = Field(description="The arguments of the function")
    local_variables: List[str] = Field(description="The local variables used in the function")
    func_calls_in_func_with_fullname: List[Any] = Field(description="The list of function calls in the function")
    filename: str = Field(description="The name of the file containing the function")
    class_name: Optional[str] = Field(description="The name of the class containing the function", default=None)
    comments: List[str] = Field(description="The comments in the function (Not Implemented)", default_factory=list)
    cfg: Optional[str] = Field(description="Not Implemented", default=None)
    package: Optional[str] = Field(description="The package of the function (Java Only)", default=None)
    language_specific_info: Optional[Dict[str, Any]] = Field(description="The language specific information of the function", default=None)

class CommitToFunctionIndex(ShellphishBaseModel):
    commit_to_index_info: Dict[str, Dict[FUNCTION_INDEX_KEY, Path]] = Field(description="The mapping of commit sha (e.g. '1_9faebc...') to function index information")

class SignatureToFile(ShellphishBaseModel):
    sig_to_file: Dict[FUNCTION_INDEX_KEY, Path] = Field(description="The mapping of function signature to jsons directory file path")

class ReducedFunctionIndex(ShellphishBaseModel):
    func_name: str = Field(description="The name of the function")
    function_signature: FUNCTION_INDEX_KEY = Field(description="The signature of the function (filename:start_line:start_column::signature)")
    filename: str = Field(description="The name of the file containing the function")
    indexed_jsons_relative_filepath: Path = Field(description="The relative path to the source code of the function inside the functions jsons produced by the indexers.")
    start_line: int = Field(description="The starting line of the function")
    end_line: int = Field(description="The ending line of the function")
    start_column: int = Field(description="The starting column of the function")
    end_column: int = Field(description="The ending column of the function")
    start_offset: int = Field(description="The starting offset of the function")
    end_offset: int = Field(description="The ending offset of the function")
    line_map: Optional[Dict[int, str]] = Field(description="The mapping of line number to source code line (Contains full source of the function)", default=None)
    target_container_path: Optional[Path] = Field(description="The path to the file containing the function. This is the absolute path as seen from in the target container.", examples=["/src/hiredis/hiredis.c"], default=None)
    focus_repo_relative_path: Optional[Path] = Field(description="The path to the file containing the function. This is the relative path as seen from the focus repository. If this is null, the function is *not* inside the focus repo.", examples=["hiredis.c"], default=None)

class FunctionsByFile(ShellphishBaseModel):
    func_by_file: Dict[Path, List[ReducedFunctionIndex]] = Field(description="The mapping of file path to list of functions")
