from enum import Enum
from pydantic import StringConstraints, field_validator, ValidationInfo, Field, model_validator
from typing import Annotated, Optional
from pathlib import Path

from shellphish_crs_utils.models.base import ShellphishBaseModel

class RelativePathKind(str, Enum):
    ARTIFACTS_DIR = "artifacts"
    TARGET_ROOT = "target_root"
    SOURCE_REPO = "source"
    OSS_FUZZ = "oss-fuzz"

class BinaryLocation(ShellphishBaseModel):
    file_name: Optional[Path] = Field(description="The name of the binary occurred", default=None)
    full_binary_path: Path = Field(description="The full path to the binary occurred")

    package: Optional[str] = Field(default=None, description="The package (for java, python, etc.)")
    offset: Optional[int] = Field(default=None, description="The offset of the symbol in the binary")
    function_name: Optional[str] = Field(default=None, description="The name of the function")
    build_id: Optional[str] = Field(default=None, description="The build id of the binary")
    raw_signature: Optional[str] = Field(default=None, description="The signature of the function (if available)")

    symbol_offset: Optional[int] = Field(default=None, description="The offset of the symbol (Not currently used)")
    symbol_size: Optional[int] = Field(default=None, description="The size of the symbol (Not currently used)")
    function_index_signature: Optional[str] = Field(default=None, description="Function signature defined by the function indexer convention (filename:start_line:start_column::signature)")
    function_index_key: Optional[str] = Field(default=None, description="The key index of the function in the function index (The same as the function signature)")

    @model_validator(mode='after')
    def sanity_check_model(self) -> "BinaryLocation":
        if not self.file_name and not self.full_binary_path:
            raise ValueError('Neither file name nor full binary path is available??')
        if not self.file_name and self.full_binary_path:
            raise ValueError('File name is not available despite full binary path being known')

        return self
    
    # create a binary location
    @classmethod
    def create(cls, full_binary_path=None, file_name=None, package=None, offset=None, function_name=None, build_id=None, raw_signature=None, symbol_offset=None, symbol_size=None, function_index_signature=None, function_index_key=None):
        # create a binary location
        v = {}
        if full_binary_path:
            v['full_binary_path'] = Path(full_binary_path)
        if file_name:
            v['file_name'] = Path(file_name)
        elif full_binary_path:
            v['file_name'] = Path(full_binary_path).name
        if package:
            v['package'] = package
        if offset:
            v['offset'] = offset
        if function_name:
            v['function_name'] = function_name
        if build_id:
            v['build_id'] = build_id
        if raw_signature:
            v['raw_signature'] = raw_signature
        if symbol_offset:
            v['symbol_offset'] = symbol_offset
        if symbol_size:
            v['symbol_size'] = symbol_size
        if function_index_signature:
            v['function_index_signature'] = function_index_signature
        if function_index_key:
            v['function_index_key'] = function_index_key
        return cls(**v)

class JavaInfo(ShellphishBaseModel):
    full_method_path: Optional[str] = Field(examples=['net.lingala.zip4j.model.AbstractFileHeader.getZip64ExtendedInfo', "java.lang.ProcessBuilder.start"], default=None, description="The full method path")
    package: Optional[str] = Field(examples=['net.lingala.zip4j.model', "java.lang"], default=None, description="The package (not including the class name.")
    class_path: Optional[str] = Field(examples=["net.lingala.zip4j.model.AbstractFileHeader", "java.lang.ProcessBuilder"], default=None, description="The full class path")
    class_name: Optional[str] = Field(examples=["AbstractFileHeader", "ProcessBuilder"], default=None, description="Only the class name")
    method_name: Optional[str] = Field(examples=["getZip64ExtendedInfo", "start"], default=None, description="The method name")
    package_prefix: Optional[str] = Field(examples=[None, "java.base"], default=None, description="The package prefix (java.base, java.xml, app/)")
    method_descriptor: Optional[str] = Field(examples=["()V", "(Z)V", "()Ljava/lang/Exception;", "(Lnet/lingala/zip4j/progress/ProgressMonitor$Task;)V"], default=None, description="The method descriptor")
    is_native_method: Optional[bool] = Field(default=False, description="Whether the method is a native method")

    @model_validator(mode='after')
    def sanity_check_model(self) -> "JavaInfo":
        if self.full_method_path:
            if not self.package and self.full_method_path.count('.') > 1:
                raise ValueError('Package is not set despite full method path being known')
            if not self.class_path:
                raise ValueError('Class path is not set despite full method path being known')
            if not self.class_name:
                raise ValueError('Class name is not set despite full method path being known')
            if not self.method_name:
                raise ValueError('Method name is not set despite full method path being known')
        if self.class_path:
            # if we know the classpath we should at least know the package and class name
            if not self.package and '.' in self.class_path:
                raise ValueError(f'Package is not set despite class path being known, class path: {self.class_path}')
            if not self.class_name:
                raise ValueError('Class name is not set despite class path being known')

        return self

    @field_validator('full_method_path')
    def check_valid_full_method_path(cls, value: str, info: ValidationInfo):
        # ensure the full_method_path is always in the format of "package.class.method"
        if value is None:
            return value

        if '/' in value:
            # no slashes allowed in the full method path
            raise ValueError("Full method path cannot contain slashes")

        return value

    @field_validator('package_prefix')
    def check_valid_package_prefix(cls, value: str, info: ValidationInfo):
        # Ensure the package prefix is always "java.base"
        if value is None:
            return value

        # if value != "java.base":
        #     raise ValueError("Package prefix must be 'java.base'")

        return value

    @field_validator('class_path')
    def check_valid_class_path(cls, value: str, info: ValidationInfo):
        # Ensure the class path always contains dots, not slashes
        if value is None:
            return value

        if '/' in value:
            raise ValueError("Class path cannot contain slashes")

        return value

    @field_validator('package')
    def check_valid_package(cls, value: str, info: ValidationInfo):
        # Ensure the package always contains dots, not slashes
        if value is None:
            return value

        if '/' in value:
            raise ValueError("Package cannot contain slashes")

        return value

    @field_validator('class_name')
    def check_valid_class_name(cls, value: str, info: ValidationInfo):
        # Ensure the class name does not contain dots
        if value is None:
            return value

        if '.' in value:
            raise ValueError("Class name cannot contain dots")

        return value

    @field_validator('method_name')
    def check_valid_method_name(cls, value: str, info: ValidationInfo):
        # Ensure the method name does not contain dots
        if value is None:
            return value

        if '.' in value:
            raise ValueError("Method name cannot contain dots")

        return value

    @field_validator('method_descriptor')
    def check_valid_method_descriptor(cls, value: str, info: ValidationInfo):
        # Ensure the method descriptor is always in the format of "()V", "(Z)V", "()Ljava/lang/Exception;", "(Lnet/lingala/zip4j/progress/ProgressMonitor$Task;)V"
        if value is None:
            return value

        open_paren = value.count("(")
        close_paren = value.count(")")
        if open_paren != 1 or close_paren != 1:
            raise ValueError("Method descriptor must contain exactly one open and close parenthesis")

        if value[0] != "(":
            raise ValueError("Method descriptor must start with an open parenthesis")

        if value[-1] == ")":
            raise ValueError("Method descriptor must not end with a close parenthesis, as it should always be followed by the return type")

        return value

class SourceLocation(ShellphishBaseModel):
    # CAUTION: You should (if possible) always use source_relative_file_path.
    # However, if that is not available, you can attempt to use full_file_path.
    # For java crashes, the full file path is not available, in which case you should be able to at least use the file_name
    # together with the method info and such from the JavaInfo object to locate the source.
    focus_repo_relative_path: Optional[Path] = Field(default=None, description="If we know for sure this is in the focus repo, this is the path relative to the source repo.")

    relative_path: Optional[Path] = Field(description="The path to the source code of the method. The root of this path is unspecified.", default=None)

    full_file_path: Optional[Path] = Field(default=None, description="The full path to the file where the crash occurred. This is not very reusable as it might contain run-specific paths. Only ever use this if focus_repo_relative_path and relative_path are not available.")
    file_name: Optional[Path] = Field(default=None, description="The name of the file where the crash occurred. This might be set even if the full and relative paths are not known.")
    function_name: Optional[str] = Field(default=None, description="The name of the function ")

    line_text: Optional[str] = Field(default=None, description="The line of code")
    line_number: Optional[int] = Field(default=None, description="The line number")
    symbol_offset: Optional[int] = Field(default=None, description="The offset of the symbol (Not currently used)")
    symbol_size: Optional[int] = Field(default=None, description="The size of the symbol (Not currently used)")

    raw_signature: Optional[str] = Field(default=None, description="The signature of the function (if available)")

    function_index_signature: Optional[str] = Field(default=None, description="Function signature defined by the function indexer convention (filename:start_line:start_column::signature)")
    function_index_key: Optional[str] = Field(default=None, description="The key index of the function in the function index (The same as the function signature)")

    java_info: Optional[JavaInfo] = Field(default=None, description="Java specific information")

    def __hash__(self):
        return hash(self.model_dump_json())

    def __eq__(self, other):
        return self.model_dump() == other.model_dump()

    @classmethod
    def create(cls, full_file_path=None, relative_path=None, file_name=None, function_name=None, line_number=None, line_text=None, symbol_offset=None, symbol_size=None, raw_signature=None, focus_repo_container_path=None, focus_repo_relative_path=None,function_index_signature=None, function_index_key=None, java_info=None):
        v = {}
        if full_file_path:
            v['full_file_path'] = Path(full_file_path)
        if relative_path:
            v['relative_path'] = Path(relative_path)
        if file_name or relative_path or full_file_path:
            v['file_name'] = Path(file_name or (relative_path.name if relative_path else None) or full_file_path.name)
        if function_name:
            v['function_name'] = function_name
        if line_number:
            v['line_number'] = line_number
        if line_text:
            v['line_text'] = line_text
        if symbol_offset:
            v['symbol_offset'] = symbol_offset
        if symbol_size:
            v['symbol_size'] = symbol_size
        if raw_signature:
            v['raw_signature'] = raw_signature
        if focus_repo_relative_path:
            v['focus_repo_relative_path'] = Path(focus_repo_relative_path)
        elif focus_repo_container_path and full_file_path:
            v['focus_repo_relative_path'] = Path(full_file_path).relative_to(focus_repo_container_path)
        return cls(**v)

    @model_validator(mode='after')
    def sanity_check_model(self) -> "SourceLocation":
        if not self.file_name and (self.full_file_path or self.relative_path):
            raise ValueError('File name is not available despite full and/or relative paths being known')
        if not self.file_name and self.java_info and self.java_info.class_name and not self.java_info.is_native_method:
            raise ValueError('File name is not available despite Java class name being known')
        if '/' in str(self.file_name):
            raise ValueError('File name contains a slash')

        if self.file_name and self.relative_path:
            assert self.file_name.name == self.relative_path.name, f"File name {self.file_name} does not match the name of the relative path {self.relative_path.name}"
        if self.file_name and self.full_file_path:
            assert self.file_name.name == self.full_file_path.name, f"File name {self.file_name} does not match the name of the full file path {self.full_file_path.name}"

        if self.function_index_key and not self.function_index_signature:
            raise ValueError('Function index key is set but function index signature is not')
        if self.function_index_signature and not self.function_index_key:
            raise ValueError('Function index signature is set but function index key is not')

        if self.function_index_key:
            # if we have the function index key we should know a bunch of things
            if not self.file_name:
                raise ValueError('File name is not set despite function index key being known')
            # if not self.line_number:
            #     raise ValueError('Line number is not set despite function index key being known')
            if not self.function_name:
                raise ValueError('Function name is not set despite function index key being known')
            if not self.full_file_path:
                raise ValueError('Full file path is not set despite function index key being known')
            if not self.raw_signature:
                raise ValueError('Raw signature is not set despite function index key being known')
        return self

class POI(ShellphishBaseModel):
    reason: Optional[str] = Field(description="The reason for the POI, normally a description of the crash", default=None)
    source_location: SourceLocation = Field(description="The source location of the crash")
