from typing import List, Optional, Set, Dict, Any
from pathlib import Path

from pydantic import Field
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from src.models.code_block import CodeBlock
from src.models import BaseObject

USE_REMOTE_FUNCTION_RESOLVER = True

class CodeRegistry(BaseObject):
    index_dir: Path = Field(description="Path to the index directory")
    index_dir_json: Path = Field(description="Path to the index directory")

    code_blocks: Dict[str, List[CodeBlock]] = Field(default_factory=dict)
    all_code_blocks: List[CodeBlock] = Field(default_factory=list)

    entrypoint_code_blocks: List[CodeBlock] = Field(default_factory=list)

    def pre_process_project(self, project: OSSFuzzProject, metadata: Dict[str, Any]) -> None:
        if not project.harnesses:
            self.warn("No harnesses found")
            return

        use_local_instead = not USE_REMOTE_FUNCTION_RESOLVER

        if USE_REMOTE_FUNCTION_RESOLVER:
            resolver = RemoteFunctionResolver(
                cp_name=project.project_name,
                project_id=project.project_id
            )
            if not resolver.is_ready():
                self.warn("Remote function resolver is not ready")
                use_local_instead = True

        if self.index_dir and self.index_dir_json and use_local_instead:
            resolver = LocalFunctionResolver(
                functions_index_path=self.index_dir,
                functions_jsons_path=self.index_dir_json
            )

        for harness in project.harnesses:
            path = None
            try:
                harness_target_container_path = project.get_harness_source_target_container_path(
                    harness,
                    resolver,
                )
                path = project.artifacts_path(container_path=harness_target_container_path)
                self.warn(f"Harness target container path: {harness_target_container_path}")
            except Exception as e:
                self.warn(f"Error getting path for harness {harness}: {e}")
                continue

            self.warn(f"Path for harness {harness}: {path}")

            if not path:
                self.warn(f"No path found for harness {harness}")
                continue

            self.warn(f"Found path for harness {harness}: {path}")

            # info = project.get_harness_info(harness)
            try:
                harness_index_key = project.get_harness_function_index_key(harness, resolver)
            except Exception as e:
                self.warn(f"Error getting harness function index key for {harness}: {e}")
                continue
            if not harness_index_key:
                self.warn(f"No function index found for harness {harness}")
                continue 
  
            harness_entry_code_blocks = self.find_function_by_name(resolver.get_funcname(harness_index_key))
            
            print(harness_entry_code_blocks)
            if not harness_entry_code_blocks:
                self.warn(f"No entrypoint code blocks found for harness {harness}. Creating a new one.")
                try:
                    harness_entry_code_blocks = [CodeBlock(
                        function_key=harness_index_key,
                        function_info=resolver.get(harness_index_key),
                    )]
                except Exception as e:
                    self.warn(f"Error creating code block for harness {harness}: {e}")
                    continue

            for code_block in harness_entry_code_blocks:
                if code_block not in self.entrypoint_code_blocks:
                    self.entrypoint_code_blocks.append(code_block)


    def add_code_block(self, code_block: CodeBlock):
        if code_block.funcname not in self.code_blocks:
            self.code_blocks[code_block.funcname] = []
        self.code_blocks[code_block.funcname].append(code_block)
        self.all_code_blocks.append(code_block)

    def add_code_blocks(self, code_blocks: List[CodeBlock]):
        for code_block in code_blocks:
            self.add_code_block(code_block)

    def find_function_by_name(self, funcname: str) -> List[CodeBlock]:
        if isinstance(funcname, dict):
            funcname = funcname.get('name')
        if not funcname:
            return []
        if funcname not in self.code_blocks:
            return []
        return self.code_blocks[funcname]
