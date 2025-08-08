from typing import List, Dict

from src.models.filter import FilterPass
from src.models.filter_result import FilterResult
from src.models.code_block import CodeBlock
from pathlib import Path

class SkipTestsFilter(FilterPass):
    name: str = "skip_tests_filter"
    enabled: bool = True

    __TEST_NAMES__ = {"test", "tests"}
    __TEST_SUFFIXES__ = ("test", "tests")
    
    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        """Apply the filter to code blocks"""
        results = []

        self.info(f"Applying SkipTests filter with mode!")

        for block in code_blocks:
            weight = 0.0
            metadata = {"is_test": False}
            
            filepath = Path(block.function_info.focus_repo_relative_path)

            filename = filepath.name.lower()
            parent_dir = filepath.parent.name.lower()
            file_stem = filepath.stem.lower()

            if filename in self.__TEST_NAMES__ or \
                parent_dir in self.__TEST_NAMES__ or \
                file_stem.endswith(self.__TEST_SUFFIXES__):
                
                metadata = {"is_test": True}

            result = FilterResult(weight=weight, metadata={"skip_test": metadata})
            block.filter_results[self.name] = result
            results.append(result)

        return results
