from typing import List, Dict

from src.models.filter import FilterPass
from src.models.filter_result import FilterResult
from src.models.code_block import CodeBlock

class DangerousFunctionsFilter(FilterPass):
    name: str = "dangerous_functions"
    enabled: bool = True
    config: Dict = {}

    language: str = "c"

    __DANGEROUS_FUNCTIONS__ = {
        'c':{
            "gets": 8.0,
            "strcpy": 8.0,
            "system": 8.0,
            "strcat": 4.0,
            "exec": 4.0,
            "free": 1.5,
            "fgets": .5,
            "memcpy": .1,
        },
        'c++':{
            "gets": 8.0,
            "strcpy": 8.0,
            "system": 8.0,
            "strcat": 4.0,
            "exec": 4.0,
            "free": 1.5,
            "fgets": .5,
            "memcpy": .1,
        }
    }
    __DANGEROUS_CODE_STRUCTURES__ = {
        'c':{
            "for ": .5, # Iteration over some data structure
            "for(": .5, # Iteration over some data structure
            "while ": .3,
            "while(": .3,
        },
        'c++':{
            "for ": .5, # Iteration over some data structure
            "for (": .5, # Iteration over some data structure
            "while ": .3,
            "while(": .3,
        }
    }

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:

        out = []

        for code_block in code_blocks:
            weight = 0.0
            metadata = {}
            for dangerous_function in self.__DANGEROUS_FUNCTIONS__.get(self.language,{}):
                if not (
                    dangerous_function in code_block.function_info.func_calls_in_func_with_fullname
                ):
                    continue

                weight += self.__DANGEROUS_FUNCTIONS__.get(self.language,{})[dangerous_function]
                dl = metadata.get("potentially_dangerous_functions", [])
                dl.append(dangerous_function)
                metadata["potentially_dangerous_functions"] = dl

            code = code_block.function_info.code.lower()
            for dangerous_code_structure in self.__DANGEROUS_CODE_STRUCTURES__.get(self.language,{}):
                if not (
                    dangerous_code_structure in code
                ):
                    continue

                dl = metadata.get("potentially_dangerous_code", [])
                dl.append(dangerous_code_structure)
                metadata["potentially_dangerous_code"] = dl

                weight += self.__DANGEROUS_CODE_STRUCTURES__.get(self.language,{})[dangerous_code_structure]

            res = FilterResult(weight=weight, metadata=metadata)
            code_block.filter_results[self.name] = res
            out.append(res)

        return out
