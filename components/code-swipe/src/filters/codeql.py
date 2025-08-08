import yaml
import json
from collections import defaultdict
from typing import List, Optional, Set, Dict, Any
import logging
from pathlib import Path

from pydantic import Field
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from src.input.code_registry import CodeRegistry
from src.models.code_block import CodeBlock
from src.models.filter import FilterPass, FilterResult
from src.models import BaseObject
from src.common.util import time_it
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models.symbols import SourceLocation

from src.input.ingester import FunctionIndexIngester

class CodeQLHit(BaseObject):
    additionalInfo: Dict = Field(default_factory=dict)
    desc: str
    startLine: str
    endLine: str
    vuln_type: str = Field(alias="type")
    query: str
    location: dict

class CodeQLFunction(BaseObject):
    id: str
    name: Optional[str] = None
    src: Optional[str] = None
    location: Dict = Field(default_factory=dict)
    hits: Optional[List[CodeQLHit]] = None

class CodeQLReport(BaseObject):
    functions: Dict[str, List[CodeQLFunction]] = Field(default_factory=dict)

class CodeQLFilter(FilterPass):
    name: str = "codeql"
    enabled: bool = True
    config: Dict = {}
    language: str = "c"  # Default, can be set to "jvm" for Java
    codeql_report: CodeQLReport


    @classmethod
    @time_it
    def from_report(cls, report_path: Path, language: str = None) -> "CodeQLFilter":
        report_path = Path(report_path)
        cls.info_static(f"Loading CodeQL report from {report_path}")
        with open(report_path, "r") as f:
            all_funcs = yaml.load(f, Loader=yaml.CLoader)

        report = CodeQLReport()

        for func in all_funcs:
            try:
                func_obj = CodeQLFunction(**func)
            except Exception as e:
                cls.info_static(f"Error loading CodeQL function: {json.dumps(func, indent=2)}")
                cls.warn_static(f"Error loading CodeQL function: {e}")
                continue
            if not func_obj.hits or len(func_obj.hits) == 0:
                continue
            key = func_obj.name or func_obj.location.get("function_name")
            # there might be multiple functions with the same name
            l = report.functions.get(key, [])
            l.append(func_obj)
            report.functions[key] = l

        cls.info_static(f"Loaded {len(report.functions)} CodeQL functions (language: {language})")
        return cls(codeql_report=report, language=language)

    @classmethod
    def get_vuln_weights(cls, language: str) -> Dict[str, int]:
        """Get vulnerability weights based on language"""
        java_vuln_weights =  {
            "CommandInjection": 5,
            "Deserialization": 5,
            "PathTraversal": 3,
            "ReflectionCallInjection": 4,
            "RegexInjection": 4,
            "ServerSideRequestForgery": 5,
            "XXEInjection": 5,
            "SqlInjection": 4,
            "XPathInjection": 4,
            "ScriptEngineInjection": 4,
            "ExpressionLanguage": 4,
            "LdapInjection": 4,
            "NamingContextLookup": 4,
        }

        c_vuln_weights = {
            "nullptr": 1,           # This query is REALLY noisy, so we give it a low weight
            "alloc_const": 2,
            "alloc_const_df": 2,
            "alloc_then_arr": 2,
            "alloc_then_loop": 2,
            "alloc_then_mem": 2,
            "alloc_checks": 2,
            "nullptr.gut": 3,
            "nullptr.naive": 3,
            "stack_buf_loop": 3,
            "stack_const_alloc": 3,
            "double_free": 5,
            "uaf": 5,
        }

        if language.lower() == "jvm":
            return java_vuln_weights
        elif language.lower() in ["c", "c++"]:
            return c_vuln_weights
        else:
            return {}

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        out = []
        self.info(f"Found {len(self.codeql_report.functions)} CodeQL functions")

        found_matches = set()

        found_queries = defaultdict(int)
        unknown_types = set()
        # Select the correct weights dict based on language
        vuln_type_weights = CodeQLFilter.get_vuln_weights(self.language)

        self.info(f"Available CodeQL function keys: {list(self.codeql_report.functions.keys())}")

        for code_block in code_blocks:
            key = code_block.function_key
            func_name = code_block.funcname
            file_name = code_block.function_info.filename
            full_file_path = key[:key.find(":")]

            matches = self.codeql_report.functions.get(func_name)
            if not matches:
                func_name = code_block.function_info.full_funcname
                matches = self.codeql_report.functions.get(func_name)

            weight = 0.0
            metadata = {}

            found_match = None

            if matches:
                # TODO make sure this is the correct one...
                if len(matches) > 1:
                    possible_match = None
                    for i, m in enumerate(matches):
                        m_fname = m.location.get("file_name")
                        if m_fname != file_name:
                            continue
                        possible_match = (i, m)
                        full_path = m.location.get("full_file_path")
                        if full_path != full_file_path:
                            continue
                        break

                    if possible_match:
                        i, found_match = possible_match

                else:
                    m_fname = matches[0].location.get("file_name")
                    if m_fname == file_name:
                        # TODO should we handle amalgamated files?
                        found_match = matches[0]

            if found_match:
                found_match_full_path = found_match.location.get("full_file_path")
                if found_match_full_path != full_file_path:
                    self.warn(f"📄 CodeQL hit for {found_match_full_path}:{func_name} but not {full_file_path}:{func_name}, assuming same function")
                fmk = f'{found_match_full_path}:{func_name}'
                if fmk in found_matches:
                    self.warn(f"♟️ CodeQL match for {fmk} was already used")
                found_matches.add(fmk)

                codeql_hits = {}
                hit_queries = set()
                for h in found_match.hits:
                    if h.query in hit_queries:
                        continue
                    hit_queries.add(h.query)
                    vuln_type = getattr(h, "vuln_type", None)
                    weight_add = vuln_type_weights.get(vuln_type, 1.0) if vuln_type else 1.0
                    if vuln_type and vuln_type not in vuln_type_weights:
                        unknown_types.add(vuln_type)
                    weight += weight_add

                    codeql_hits[h.query] = vuln_type
                    found_queries[h.query] += 1
                metadata["codeql_hits"] = codeql_hits
            else:
                self.info(f"  No matching CodeQL function found for this code block.")
            res = FilterResult(weight=weight, metadata=metadata)
            code_block.filter_results[self.name] = res
            out.append(res)

        if unknown_types:
            self.warn(f"Unknown vuln types found: {unknown_types}")
        self.info(f"Found {len(found_matches)}/{len(self.codeql_report.functions)} CodeQL matches")
        self.info(f"All queries: {found_queries}")

        return out
