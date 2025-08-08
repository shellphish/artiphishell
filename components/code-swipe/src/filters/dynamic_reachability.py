from collections import defaultdict
from typing import List, Optional, Set, Dict, Any
import logging

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

try:
    import analysis_graph
    from analysis_graph import CFGFunction
    from neomodel import db, config, NeomodelException
except Exception as e:
    import traceback
    traceback.print_exc()
    analysis_graph = None

class DynamicReachabilityFilter(FilterPass):
    name: str = "dynamic_reachability"
    enabled: bool = True
    config: Dict = {}

    matches_by_func_identifier: Dict[FUNCTION_INDEX_KEY, List] = Field(default_factory=dict)

    @time_it
    def get_covered_functions(self):
        if analysis_graph is None:
            return

        query = """
MATCH (f:CFGFunction)
WHERE EXISTS { MATCH (:HarnessInputNone)-[:COVERS]->(f) }
   OR EXISTS { MATCH (:Grammar)-[:COVERS]->(f) }
CALL {
  WITH f
  MATCH (src)-[:COVERS]->(f)
  WHERE src:HarnessInputNode OR src:Grammar
  WITH src
  ORDER BY CASE WHEN src:HarnessInputNone THEN src.first_discovered_timestamp
                ELSE datetime('1970-01-01T00:00:00Z') END
  RETURN
    CASE WHEN src:HarnessInputNode THEN src.harness_name END AS harness_name,
    CASE WHEN src:Grammar     THEN src              END AS grammar
  LIMIT 1
}
RETURN f, harness_name, grammar
        """

        rows, _ = db.cypher_query(query)


        for func_node, harness_name, grammar_node in rows:
            function = analysis_graph.CFGFunction.inflate(func_node)

            metadata = {}
            # You can inspect labels to decide how to inflate the example
            if harness_name:
                metadata["harness_name"] = harness_name
            else:
                metadata["grammar"] = analysis_graph.models.grammars.Grammar.inflate(grammar_node)

            identifier: FUNCTION_INDEX_KEY = function.identifier

            if identifier not in self.matches_by_func_identifier:
                self.matches_by_func_identifier[identifier] = []

            self.matches_by_func_identifier[identifier].append((function, metadata))

        self.info(f"Found {len(self.matches_by_func_identifier)} functions with dynamic reachability")



    def pre_process_project(self, project: OSSFuzzProject, code_registry: CodeRegistry, metadata: Dict[str, Any]) -> None:
        if analysis_graph is None:
            self.warn("analysis_graph not found, dynamic reachability disabled")
            return

        self.info("Starting dynamic reachability analysis")

        self.get_covered_functions()

        # Get all covered functions from the analysis graph

    def apply(self, code_blocks: List[CodeBlock]) -> List[FilterResult]:
        out = []

        # We have to do this in reverse because the coverage identifiers may be in the wrong location and then we need to do "resolve_source_location" to handle that
        # but its too expensive to run on every coverage identifier
        # so we try to match any we can first and then the rest we try to resolveo

        code_block_map = {code_block.function_key: code_block for code_block in code_blocks}

        resolver: Optional[FunctionResolver] = FunctionIndexIngester.__RESOLVER__

        to_resolve = []

        # Find any keys that need to be translated to the focus repo
        for ident, hit in self.matches_by_func_identifier.items():
            found_block = None
            if ident in code_block_map:
                pass
            elif resolver is None:
                self.warn(f"No resolver found, skipping {ident} which cannot be resolved")
            else:
                to_resolve.append(ident)

        resolved = {}

        if to_resolve and resolver:
            resolved, missing = resolver.find_matching_indices(to_resolve)
            self.warn(f"Resolved {len(resolved)}/{len(to_resolve)} functions")

        found_blocks = {}

        for ident, hits in self.matches_by_func_identifier.items():
            if len(hits) == 1:
                metadata = hits[0]
            else:
                metadata = {}

                # TODO better handle multiple harnesses reachable to the same function?
                for hit, hit_metadata in hits:
                    metadata.update(hit_metadata)

            found_block = None
            if ident in code_block_map:
                found_block = code_block_map[ident]
            elif ident in resolved:
                new_ident = resolved[ident]
                if new_ident in code_block_map:
                    found_block = code_block_map[new_ident]

            if found_block:
                found_blocks[found_block.function_key] = metadata

        out = []

        for code_block in code_blocks:
            if code_block.function_key in found_blocks:
                metadata={
                    "reachable": True,
                    "has_harness_input": True,
                }

                _, hit_metadata = found_blocks[code_block.function_key]
                if hit_metadata.get("harness_name"):
                    metadata["harness_name"] = hit_metadata["harness_name"]

                res = FilterResult(
                    weight=1.0,
                    metadata=metadata,
                )
            else:
                res = FilterResult(weight=0.0)
            code_block.filter_results[self.name] = res
            out.append(res)

        return out