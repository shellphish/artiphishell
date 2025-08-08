
import hashlib
import logging 

from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from analysis_graph.models.grammars import Grammar
from pydantic import BaseModel, Field
from neomodel import db

from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.models.target import HarnessInfo
from analysis_graph.models.harness_inputs import HarnessInputNode, HarnessNode
from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.target_stats import CoveragePerformanceStats
from analysis_graph.models.coverage import CoveredFunctionLine

logger = logging.getLogger("analysis_graph.api.dynamic_coverage")
logger.setLevel(logging.INFO)

def update_coverage_stats(harness_info_id: str, harness_info: HarnessInfo, last_100_avg, overall_avg):
    cov_stats_node = CoveragePerformanceStats.get_or_create({
        'pdt_project_id': harness_info.project_id,
        'target_name': harness_info.project_name,
        'pdt_harness_info_id': harness_info_id,
        'harness_name': harness_info.cp_harness_name,
    })[0]

    assert type(last_100_avg) is float
    assert type(overall_avg) is float
    cov_stats_node.last_100_inputs_average_tracing_time_millis.append(last_100_avg)
    cov_stats_node.overall_average_tracing_time_millis.append(overall_avg)
    cov_stats_node.updates.append(datetime.now(tz=timezone.utc))
    cov_stats_node.save()

def register_harness_input_function_coverage(harness_input_id: str, harness_info_id: str, harness_info: HarnessInfo, input: bytes, crashing: bool, cov: FunctionCoverageMap):

    covered_lines = {(k, l.line_number) for k in cov.keys() for l in cov[k] if l.count_covered}
    covered_func_keys = {x[0] for x in covered_lines}

    # The harness_info_id is a hash of the harness_info_id and its content
    # This ensures that we can uniquely identify the harness_info for this input
    harness_input_identifier = HarnessInputNode.compute_identifier(harness_info_id=harness_info_id, harness_info=harness_info, content=input, crashing=crashing)

    
    this_thread_created_this_node = False
    harness_input_node = None
    try:
        this_thread_created_this_node, harness_input_node = HarnessInputNode.create_node(
            harness_info_id=harness_info_id,
            harness_info=harness_info,  # This is the actual HarnessInfo object
            content=input,  # The actual input bytes
            crashing=crashing,  # Whether this input caused a crash or not
        )
    
    except Exception as e:
            harness_input_node = None

    # At this point, it MUST exists
    if harness_input_node is None:
        harness_input_node = HarnessInputNode.nodes.get_or_none(identifier=harness_input_id)
    
    if not this_thread_created_this_node:
        # If another thred created it in the meantime, we let that thread finish and we return.
        return harness_input_node
    
    assert harness_input_node is not None, f"Failed to create or find HarnessInputNode for identifier {harness_input_id}. This should not happen."

    cfg_function = None
    for k in covered_func_keys:
        try:
            with db.write_transaction as tx:
                cfg_function = CFGFunction.nodes.get_or_none(identifier=k)
                if cfg_function is None:
                    # We have to create it!
                    try:
                        cfg_function = CFGFunction.create(
                            dict(identifier=k), relationship=[(harness_input_node.covered_functions, "COVERS")]
                        )[0]
                        cfg_function.save()
                    except Exception as e:
                        logger.warning("********************************************************")
                        logger.warning(e)
                        logger.warning("********************************************************")
                        # All right, somebody push this function in the meantime, we can just ignore this
                        # NOTE: this transaction is automatically rolled back from neomodel
                        # NOTE: you cannot use the context of this transaction to retry the creation of the node
                        #       it will throw an error!
                        cfg_function = None
        except Exception as e:
            logger.warning("********************************************************")
            logger.warning(e)
            logger.warning("********************************************************")
            cfg_function = None

        try:
            with db.write_transaction as tx:
                if cfg_function is None:
                    # If we got an UniqueProperty error,
                    # we need to fetch the node again...
                    cfg_function = CFGFunction.nodes.get_or_none(identifier=k)

                # NOTE: using raw query because neomodel is dumb and creates a cartesian product
                #       if I don't specify myself the ids.
                query = f"""
                MATCH (hi:HarnessInputNode)
                WHERE hi.identifier = "{harness_input_node.identifier}"
                MATCH (cf:CFGFunction)
                WHERE cf.identifier = "{k}"
                MERGE (hi)-[r:COVERS]->(cf)
                RETURN r
                """
                
                assert(cfg_function is not None), f"Failed to find CFGFunction for identifier {k}. This should not happen."

                db.cypher_query(query)

                # if not relationship_created:
                #     raise Exception(f"Failed to create relationship between HarnessInputNode {harness_input_node.identifier} and CFGFunction {k}. This should not happen.")
                harness_input_node.save()

        except Exception as e:
            logger.warning("********************************************************")
            logger.warning(e)
            logger.warning("********************************************************")
            pass

    if cfg_function is None:
        # Refresh the object in case we were not the one creating it!
        harness_input_node = HarnessInputNode.nodes.get_or_none(identifier=harness_input_id)
    
    return harness_input_node


def register_harness_input_file_coverage(harness_input_id: str, harness_info_id: str, harness_info: HarnessInfo, input: bytes, crashing: bool, function_resolver: FunctionResolver, cov: FileCoverageMap):
    function_coverage = function_resolver.get_function_coverage(cov)
    return register_harness_input_function_coverage(harness_input_id, harness_info_id, harness_info, input, crashing, function_coverage)


def register_grammar_function_coverage(harness_info_id: str, harness_info: HarnessInfo, grammar_type: str, grammar: str, cov: FunctionCoverageMap):
    grammar_node = Grammar.ensure_exists(grammar_type, grammar)

    covered_lines = {(k, l.line_number) for k in cov.keys() for l in cov[k] if l.count_covered}
    covered_func_keys = {x[0] for x in covered_lines}

    cfg_function = None
    
    try:
        # First, upload the CFGFunction nodes if they do not exist (this races with covguy)
        for k in covered_func_keys:
            try:
                with db.write_transaction as tx:
                    cfg_function = CFGFunction.nodes.get_or_none(identifier=k)
                    if cfg_function is None:
                        # We have to create it!
                        try:
                            cfg_function = CFGFunction.create(
                                dict(identifier=k), relationship=[(grammar_node.covered_functions, "COVERS")]
                            )[0]
                            cfg_function.save()
                        except Exception as e:
                            logger.warning("********************************************************")
                            logger.warning(e)
                            logger.warning("********************************************************")
                            # All right, somebody push this function in the meantime, we can just ignore this
                            # NOTE: this transaction is automatically rolled back from neomodel
                            # NOTE: you cannot use the context of this transaction to retry the creation of the node
                            #       it will throw an error!
                            cfg_function = None
            except Exception as e:
                logger.warning("********************************************************")
                logger.warning(e)
                logger.warning("********************************************************")
                cfg_function = None

            # Now we want to registe the grammar -> function relationship
            try:
                with db.write_transaction as tx:
                    if cfg_function is None:
                        # If we got an UniqueProperty error,
                        # we need to fetch the node again...
                        cfg_function = CFGFunction.nodes.get_or_none(identifier=k)

                    # NOTE: using raw query because neomodel is dumb and creates a cartesian product
                    #       if I don't specify myself the ids.
                    query = f"""
                    MATCH (g:Grammar)
                    WHERE g.hash = "{grammar_node.hash}"
                    MATCH (cf:CFGFunction)
                    WHERE cf.identifier = "{k}"
                    MERGE (g)-[r:COVERS]->(cf)
                    RETURN r
                    """
                    
                    assert(cfg_function is not None), f"Failed to find CFGFunction for identifier {k}. This should not happen."

                    db.cypher_query(query)

                    # if not relationship_created:
                    #     raise Exception(f"Failed to create relationship between Grammar {grammar_node.hash} and CFGFunction {k}. This should not happen.")
                    grammar_node.save()
            except Exception as e:
                logger.error("********************************************************")
                logger.error(e)
                logger.error("********************************************************")
                logger.error("Failed to create relationship between Grammar and CFGFunction...")
                return None
        
        # # Now, we want to register the CoveredFunctionLine
        # for k, lno in covered_lines:
        #     try:
        #         with db.write_transaction as tx:
        #             covered_line = CoveredFunctionLine.nodes.get_or_none(identifier=f"{k}:::{lno}")
        #             if covered_line is None:
        #                 # In this case we want to create it!
        #                 try:
        #                     covered_line = CoveredFunctionLine.create(
        #                         dict(**HarnessNode.extract_keys(harness_info_id, harness_info), function_index_key=k, line_number=lno, identifier=f"{k}:::{lno}"),
        #                         relationship=[(grammar_node.covered_lines, "COVERS")]
        #                     )[0]
        #                     covered_line.save()
        #                 except Exception as e:
        #                     logger.warning("********************************************************")
        #                     logger.warning(e)
        #                     logger.warning("********************************************************")
        #                     # All right, somebody push this covered line in the meantime, we can just ignore this
        #                     # NOTE: this transaction is automatically rolled back from neomodel
        #                     # NOTE: you cannot use the context of this transaction to retry the creation of the node
        #                     #       it will throw an error!
        #                     covered_line = None
        #     except Exception as e:
        #         logger.warning("********************************************************")
        #         logger.warning(e)
        #         logger.warning("********************************************************")
        #         covered_line = None

        #     # Now we want to create the relationship
        #     try:
        #         with db.write_transaction as tx:
        #             if covered_line is None:
        #                 # If we got an UniqueProperty error,
        #                 # we need to fetch the node again...
        #                 covered_line = CoveredFunctionLine.nodes.get_or_none(identifier=f"{k}:::{lno}")

        #             # NOTE: using raw query because neomodel is dumb and creates a cartesian product
        #             #       if I don't specify myself the ids.
        #             query = f"""
        #             MATCH (g:Grammar)
        #             WHERE g.hash = "{grammar_node.hash}"
        #             MATCH (cfl:CoveredFunctionLine)
        #             WHERE cfl.identifier = "{k}:::{lno}"
        #             MERGE (g)-[r:COVERS]->(cfl)
        #             RETURN r
        #             """
                    
        #             assert(covered_line is not None), f"Failed to find CoveredFunctionLine for identifier {k}:::{lno}. This should not happen."

        #             db.cypher_query(query)

        #             # if not relationship_created:
        #             #     raise Exception(f"Failed to create relationship between Grammar {grammar_node.hash} and CoveredFunctionLine {k}:::{lno}. This should not happen.")
        #             grammar_node.save()
        #     except Exception as e:
        #         logger.error("********************************************************")
        #         logger.error(e)
        #         logger.error("********************************************************")
        #         return None
    except Exception as e:
        logger.error("[BAD][BAD] Ping @Lukas, @Fabio, @Zebaztian [BAD][BAD]")
        logger.error("********************************************************")
        logger.error(e)
        logger.error("********************************************************")
        logger.error("[BAD][BAD] Ping @Lukas, @Fabio, @Zebaztian [BAD][BAD]")
        return None

    return grammar_node

def register_grammar_file_coverage(harness_info_id: str, harness_info: HarnessInfo, grammar_type: str, grammar: str, function_resolver: FunctionResolver, cov: FileCoverageMap):
    function_coverage = function_resolver.get_function_coverage(cov)
    return register_grammar_function_coverage(harness_info_id, harness_info, grammar_type, grammar, function_coverage)

def get_one_covering_grammar_for_functions(covered_functions: List[FUNCTION_INDEX_KEY]) -> Tuple[List[Grammar], Set[CFGFunction]]:
    # This function should return one grammar for each function in covered_functions
    # If there are multiple grammars covering the same function, we greedily return the one that covers the most
    try:
        result = db.cypher_query("""
        MATCH (g:Grammar)-[:COVERS]->(cf:CFGFunction)
        WHERE cf.identifier IN $covered_functions
        RETURN g, collect(cf.identifier) AS covered_functions
        """, {"covered_functions": covered_functions})
    except Exception as e:
        logger.error("********************************************************")
        logger.error(e)
        logger.error("********************************************************")
        return [], set()

    grammars = []
    newly_covered_funcs = set()
    for record in result[0]:
        try:
            grammar_node = Grammar.inflate(record[0])
            cur_covered_funcs = record[1]
            # if the grammar covers any function that is not already covered, we add it
            if any(f not in newly_covered_funcs for f in cur_covered_funcs):
                grammars.append(grammar_node)
                newly_covered_funcs.update(cur_covered_funcs)
        except Exception as e:
            logger.error("********************************************************")
            logger.error(e)
            logger.error("********************************************************")
            continue
    return grammars, newly_covered_funcs

def get_functions_harness_reachability(project_id: str, harness_name: str) -> Dict[CFGFunction, Set[str]]:
    """
    Return for all functions in the project the harnesses that can reach them.
    """
    try:
        result = db.cypher_query("""
        MATCH (hi:HarnessInputNode)-[:COVERS]->(cf:CFGFunction)
        WHERE hi.harness_name = $harness_name and hi.pdt_project_id = $project_id
        RETURN cf, collect(hi.harness_name) AS harness_names
        """, {"harness_name": harness_name, "project_id": project_id})
    except Exception as e:
        logger.error("********************************************************")
        logger.error(e)
        logger.error("********************************************************")
        return {}

    functions = {}
    for record in result[0]:
        try:
            cfg_function = CFGFunction.inflate(record[0])
            harness_names = record[1]
            # If the function is covered by inputs from multiple harnesses, we skip it
            if len(set(harness_names)) == 1 and harness_names[0] == harness_name:
                functions[cfg_function] = set(harness_names)
        except Exception as e:
            logger.error("********************************************************")
            logger.error(e)
            logger.error("********************************************************")
            continue
    return functions