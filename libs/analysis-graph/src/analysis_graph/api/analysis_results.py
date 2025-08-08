
import hashlib

from datetime import datetime, timezone
from typing import Dict, List, Optional
from analysis_graph.models.grammars import Grammar
from pydantic import BaseModel, Field
from neomodel import db

from shellphish_crs_utils.function_resolver import FunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.coverage import FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.models.target import HarnessInfo
from analysis_graph.models.cfg import CFGFunction

from analysis_graph.models.cfg import DeltaDiffMode

def add_delta_info(project_id: str, git_diff: str, boundary_change: List[FUNCTION_INDEX_KEY], function_change: List[FUNCTION_INDEX_KEY]):
    """
    Register a delta info in the database.
    :param project_id: The project ID
    :param git_diff: The git diff
    :param boundary_change: A list of function keys that have changed
    :param function_change: A list of function keys that have changed
    """

    # Add the delta info to the database
    with db.write_transaction as tx:
        deltaDiffNode = DeltaDiffMode.create(
            dict(project_id=project_id, git_diff=git_diff)
        )
        deltaDiffNode[0].save()
    
    try:
        # Connect the DeltaDiffNode to the CFGFunction nodes
        with db.write_transaction as tx:
            
            delta_info = DeltaDiffMode.nodes.get_or_none(project_id=project_id)

            for k in function_change:
                cfg_function = CFGFunction.nodes.get_or_none(identifier=k)
                if cfg_function:
                    # Connect the DeltaDiffNode to the CFGFunction
                    delta_info.function_change.connect(cfg_function)
        
            for k in boundary_change:
                cfg_function = CFGFunction.nodes.get_or_none(identifier=k)
                if cfg_function:
                    # Connect the DeltaDiffNode to the CFGFunction
                    delta_info.boundary_change.connect(cfg_function)
        
            delta_info.save()

    except Exception as e:
        print(f"Error wile uploading diff data to the analysis graph: {e}...")
        return None

    return delta_info