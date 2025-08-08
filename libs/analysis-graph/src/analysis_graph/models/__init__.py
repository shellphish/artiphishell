from datetime import datetime
import logging
import time
from typing import Tuple, TypeVar
from analysis_graph import db
from neomodel import StructuredNode, StringProperty, StructuredRel, DateTimeNeo4jFormatProperty, MultipleNodesReturned
import pytz
from shellphish_crs_utils import models
from shellphish_crs_utils.models.target import HarnessInfo

TShellphishBaseNode = TypeVar("TShellphishBaseNode", bound="ShellphishBaseNode")

log = logging.getLogger(__name__)

def current_neo4j_time() -> datetime:
    """
    Get the current time in UTC as a datetime object.
    This is used to ensure that all timestamps in the graph are in UTC.
    """
    return datetime.now(pytz.utc)

class TimedRelationEdgeModel(StructuredRel):
    created_at = DateTimeNeo4jFormatProperty(default=None)


class ShellphishBaseNode(StructuredNode):
    """
    Base class for all nodes in the graph. This is used to set up the neo4j connection and other common properties.
    """
    __abstract_node__ = True # stop these classes from showing up as node types in the graph

    @classmethod
    def get_or_create_node_reliable(cls, create_properties, get_properties=None, retries=3) -> TShellphishBaseNode:
        newly_created, node = cls.create_node_safely(
            get_properties=get_properties,
            create_properties=create_properties,
            retries=3
        )
        if newly_created:
            log.info(f"Created new {cls.__name__} node: {node}")
        else:
            log.info(f"Retrieved existing {cls.__name__} node: {node}")
        return node

    @classmethod
    def create_node_safely(cls, create_properties, get_properties=None, retries=3) -> Tuple[bool, TShellphishBaseNode]:
        if get_properties is None:
            get_properties = create_properties
        try:
            for i in range(retries):
                try:
                    with db.write_transaction:
                        try:
                            node = cls.nodes.get_or_none(**get_properties)
                        except MultipleNodesReturned as e:
                            # TODO: this is a hack to get around the fact that race conditions can cause multiple nodes to be created even with unique indexes :shrug:
                            log.error(f"Multiple nodes returned for {cls} for {get_properties=!r} {create_properties=!r}: {e}", exc_info=True)
                            node = cls.nodes.filter(**get_properties).first()
                        if node is None:
                            try:
                                node = cls.create(
                                    create_properties
                                )
                                assert node is not None, f"Failed to create {cls} for {get_properties=!r} {create_properties=!r} on attempt {i + 1}/{retries}"
                                return True, node[0]
                            except Exception as e:
                                #import traceback
                                #traceback.print_exc()  # Print the traceback to see where the error occurred
                                log.warning(f"Failed to create {cls} for {get_properties=!r} {create_properties=!r} on attempt {i + 1}/{retries}: {e}", exc_info=True)
                                # If we fail to create the node, we will just try again
                                if i < retries - 1:
                                    time.sleep(10*(i+1))
                                continue
                        else:
                            # We already registered this input before, so we can just return it
                            return False, node
                except Exception as e:
                    log.error(f"Error while creating {cls} for {get_properties=!r} {create_properties=!r}: {e}", exc_info=True)
                    if i < retries - 1:
                        time.sleep(10*(i+1))
                    continue
            else:
                log.error(f"Failed to create {cls} for {get_properties=!r} {create_properties=!r} after {retries} attempts. This should not happen.")
                
                # If we reach here, it means we failed to create the node after all retries
                # We can return None or raise an exception based on your preference
                # For now, we will just try one last time and then just return None
                return False, cls.nodes.get_or_none(**get_properties)
        except Exception as e:
            log.error(f"Error while creating {cls} for {get_properties=!r} {create_properties=!r}: {e}", exc_info=True)
            # If we reach here, it means we encountered an error while trying to create the node
            # We can return None or raise an exception based on your preference
            # For now, we will just return None
            return False, cls.nodes.get_or_none(**get_properties)


    @classmethod
    def get_current_neo4j_time(cls):
        return current_neo4j_time()

# set up the neo4j connection
class TargetNode(ShellphishBaseNode):
    __abstract_node__ = True # stop these classes from showing up as node types in the graph

    pdt_project_id = StringProperty(required=True)
    target_name = StringProperty(required=True)

class HarnessNode(TargetNode):
    __abstract_node__ = True # stop these classes from showing up as node types in the graph

    pdt_harness_info_id = StringProperty(required=True)
    harness_name = StringProperty(required=True)

    @staticmethod
    def extract_keys(harness_info_id: str, harness_info: HarnessInfo) -> dict:
        return {
            'pdt_project_id': harness_info.project_id,
            'target_name': harness_info.project_name,
            'pdt_harness_info_id': harness_info_id,
            'harness_name': harness_info.cp_harness_name,
        }
