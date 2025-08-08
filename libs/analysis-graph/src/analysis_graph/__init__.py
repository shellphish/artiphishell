import os
import logging
from neomodel import config, install_labels, db

config.DATABASE_URL = os.environ.get('ANALYSIS_GRAPH_BOLT_URL', 'bolt://neo4j:helloworldpdt@aixcc-analysis-graph:7687')
if os.getenv('CRS_TASK_NUM'):
    config.DATABASE_URL = config.DATABASE_URL.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
else:
    if 'TASKNUM' in config.DATABASE_URL:
        raise ValueError("Env CRS_TASK_NUM is not set but ANALYSIS_GRAPH_BOLT_URL contains TASKNUM")

from analysis_graph import models
from analysis_graph.models.cfg import CFGFunction, DeltaDiffMode
from analysis_graph.models.harness_inputs import HarnessInputNode
from analysis_graph.models.sarif import SARIFreport
from analysis_graph.models.crashes import OrganizerDedupInfoNode, PoVReportNode, GeneratedPatch
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error

log = logging.getLogger("analysis_graph")

def install_all_labels():
    for i in range(5):
        try:
            db.install_all_labels()
            break
        except Exception as e:
            log.error(f"Attempt {i+1} to install labels failed: {e}")
            if i == 4 and artiphishell_should_fail_on_error():
                raise

def wipe_all_nodes_for_project(project_id: str):
    """
    Wipe all nodes for a given project ID.
    Args:
        project_id (str): The project ID to wipe nodes for.
    """
    log.info(f"Wiping all nodes for project {project_id}")

    for node_type in [HarnessInputNode, OrganizerDedupInfoNode, PoVReportNode, GeneratedPatch, DeltaDiffMode]:
        print(f"Wiping nodes of type {node_type.__name__} for project {project_id}")
        try:
            db.cypher_query(
                f"MATCH (n:{node_type.__name__})" + " WHERE n.project_id = $project_id OR n.pdt_project_id = $project_id CALL (n) { WITH n DETACH DELETE n } IN TRANSACTIONS OF 1000 ROWS",
                {'project_id': project_id}
            )
        except Exception as e:
            print("Hmm, the part deletion didn't work, try one more time with fewer records")
            print(e)
            try:
                db.cypher_query(
                    f"MATCH (n:{node_type.__name__})" + " WHERE n.project_id = $project_id OR n.pdt_project_id = $project_id CALL (n) { WITH n DETACH DELETE n } IN TRANSACTIONS OF 100 ROWS",
                    {'project_id': project_id}
                )
            except Exception as e:
                print("Hmm, the part deletion didn't work, yolo?")
                print(e)
    db.cypher_query(
        "MATCH (n) WHERE n.project_id = $project_id OR n.pdt_project_id = $project_id CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS",
        {'project_id': project_id}
    )

def wipe_all_nodes_cli():
    """
    Command line interface to wipe all nodes.
    """
    import argparse
    parser = argparse.ArgumentParser(description="Wipe all nodes in the analysis graph for a given project ID.")
    parser.add_argument('project_id', type=str, help='The project ID to wipe nodes for.')
    args = parser.parse_args()
    wipe_all_nodes_for_project(args.project_id)

def get_analysis_graph_info_cli():
    """
    Command line interface to get analysis graph info.
    """
    # first, the the number of nodes for each label
    result = db.cypher_query("MATCH (n) RETURN labels(n) AS labels, count(n) AS count")
    print("Analysis Graph Info:")
    for labels, count in result[0]:
        print(f"Labels: {labels}, Count: {count}")

    # then, return the number of edges for each label
    result = db.cypher_query("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count")
    print("Edges Info:")
    for edge_type, count in result[0]:
        print(f"Edge Type: {edge_type}, Count: {count}")