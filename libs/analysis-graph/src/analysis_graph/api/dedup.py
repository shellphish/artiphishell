from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from analysis_graph import db
import pytz
import unionfind
from shellphish_crs_utils.organizers import get_organizer_eval_duplicate_positions

def connect_new_dedup_info_node_in_analysis_graph(
    *, # prevents positional arguments
    newly_added_dedup_info_node: Optional['OrganizerDedupInfoNode']=None,
) -> None:
    """
    Iterates through the analysis graph to find all dedup_info_nodes and connects this one to all "duplicate" nodes.

    Args:
        dedup_token (str): The deduplication token to connect.
    """
    assert newly_added_dedup_info_node is not None, "newly_added_dedup_info_node must be provided"

    nodes = OrganizerDedupInfoNode.nodes.filter(pdt_project_id__exact=newly_added_dedup_info_node.pdt_project_id)
    all_dedup_info_nodes = list(nodes)
    all_states = [{'crash_state': node.crash_state, 'instrumentation_key': node.instrumentation_key} for node in all_dedup_info_nodes]
    duplicates_positions = get_organizer_eval_duplicate_positions(
        organizer_eval=dict(crash_state=newly_added_dedup_info_node.crash_state, instrumentation_key=newly_added_dedup_info_node.instrumentation_key),
        existing_evals=all_states
    )
    with db.write_transaction:
        for dup_pos in duplicates_positions:
            dup_node = all_dedup_info_nodes[dup_pos]
            if dup_node == newly_added_dedup_info_node:
                continue
            newly_added_dedup_info_node.organizer_equivalent_nodes.connect(dup_node)
            dup_node.organizer_equivalent_nodes.connect(newly_added_dedup_info_node)
            dup_node.save()
    newly_added_dedup_info_node.last_scanned_for_deduplication = OrganizerDedupInfoNode.get_current_neo4j_time()
    newly_added_dedup_info_node.save()

@dataclass
class Cluster:
    pov_report_nodes: List['PoVReportNode']
    organizer_dedup_info_nodes: List['OrganizerDedupInfoNode']
    generated_patches: List['GeneratedPatch']

    def stats(self) -> str:
        """
        Returns a string representation of the cluster statistics.
        """
        return (
            f"Cluster("
            f"{len(self.pov_report_nodes)} PoVReportNodes, "
            f"{len(self.organizer_dedup_info_nodes)} OrganizerDedupInfoNodes, "
            f"{len(self.generated_patches)} GeneratedPatches."
            f")"
        )

def find_clusters(project_id: str) -> List[Cluster]:
    """
    Find clusters of deduplication nodes in the analysis graph.
    This function is a placeholder for future implementation.
    """
    # TODO(FINALDEPLOY)  decide if we want to keep this

    cutoff_time_patrol = datetime.now(tz=timezone.utc) - timedelta(minutes=15)
    print("Cutoff time for patrol:", cutoff_time_patrol)

    equivalent_edges = db.cypher_query(
        """
        MATCH (n:OrganizerDedupInfoNode)-[:ORGANIZER_EQUIVALENT_DEDUP_INFO]->(m:OrganizerDedupInfoNode)
        WHERE n.pdt_project_id = $project_id AND m.pdt_project_id = $project_id
        RETURN n.identifier, m.identifier
        """,
        {'project_id': project_id}
    )
    # equivalent_edges = []


    equivalent_due_to_mitigating_patch_edges = db.cypher_query(
        """
        MATCH (n:GeneratedPatch)-[:MITIGATED_POV_REPORT]->(m:PoVReportNode)
        WHERE NOT n.fail_functionality and n.pdt_project_id = $project_id AND m.pdt_project_id = $project_id and (
                (n.finished_patch_patrol or datetime(n.time_created) < datetime($cutoff_time_patrol))
            and
                (m.finished_pov_patrol or datetime(m.time_created) < datetime($cutoff_time_patrol))
        )
        RETURN n.patch_key, m.key
        """,
        {'project_id': project_id, 'cutoff_time_patrol': cutoff_time_patrol}
    )
    equivalent_due_to_pov_token_edges = db.cypher_query(
        """
        MATCH (n:PoVReportNode)-[:ORGANIZER_DEDUP_INFO]->(m:OrganizerDedupInfoNode)
        WHERE n.pdt_project_id = $project_id AND m.pdt_project_id = $project_id and (n.finished_pov_patrol or datetime(n.time_created) < datetime($cutoff_time_patrol))
        RETURN n.key, m.identifier
        """,
        {'project_id': project_id, 'cutoff_time_patrol': cutoff_time_patrol}
    )

    pov_report_nodes_by_id = {}
    dedup_info_nodes_by_id = {}
    generated_patches_by_id = {}

    uf = unionfind.UnionFind()
    for [n, m] in (equivalent_edges or [[]])[0]:
        uf.union(('ORGANIZER_DEDUP_INFO', n), ('ORGANIZER_DEDUP_INFO', m))
    for [n, m] in (equivalent_due_to_mitigating_patch_edges or [[]])[0]:
        uf.union(('GENERATED_PATCH', n), ('POV_REPORT', m))
    for n, m in (equivalent_due_to_pov_token_edges or [[]])[0]:
        uf.union(('POV_REPORT', n), ('ORGANIZER_DEDUP_INFO', m))

    all_pov_reports = PoVReportNode.nodes.filter(pdt_project_id=project_id).all()
    pov_report_nodes_by_id = {node.key: node for node in all_pov_reports}
    all_dedup_info_nodes = OrganizerDedupInfoNode.nodes.filter(pdt_project_id=project_id).all()
    dedup_info_nodes_by_id = {node.identifier: node for node in all_dedup_info_nodes}
    all_generated_patches = GeneratedPatch.nodes.filter(pdt_project_id=project_id).all()
    generated_patches_by_id = {node.patch_key: node for node in all_generated_patches}

    clusters = []
    components = list(uf.components())
    print(f"Found {len(components)} clusters in the analysis graph. (hello)")
    for i, clustered_nodes in enumerate(components):
        cluster = Cluster(
            pov_report_nodes=[],
            organizer_dedup_info_nodes=[],
            generated_patches=[]
        )
        print(f"Cluster {i + 1}/{len(components)} with {len(clustered_nodes)} nodes.")
        for type, id in clustered_nodes:
            if type == 'POV_REPORT':
                cluster.pov_report_nodes.append(pov_report_nodes_by_id[id])
            elif type == 'ORGANIZER_DEDUP_INFO':
                cluster.organizer_dedup_info_nodes.append(dedup_info_nodes_by_id[id])
            elif type == 'GENERATED_PATCH':
                cluster.generated_patches.append(generated_patches_by_id[id])
            else:
                raise ValueError(f"Unknown type {type} in union-find structure")
        if not cluster.pov_report_nodes:
            print(f"Skipping cluster {i + 1} as it has no PoVReportNodes: {cluster.stats()}")
            continue
        clusters.append(cluster)

    return clusters


from analysis_graph.models.crashes import OrganizerDedupInfoNode
from analysis_graph.models.crashes import GeneratedPatch, PoVReportNode