
import hashlib
import logging
import json
import uuid
from typing import List, Optional, Tuple, Union
from neomodel import UniqueIdProperty, Traversal, StructuredNode, StructuredRel, StringProperty, IntegerProperty, \
    RelationshipTo, RelationshipFrom, Relationship, JSONProperty, BooleanProperty, ArrayProperty, \
    DateTimeNeo4jFormatProperty, FloatProperty
from analysis_graph import db
from analysis_graph.models import ShellphishBaseNode, TimedRelationEdgeModel
from analysis_graph.models.sarif import SARIFreport
from analysis_graph.models.harness_inputs import HarnessInputNode
import pytz
from shellphish_crs_utils.models.crs_reports import DedupInfoKind, POIReport as CRSUtilsPOIReport, DedupInfo as CRSUtilsDedupInfo, PoVReport as CRSUtilsPOVReport
from shellphish_crs_utils.models.organizer_evaluation import OrganizerCrashEvaluation
from crs_telemetry.utils import (
    get_otel_tracer,
)
from datetime import datetime, timezone

from shellphish_crs_utils.models.target import PDT_ID



telemetry_tracer = get_otel_tracer()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEDUP_INFO_KINDS = {v.value: v.value for v in DedupInfoKind}

class DedupTokenNode(ShellphishBaseNode):
    kind = StringProperty(choices=dict(DEDUP_INFO_KINDS), required=True)
    reason = StringProperty(required=True)
    identifier = StringProperty(required=True)

    first_discovered = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc))  # timestamp of when the token was first discovered
    last_scanned_for_deduplication = DateTimeNeo4jFormatProperty(default=None)  # timestamp of when the token was last scanned for deduplication

class OrganizerCrashEvaluationNode(ShellphishBaseNode):
    """
    A node that represents a crash evaluation by the organizers.
    """
    significance = IntegerProperty(required=True)
    code_label = StringProperty(required=True)
    significance_message = StringProperty(required=True)
    crash_state = StringProperty(required=True)
    instrumentation_key = StringProperty(required=True)

    first_discovered = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc))  # timestamp of when the evaluation was first discovered
    last_scanned_for_deduplication = DateTimeNeo4jFormatProperty(default=None)  # timestamp of when the evaluation was last scanned for deduplication

    last_equivalence_checked = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc))  # timestamp of when the equivalence was last checked
    equivalent_crash_evaluation_nodes = Relationship('OrganizerCrashEvaluationNode', 'EQUIVALENT_CRASH_EVALUATION')

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.OrganizerCrashEvaluationNode.from_crs_utils_evaluation")
    def from_crs_utils_evaluation(cls, evaluation: 'OrganizerCrashEvaluation') -> 'OrganizerCrashEvaluationNode':
        """
        Create an OrganizerCrashEvaluationNode object from a CRSUtils evaluation.
        :param evaluation: The CRSUtils evaluation object.
        :return: An OrganizerCrashEvaluationNode object.
        """
        self = cls.get_or_create_node_reliable({
            'significance': evaluation.significance.value,
            'code_label': evaluation.code_label,
            'significance_message': evaluation.significance_message,
            'crash_state': evaluation.crash_state,
            'instrumentation_key': evaluation.instrumentation_key
        })
        self.save()
        return self

# class DedupInfoNode(ShellphishBaseNode):
#     identifier = StringProperty(unique_index=True, required=True)
#     canonical_representation = StringProperty(unique_index=True, required=True)
#     pdt_project_id = StringProperty(required=True)
#     kind = StringProperty(choices=dict(DEDUP_INFO_KINDS), required=True)
#     content = JSONProperty(required=True)

#     organizer_crash_state = StringProperty(required=True)  # The crash state as determined by the organizers
#     organizer_instrumentation_key = StringProperty()

#     first_discovered = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc)) # timestamp of when the dedup info was first discovered
#     last_scanned_for_deduplication = DateTimeNeo4jFormatProperty(default=None) # timestamp of when the dedup info was last scanned for deduplication

#     consistent_sanitizers = ArrayProperty(StringProperty())
#     tokens = RelationshipTo('DedupTokenNode', 'DEDUP_TOKEN')
#     generated_patches = RelationshipFrom('GeneratedPatch', 'GENERATED_PATCH_FOR')
#     pov_reports = RelationshipFrom('PoVReportNode', 'DEDUP_INFO')

#     organizer_equivalent_nodes = Relationship('DedupInfoNode', 'ORGANIZER_EQUIVALENT_DEDUP_INFO')
#     def maybe_recompute_duplicates(self, force_update=False):
#         """
#         Recompute the duplicates of this node in the analysis graph.
#         This is used to ensure that the duplicates are up-to-date.
#         """

#         from analysis_graph.api.dedup import connect_new_dedup_info_node_in_analysis_graph
#         if self.kind != DedupInfoKind.ORGANIZERS:
#             return  # Only compute duplicates for organizer dedup info nodes
#         time_since_last_duplicate_recomputation = self.get_current_neo4j_time() - self.last_scanned_for_deduplication if self.last_scanned_for_deduplication else None
#         if not force_update and (time_since_last_duplicate_recomputation is None or time_since_last_duplicate_recomputation.total_seconds() <= 15 * 60):
#             return

#         # 15 minutes have passed since the last recomputation, so we recompute the duplicates to make sure the info is up-to-date
#         connect_new_dedup_info_node_in_analysis_graph(newly_added_dedup_info_node=self)
#         self.last_scanned_for_deduplication = OrganizerDedupInfoNode.get_current_neo4j_time()
#         self.save()

#     @classmethod
#     @telemetry_tracer.start_as_current_span("analysisgraph.DedupInfoNode.from_crs_utils_dedup_info")
#     def from_crs_utils_dedup_info(cls, crash_state, instrumentation_key, dedup_info: CRSUtilsDedupInfo) -> 'DedupInfoNode':
#         """
#         Create a DedupInfoNode object from a CRSUtilsDedupInfo object.
#         :param dedup_info: The CRSUtilsDedupInfo object.
#         :return: A DedupInfoNode object.
#         """
#         value = {
#             'kind': dedup_info.kind.value,
#             'pdt_project_id': dedup_info.pdt_project_id,
#             'identifier': dedup_info.identifier(),
#             'canonical_representation': dedup_info.canonical_representation(),
#             'content': json.loads(dedup_info.model_dump_json()),
#             'consistent_sanitizers': dedup_info.consistent_sanitizers,
#             'organizer_crash_state': crash_state,
#         }
#         if instrumentation_key is not None:
#             value['organizer_instrumentation_key'] = instrumentation_key

#         is_new, self = cls.create_node_safely(value)
#         if is_new:
#             self.content = json.loads(dedup_info.model_dump_json())
#             for reason, token in dedup_info.tokens.items():
#                 _newly_created, token_obj = DedupTokenNode.get_or_create_reliable_one({
#                     'kind': dedup_info.kind.value,
#                     'reason': reason,
#                     'identifier': token,
#                 })
#                 self.tokens.connect(token_obj)

#             self.save()

#         self.maybe_recompute_duplicates(force_update=is_new)
#         return self

#     @classmethod
#     @telemetry_tracer.start_as_current_span("analysisgraph.DedupInfoNode.for_poi_report")
#     def for_poi_report(cls, poi_report: CRSUtilsPOIReport, kind: Union[str, DedupInfoKind]) -> 'DedupInfoNode':
#         """
#         Create a DedupInfoNode object from a CRSUtilsPOIReport object.
#         :param poi_report: The CRSUtilsPOIReport object.
#         :return: A DedupInfoNode object.
#         """
#         if isinstance(kind, DedupInfoKind):
#             kind = kind.value
#         dedup_info = poi_report.get_dedup_info(kind)
#         return cls.from_crs_utils_dedup_info(
#             poi_report.organizer_crash_eval.crash_state,
#             poi_report.organizer_crash_eval.instrumentation_key,
#             dedup_info
#         )


class OrganizerDedupInfoNode(ShellphishBaseNode):
    identifier = StringProperty(unique_index=True, required=True)
    identifier_string = StringProperty(required=True)
    pdt_project_id = StringProperty(required=True)
    crash_state = StringProperty(required=True)
    instrumentation_key = StringProperty()

    first_discovered = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc)) # timestamp of when the dedup info was first discovered
    last_scanned_for_deduplication = DateTimeNeo4jFormatProperty(default=None) # timestamp of when the dedup info was last scanned for deduplication

    tokens = RelationshipTo('DedupTokenNode', 'DEDUP_TOKEN')
    generated_patches = RelationshipFrom('GeneratedPatch', 'GENERATED_PATCH_FOR', model=TimedRelationEdgeModel)
    pov_reports = RelationshipFrom('PoVReportNode', 'ORGANIZER_DEDUP_INFO', model=TimedRelationEdgeModel)

    organizer_equivalent_nodes = Relationship('OrganizerDedupInfoNode', 'ORGANIZER_EQUIVALENT_DEDUP_INFO', model=TimedRelationEdgeModel)
    def maybe_recompute_duplicates(self, force_update=False):
        """
        Recompute the duplicates of this node in the analysis graph.
        This is used to ensure that the duplicates are up-to-date.
        """

        from analysis_graph.api.dedup import connect_new_dedup_info_node_in_analysis_graph
        time_since_last_duplicate_recomputation = self.get_current_neo4j_time() - self.last_scanned_for_deduplication if self.last_scanned_for_deduplication else None
        if not force_update and (time_since_last_duplicate_recomputation is None or time_since_last_duplicate_recomputation.total_seconds() <= 15 * 60):
            return

        # 15 minutes have passed since the last recomputation, so we recompute the duplicates to make sure the info is up-to-date
        if self.instrumentation_key is None:
            connect_new_dedup_info_node_in_analysis_graph(newly_added_dedup_info_node=self)
        self.last_scanned_for_deduplication = OrganizerDedupInfoNode.get_current_neo4j_time()
        self.save()

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.OrganizerDedupInfoNode.from_crs_utils_dedup_info")
    def from_crs_utils_dedup_info(cls, crash_state, instrumentation_key, pdt_project_id: PDT_ID) -> 'OrganizerDedupInfoNode':
        """
        Create a DedupInfoNode object from a CRSUtilsDedupInfo object.
        :param dedup_info: The CRSUtilsDedupInfo object.
        :return: A DedupInfoNode object.
        """
        identifier_string = f'{pdt_project_id}-{crash_state}-{instrumentation_key or ""}'
        identifier = hashlib.sha256(identifier_string.encode()).hexdigest()
        value = {
            'pdt_project_id': pdt_project_id,
            'identifier': identifier,
            'identifier_string': identifier_string,
            'crash_state': crash_state,
        }
        if instrumentation_key is not None:
            value['instrumentation_key'] = instrumentation_key

        is_new, self = cls.create_node_safely(value)
        if is_new:
            self.save()

        self.maybe_recompute_duplicates(force_update=is_new)
        return self


class RunPovResultNode(ShellphishBaseNode):
    '''
    A RunPoVResult is a result of a run of povguy. This can be crashing or non-crashing and is not deduplicated.
    This is used to link the PoV report to the runs of povguy that generated it.
    '''
    key = StringProperty(unique_index=True)
    content = JSONProperty()

    crashes_on_base = BooleanProperty(default=None)
    crashes = BooleanProperty()

    harness_input = RelationshipTo('HarnessInputNode', 'HARNESS_INPUT')
    pov_report = RelationshipTo('PoVReportNode', 'POV_REPORT')

class PoVReportNode(ShellphishBaseNode):
    '''
    A PoV report is a report that contains information about a crash. This is deduplicated and anonymized.
    '''
    uid = UniqueIdProperty()  # unique identifier for the node
    key = StringProperty(unique_index=True, required=True)
    pdt_project_id = StringProperty(required=True)  # The project ID of the PoV report
    content = JSONProperty()

    first_discovered = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc))  # timestamp of when the PoV report was first discovered
    last_scanned_for_deduplication = DateTimeNeo4jFormatProperty(default=None)  # timestamp of when the PoV report was last scanned for deduplication
    harness_inputs = RelationshipTo('HarnessInputNode', 'HARNESS_INPUT', model=TimedRelationEdgeModel)
    organizer_dedup_infos = RelationshipTo('OrganizerDedupInfoNode', 'ORGANIZER_DEDUP_INFO')
    finished_pov_patrol = BooleanProperty(default=False)  # whether the pov was finished being analyzed by the patch patrol

    submitted_time = DateTimeNeo4jFormatProperty(default=None)  # timestamp of when the pov was submitted to the organizers
    submission_result_time = DateTimeNeo4jFormatProperty(default=None) # timestamp of when the submission result was receivedA
    failed = BooleanProperty()  # whether the pov failed to crash

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.PoVReportNode.from_crs_utils_pov_report")
    def from_crs_utils_pov_report(cls, pov_report_id: str, pov_report: CRSUtilsPOVReport, failed : bool = False) -> Tuple[bool, 'PoVReportNode']:
        """
        Create a PoVReportNode object from a CRSUtilsPOVReport object.
        :param pov_report_id: The ID of the PoV report.
        :param pov_report: The CRSUtilsPOVReport object.
        :return: A PoVReportNode object.
        """
        vals = {}
        vals['key'] = pov_report_id
        vals['content'] = json.loads(pov_report.model_dump_json())
        vals['pdt_project_id'] = pov_report.project_id
        vals['failed'] = failed 
        newly_created, self = cls.create_node_safely(vals)

        orga_dedup_info = OrganizerDedupInfoNode.from_crs_utils_dedup_info(
            pov_report.organizer_crash_eval.crash_state,
            pov_report.organizer_crash_eval.instrumentation_key,
            pdt_project_id=pov_report.project_id,
        )
        self.organizer_dedup_infos.connect(orga_dedup_info)
        self.save()

        return newly_created, self

class GeneratedPatch(ShellphishBaseNode):
    '''
    A PoV report is a report that contains information about a crash. This is deduplicated and anonymized.
    '''
    uid = UniqueIdProperty()  # unique identifier for the node
    patch_key = StringProperty(unique_index=True)
    pdt_project_id = StringProperty(required=True)  # The project ID of the patch
    diff = StringProperty()
    time_created = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(tz=timezone.utc))  # timestamp of when the patch was created
    submitted_time = DateTimeNeo4jFormatProperty(default=None)  # timestamp of when the patch was submitted to the organizers
    submission_result_time = DateTimeNeo4jFormatProperty(default=None) # timestamp of when the submission result was received
    fail_functionality = BooleanProperty()  # whether the patch failed to fix the crash
    finished_patch_patrol = BooleanProperty(default=False)  # whether the patch was finished being analyzed by the patch patrol
    imperfect_submission_in_endgame = BooleanProperty(default=False)  # whether the patch was submitted in the endgame


    extra_metadata = JSONProperty()

    patcher_name = StringProperty()
    total_cost = FloatProperty()

    pov_report_generated_from = RelationshipTo('PoVReportNode', 'POV_REPORT', model=TimedRelationEdgeModel)

    mitigated_povs = RelationshipTo('PoVReportNode', 'MITIGATED_POV_REPORT', model=TimedRelationEdgeModel)
    non_mitigated_povs = RelationshipTo('PoVReportNode', 'NON_MITIGATED_POV_REPORT', model=TimedRelationEdgeModel)

    refined_from_patch = RelationshipTo('GeneratedPatch', 'REFINED_FROM', model=TimedRelationEdgeModel)

    sarif_report_generated_from = RelationshipTo('SARIFreport', 'SARIF_REPORT_GENERATED_FROM', model=TimedRelationEdgeModel)

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.GeneratedPatch.upload_patch")
    def upload_patch(cls, pdt_project_id: str, patch_pdt_id: str, diff: str, poi_report_id: str, mitigated_poi_report_ids: List[str], non_mitigated_poi_report_ids: List[str], refined_patch_id: Optional[str], fail_functionality: bool = False, patcher_name: str='unknown', total_cost: float=0.0, **extra_metadata) -> 'GeneratedPatch':
        """
        Upload a patch to the graph.
        :param patch_key: The key of the patch.
        :param diff: The diff of the patch.
        :return: A GeneratedPatch object.
        """
        self = cls.get_or_create_node_reliable({
            'patch_key': patch_pdt_id,
            'pdt_project_id': pdt_project_id,
            'diff': diff,
            'fail_functionality': fail_functionality,
            'extra_metadata': json.loads(json.dumps(extra_metadata)), # ensure it's JSON serializable
            'patcher_name': patcher_name,
            'total_cost': total_cost,
        })
        self.time_created = datetime.now(tz=timezone.utc)
        self.pov_report_generated_from.connect(PoVReportNode.get_or_create_node_reliable({'key': poi_report_id, 'pdt_project_id': pdt_project_id}))
        for mitigated_poi_report_id in mitigated_poi_report_ids:
            self.mitigated_povs.connect(PoVReportNode.get_or_create_node_reliable({
                'key': mitigated_poi_report_id,
                'pdt_project_id': pdt_project_id
            }))

        for non_mitigated_poi_report_id in non_mitigated_poi_report_ids:
            non_mitigated_pov_report = PoVReportNode.get_or_create_node_reliable({
                'key': non_mitigated_poi_report_id,
                'pdt_project_id': pdt_project_id
            })
            self.non_mitigated_povs.connect(non_mitigated_pov_report)

        if refined_patch_id:
            refined_patch = GeneratedPatch.get_or_create_node_reliable({
                'patch_key': refined_patch_id,
                'pdt_project_id': pdt_project_id,
            })
            self.refined_from_patch.connect(refined_patch)

        self.save()
        return self

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.GeneratedPatch.upload_sarif_patch")
    def upload_sarif_patch(cls,  pdt_project_id: str, patch_pdt_id: str, diff: str, sarif_report_id: str, **extra_metadata) -> 'GeneratedPatch':
        """
        Upload a patch to the graph.
        :param patch_key: The key of the patch.
        :param diff: The diff of the patch.
        :return: A GeneratedPatch object.
        """
        self = cls.get_or_create_node_reliable({
            'pdt_project_id': pdt_project_id,
            'patch_key': patch_pdt_id,
            'diff': diff,
            'extra_metadata': json.loads(json.dumps(extra_metadata)), # ensure it's JSON serializable
        })

        # Get the correspondent sarif report
        self.time_created = datetime.now(tz=timezone.utc)
        sarif_report_node = SARIFreport.get_node_or_none(sarif_report_id)

        if sarif_report_node != None:
            self.sarif_report_generated_from.connect(sarif_report_node)
        else:
            logger.info(f" 😶‍🌫️ Could not find SARIF report with ID {sarif_report_id}. Skipping patch upload.")

        self.save()
        return self

class BucketNode(ShellphishBaseNode):
    """
    A bucket node that is used to group PoV reports and patches.
    """
    pdt_project_id = StringProperty(required=True)  # The project ID of the bucket
    bucket_key = StringProperty(unique_index=True) # unique key for the bucket
    last_updated_time = DateTimeNeo4jFormatProperty(default=lambda: datetime.now(pytz.utc))  # timestamp of when the bucket was last updated
    best_patch_key = StringProperty(default=None) # the key of the best patch in the bucket, can be None if not set

    contain_povs = RelationshipTo('PoVReportNode', 'CONTAIN_POV_REPORT')
    contain_patches = RelationshipTo('GeneratedPatch', 'CONTAIN_PATCH')

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.BucketNode.upload_bucket")
    def upload_bucket(cls, pdt_project_id: str, bucket_key: str, last_updated_time: datetime, best_patch_key: str| None, contain_povs: List[str], contain_patches: List[str]) -> 'BucketNode':
        """
        Upload a bucket to the graph.
        :param best_patch_key: The key of the best patch in the bucket, can be None if not set.
        :param contain_povs: The list of PoV report keys to be contained in the bucket.
        :param contain_patches: The list of patch keys to be contained in the bucket.
        :return: A BucketNode object.
        """
        self = cls.get_or_create_node_reliable({
            'pdt_project_id': pdt_project_id,
            'bucket_key': bucket_key,
        })
        self.last_updated_time = last_updated_time
        self.best_patch_key = best_patch_key

        for pov_key in contain_povs:
            newly_created, pov_node = PoVReportNode.create_node_safely(dict(key=pov_key, pdt_project_id=pdt_project_id))
            if pov_node:
                self.contain_povs.connect(pov_node)

        for patch_key in contain_patches:
            newly_created, patch_node = GeneratedPatch.create_node_safely(dict(patch_key=patch_key, pdt_project_id=pdt_project_id))
            if patch_node:
                self.contain_patches.connect(patch_node)

        self.save()
        return self

class PatchergSubmissionNode(ShellphishBaseNode):
    """
    A metanode that contains
    """
    pdt_project_id = StringProperty(unique_index=True, required=True)
    submitted_imperfect_patches = ArrayProperty(default=list)

    @classmethod
    @telemetry_tracer.start_as_current_span("analysisgraph.PatchergSubmissionNode.upload_node")
    def upload_node(cls, pdt_project_id: str, submitted_imperfect_patches: list[str] ) -> 'PatchergSubmissionNode':
        # Use only pdt_project_id to search for existing nodes
        get_properties = {'pdt_project_id': pdt_project_id}
        create_properties = {
            'pdt_project_id': pdt_project_id,
            'submitted_imperfect_patches': submitted_imperfect_patches,
        }

        newly_created, node = cls.create_node_safely(
            get_properties=get_properties,
            create_properties=create_properties,
            retries=3
        )

        # If node exists but patches are different, update them
        if not newly_created and node.submitted_imperfect_patches != submitted_imperfect_patches:
            node.submitted_imperfect_patches = submitted_imperfect_patches
            node.save()

        return node