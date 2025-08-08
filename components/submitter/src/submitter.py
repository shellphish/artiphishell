import logging
import json
import base64
import yaml
import argparse
import os
import traceback
import time
import datetime

from enum import Enum
from pathlib import Path
from typing import Optional, Union, List
from uuid import UUID

from rich.logging import RichHandler
from rich.console import Console
from rich.table import Table

from analysis_graph.models.crashes import GeneratedPatch, BucketNode, PoVReportNode
from analysis_graph.api.sarif import get_sarif_id_from_vuln, get_sarif_id_from_patch, get_all_sarif_ids_and_pov_ids_from_project, get_pov_id_from_crash_id

from crs_telemetry.utils import (
    init_otel,
    get_otel_tracer,
    get_current_span,
)
from opentelemetry.instrumentation.requests import RequestsInstrumentor

init_otel("submitter", "scoring_submission", "task_submission")
tracer = get_otel_tracer()

from shellphish_crs_utils.models.patch import PatchMetaData
from shellphish_crs_utils.models.aixcc_api import (
    PatchSubmission,
    SubmissionStatus,
    POVSubmission,
    POVSubmissionResponse,
    PatchSubmissionResponse,
    ExtendedSarifAssessmentResponse,
    Assessment,
    SarifAssessmentSubmission,
    SARIFMetadata,
    BundleSubmission,
    BundleSubmissionResponse,
)
from shellphish_crs_utils.models.extended_aixcc_api import ExtendedTaskDetail
from shellphish_crs_utils.models.crs_reports import DedupPoVReportRepresentativeMetadata, CrashingInputMetadata
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from crs_api.competition_api import CompetitionAPI, CompetitionAPIError

# You can optionally pass a custom TracerProvider to instrument().
RequestsInstrumentor().instrument()

# Configure logging
FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)],
)
LOG = logging.getLogger("submitter")
LOG.setLevel(logging.DEBUG)

IS_CI = os.environ.get("API_COMPONENTS_USE_DUMMY_DATA", "").lower() in [
    "1",
    "t",
    "true",
    "y",
    "yes",
]

NULL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class SubmissionType(Enum):
    VULNERABILITY = "vulns"
    PATCH = "patches"
    SARIF = "sarifs"
    BUNDLE = "bundles"


class SubmissionTracker:
    """Tracks submission state and history using a file-based approach"""

    def __init__(
        self,
        shared_dir: Path,
        submitted_vulns: Path,
        submitted_patches: Path,
        submitted_sarifs: Path,
        submissions: Path,
        successful_submissions: Path,
        failed_submissions: Path,
        crs_task: ExtendedTaskDetail 
    ):
        self.shared_dir = shared_dir
        self.submitted_vulns = submitted_vulns
        self.submitted_patches = submitted_patches
        self.submitted_sarifs = submitted_sarifs
        self.submissions = submissions
        self.successful_submissions = successful_submissions
        self.failed_submissions = failed_submissions
        self.crs_task = crs_task

        self.shared_dir.mkdir(parents=True, exist_ok=True)

        self.submitted_vulns.mkdir(parents=True, exist_ok=True)
        self.submitted_patches.mkdir(parents=True, exist_ok=True)
        self.submitted_sarifs.mkdir(parents=True, exist_ok=True)

        self.submissions.mkdir(parents=True, exist_ok=True)
        self.successful_submissions.mkdir(parents=True, exist_ok=True)
        self.failed_submissions.mkdir(parents=True, exist_ok=True)

        # Directory for storing submission data
        self.lock_dir = shared_dir / "locks"
        self.lock_dir.mkdir(exist_ok=True)

        # Minimal in-memory cache for recently accessed submissions
        # Used only for performance optimization
        self.recent_submissions_cache = {}

    def _get_submission_path(
        self, task_id: UUID, submission_type: SubmissionType, identifier: str
    ) -> Path:
        """Get the path to a submission file"""
        if identifier is None:
            identifier = "DOESNT_EXIST"
        return self.lock_dir / str(task_id) / submission_type.value / identifier
    
    def _find_submission_by_partial_id(self, task_id: UUID, submission_type: SubmissionType, identifier: str) -> List[Path]:
        return list((self.lock_dir / str(task_id) / submission_type.value).glob(f"*{identifier}*"))

    def is_submitted(
        self, task_id: UUID, submission_type: SubmissionType, identifier: str
    ) -> bool:
        """Check if a submission has already been made by checking file existence"""
        submission_path = self._get_submission_path(
            task_id, submission_type, identifier
        )

        # Check cache first for performance
        cache_key = f"{task_id}:{submission_type.value}:{identifier}"
        if self.recent_submissions_cache.get(cache_key, False):
            submitted = True

        else:
            # If not in cache, check filesystem
            exists = submission_path.exists()

            # Update cache if found
            self.recent_submissions_cache[cache_key] = exists
            submitted = exists

        if submitted:
            # This will update the status of the submission if it is not already up to date
            self.get_submission(task_id, submission_type, identifier)

        return submitted

    def save_submission(
        self,
        task_id: UUID,
        submission_type: SubmissionType,
        identifier: str,
        submission_response: POVSubmissionResponse | PatchSubmissionResponse | ExtendedSarifAssessmentResponse | BundleSubmissionResponse,
    ):
        """Save submission data to shared filesystem"""
        submission_dir = self.lock_dir / str(task_id) / submission_type.value
        submission_dir.mkdir(parents=True, exist_ok=True)

        submission_path = submission_dir / identifier
        if hasattr(submission_response, "project_id") and submission_response.project_id is None:
            submission_response.project_id = str(self.crs_task.pdt_task_id)
        with submission_path.open("w") as f:
            f.write(submission_response.model_dump_json(indent=2))
        
        id_attr = "pov_id" if submission_type is SubmissionType.VULNERABILITY else None
        pdt_submission_dir = self.submitted_vulns
        if id_attr is None:
            id_attr = "patch_id" if submission_type is SubmissionType.PATCH else None
            pdt_submission_dir = self.submitted_patches
        if id_attr is None:
            id_attr = "bundle_id" if submission_type is SubmissionType.BUNDLE else None
            pdt_submission_dir = None

        if submission_type is SubmissionType.SARIF:
            pdt_submission_dir = self.submitted_sarifs
        elif id_attr is None:
            raise ValueError("Unknown submission type: " + str(submission_type))

        sub_identifier = str(submission_path.relative_to(self.lock_dir)).replace('/', '-').replace(' ', '_')
        LOG.info("Saving submission data for task_id=%s submission_type=%s identifier=%s response=%s", task_id, submission_type.value, identifier, submission_response.model_dump_json(indent=2))
        submission_file = self.submissions / sub_identifier
        prior_data = json.loads(submission_file.read_text()) if submission_file.exists() else {}
        if submission_type is not SubmissionType.SARIF and getattr(submission_response, id_attr) != NULL_UUID:
            data = submission_response.model_dump(mode="json")
            data["identifier"] = identifier
            data["type"] = submission_type.value
            data["time_updated"] = time.time()
            data["time_submitted"] = prior_data.get("time_submitted", time.time())
            submission_file.write_text(json.dumps(data, indent=2))
            if submission_type is SubmissionType.PATCH:
                try:
                    patch_node = GeneratedPatch.nodes.get_or_none(patch_key=identifier, pdt_project_id=self.crs_task.pdt_task_id)
                    if patch_node is not None:
                        LOG.info("Found patch node %s", patch_node.patch_key)
                        updated = False
                        if patch_node.submitted_time is None:
                            LOG.info("Updating submitted time for patch node %s", patch_node.patch_key)
                            patch_node.submitted_time = datetime.datetime.now(datetime.timezone.utc)
                            updated = True
                        if patch_node.submission_result_time is None and submission_response.status in (SubmissionStatus.SubmissionStatusPassed, SubmissionStatus.SubmissionStatusFailed):
                            LOG.info("Updating submission result time for patch node %s", patch_node.patch_key)
                            patch_node.submission_result_time = datetime.datetime.now(datetime.timezone.utc)
                            updated = True
                        if updated:
                            LOG.info("Saving patch node %s", patch_node.patch_key)
                            patch_node.save()
                    else:
                        LOG.warning("Patch node not found for %s", identifier)
                except Exception as e:
                    LOG.error("Failed to update patch node %s: %s", identifier, e, exc_info=True)
        
        if submission_response.status == SubmissionStatus.SubmissionStatusPassed:
            data = submission_response.model_dump(mode="json")
            data["identifier"] = identifier
            data["type"] = submission_type.value
            data["time_updated"] = time.time()
            data["time_submitted"] = prior_data.get("time_submitted", time.time())

            if submission_type is SubmissionType.SARIF or getattr(submission_response, id_attr) != NULL_UUID:
                data = json.dumps(data, indent=2)
                if pdt_submission_dir is not None:
                    (pdt_submission_dir / identifier).write_text(data)
                (self.successful_submissions / sub_identifier).write_text(data)
        
        elif submission_response.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionInconclusive):
            if submission_type not in (SubmissionType.VULNERABILITY, SubmissionType.PATCH) and (submission_type is SubmissionType.SARIF or getattr(submission_response, id_attr) != NULL_UUID):
                data = submission_response.model_dump(mode="json")
                data["identifier"] = identifier
                data["type"] = submission_type.value
                data["time_updated"] = time.time()
                data["time_submitted"] = prior_data.get("time_submitted", time.time())
                data = json.dumps(data, indent=2)
                (self.successful_submissions / sub_identifier).write_text(data)

        elif submission_response.status == SubmissionStatus.SubmissionStatusFailed:
            if submission_type is SubmissionType.SARIF or getattr(submission_response, id_attr) != NULL_UUID:
                data = submission_response.model_dump(mode="json")
                data["identifier"] = identifier
                data["type"] = submission_type.value
                data["time_updated"] = time.time()
                data["time_submitted"] = prior_data.get("time_submitted", time.time())
                data = json.dumps(data, indent=2)
                (self.failed_submissions / sub_identifier).write_text(data)

        elif submission_response.status == SubmissionStatus.SubmissionStatusErrored:
            # If the submission is errored, delete it so it can be retried
            self.delete_submission(task_id, submission_type, identifier)
            return

        # Update cache
        cache_key = f"{task_id}:{submission_type.value}:{identifier}"
        self.recent_submissions_cache[cache_key] = True

    def get_submission(
        self, task_id: UUID, submission_type: SubmissionType, identifier: str
    ) -> Optional[POVSubmissionResponse | PatchSubmissionResponse | ExtendedSarifAssessmentResponse | BundleSubmissionResponse]:
        """Get a submission by loading it from the filesystem"""
        submission_path = self._get_submission_path(
            task_id, submission_type, identifier
        )

        if not submission_path.exists():
            return None

        try:
            content = submission_path.read_text()

            if submission_type == SubmissionType.VULNERABILITY:
                submission = POVSubmissionResponse.model_validate_json(content)
            elif submission_type == SubmissionType.PATCH:
                submission = PatchSubmissionResponse.model_validate_json(content)
            elif submission_type == SubmissionType.SARIF:
                submission = ExtendedSarifAssessmentResponse.model_validate_json(content)
            elif submission_type == SubmissionType.BUNDLE:
                submission = BundleSubmissionResponse.model_validate_json(content)
            else:
                LOG.error("Unknown submission type: %s", submission_type)
                return None

            try:
                if (
                    not IS_CI
                    and submission.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionInconclusive)
                    and Submitter.API is not None
                ):
                    LOG.debug(
                        "Found %s submission, checking for status update: %s", submission_type.value, identifier
                    )
                    response = None
                    if isinstance(submission, POVSubmissionResponse):
                        response = Submitter.check_pov_status(task_id, submission)
                        if response is not None and response.status != submission.status:
                            span = get_current_span()
                            span.add_event(
                                "submitter.vulnerability.status_update",
                                {
                                    "old_status": submission.status.value,
                                    "new_status": response.status.value,
                                    "pov_id": response.pov_id,
                                },
                            )
                            LOG.info(
                                "Vulnerability submission status updated: %s", response.status
                            )
                            try:
                                pov_node = PoVReportNode.nodes.get_or_none(key=identifier, pdt_project_id=self.crs_task.pdt_task_id)
                                if pov_node:
                                    pov_node.submission_result_time = datetime.datetime.now(datetime.timezone.utc)
                                    pov_node.failed = response.status == SubmissionStatus.SubmissionStatusFailed
                                    pov_node.save()
                                else:
                                    LOG.warning("PoV node not found in analysis graph: %s", identifier)
                            except Exception as e:
                                LOG.error("Failed to update pov node: %s", e, exc_info=True)
                    elif isinstance(submission, PatchSubmissionResponse):
                        response = Submitter.check_patch_status(task_id, submission)
                        if response is not None and response.status != submission.status:
                            span = get_current_span()
                            span.add_event(
                                "submitter.patch.status_update",
                                {
                                    "old_status": submission.status.value,
                                    "new_status": response.status.value,
                                    "patch_id": response.patch_id,
                                },
                            )
                            LOG.info(
                                "Patch submission status updated: %s", response.status
                            )
                            try:
                                patch_node = GeneratedPatch.nodes.get_or_none(patch_key=identifier, pdt_project_id=self.crs_task.pdt_task_id)
                                if patch_node:
                                    patch_node.submission_result_time = datetime.datetime.now(datetime.timezone.utc)
                                    patch_node.fail_functionality = response.status == SubmissionStatus.SubmissionStatusFailed
                                    patch_node.save()
                                else:
                                    LOG.warning("Patch node not found in analysis graph: %s", identifier)
                            except Exception as e:
                                LOG.error("Failed to update patch node: %s", e, exc_info=True)

                    if response is not None:
                        self.save_submission(
                            task_id, submission_type, identifier, response
                        )
                        return response
            except Exception as e:
                LOG.error("Failed to update submission status: %s", e, exc_info=True)

            return submission
        except Exception as e:
            LOG.error(
                "Failed to load submission %s: %s", submission_path, e, exc_info=True
            )
            return None

    def get_submission_status(
        self, task_id: UUID, submission_type: SubmissionType, identifier: str
    ) -> Optional[SubmissionStatus]:
        """Get the status of a specific submission"""
        submission = self.get_submission(task_id, submission_type, identifier)
        return submission.status if submission else None

    def list_submissions(
        self, task_id: UUID, submission_type: SubmissionType
    ) -> List[str]:
        """List all submissions of a specific type for a task"""
        submission_dir = self.lock_dir / str(task_id) / submission_type.value

        if not submission_dir.exists():
            return []

        return [f.name for f in submission_dir.iterdir() if f.is_file()]
    
    def delete_submission(self, task_id: UUID, submission_type: SubmissionType, identifier: str) -> None:
        """Delete a submission by removing it from the filesystem"""
        submission_path = self._get_submission_path(task_id, submission_type, identifier)
        cache_key = f"{task_id}:{submission_type.value}:{identifier}"
        self.recent_submissions_cache.pop(cache_key, None)
        if submission_path.exists():
            submission_path.unlink()
            LOG.info("Deleted submission %s", submission_path)

    def generate_bundle_identifier(
        self,
        patch_identifier: str | None,
        vuln_identifier: str | None,
        sarif_identifier: str | None,
    ) -> str:
        """Generate a unique identifier for a bundle"""
        patch_part = patch_identifier or "0"
        vuln_part = vuln_identifier or "0"
        sarif_part = sarif_identifier or "0"

        return f"{vuln_part}.{patch_part}.{sarif_part}"
    
    def get_all_bundle_matches(self, task_id: UUID, patch_identifier: str | None = None, vuln_identifier: str | None = None, sarif_identifier: str | None = None) -> List[str]:
        """Get all bundle submissions that match any of the given identifiers"""
        
        bundle_id = self.generate_bundle_identifier(patch_identifier, vuln_identifier, sarif_identifier)
        vuln_part = bundle_id.split(".")[0]
        patch_part = bundle_id.split(".")[1]
        sarif_part = bundle_id.split(".")[2]
        if vuln_part != "0":
            partial_vuln_matches = self._find_submission_by_partial_id(task_id, SubmissionType.BUNDLE, vuln_part)
        else:
            partial_vuln_matches = []
        
        if patch_part != "0":
            partial_patch_matches = self._find_submission_by_partial_id(task_id, SubmissionType.BUNDLE, patch_part)
        else:
            partial_patch_matches = []
        
        if sarif_part != "0":
            partial_sarif_matches = self._find_submission_by_partial_id(task_id, SubmissionType.BUNDLE, sarif_part)
        else:
            partial_sarif_matches = []

        matches = []
        for match in partial_vuln_matches + partial_patch_matches + partial_sarif_matches:
            submission = self.get_submission(task_id, SubmissionType.BUNDLE, match.name)
            if submission:
                matches.append(match.name)

        return matches

class Submitter:
    """Handles vulnerability and patch submissions"""

    API = None

    def __init__(
        self,
        shared_dir: Path,
        vuln_dir: Path,
        vuln_metadata_dir: Path,
        patch_dir: Path,
        patch_metadata_dir: Path,
        sarif_dir: Path,
        sarif_retry_dir: Path,
        crash_dir: Path,
        crs_task: Path,
        submitted_vulns: Path,
        submitted_patches: Path,
        submitted_sarifs: Path,
        submissions: Path,
        successful_submissions: Path,
        failed_submissions: Path,
        competition_server_url: str,
        competition_server_api_id: str,
        competition_server_api_key: str,
    ):
        self.shared_dir = shared_dir / "submitter"
        if not self.shared_dir.exists():
            self.shared_dir.mkdir(parents=True, exist_ok=True)

        self.vuln_dir = vuln_dir
        self.vuln_metadata_dir = vuln_metadata_dir
        self.patch_dir = patch_dir
        self.patch_metadata_dir = patch_metadata_dir
        self.sarif_dir = sarif_dir
        self.sarif_retry_dir = sarif_retry_dir
        self.crash_dir = crash_dir
        self.crs_task = ExtendedTaskDetail.model_validate(
            yaml.load(crs_task.read_text(), Loader=yaml.FullLoader)
        )
        self.tracker = SubmissionTracker(
            self.shared_dir, 
            submitted_vulns, 
            submitted_patches, 
            submitted_sarifs,
            submissions,
            successful_submissions,
            failed_submissions,
            self.crs_task
        )
        Submitter.API = CompetitionAPI(
            base_url=competition_server_url,
            username=competition_server_api_id,
            password=competition_server_api_key,
        )

    
    @tracer.start_as_current_span("submit_pov")
    def submit_pov(
        self,
        task_id: UUID,
        identifier: str,
        architecture: str,
        harness_name: str,
        sanitizer: str,
        data_file: Path,
        engine: Optional[str] = None,
    ) -> Optional[POVSubmissionResponse]:
        """Submit a vulnerability and return its response"""

        LOG.info("Submitting vulnerability for task %s", task_id)
        LOG.debug(
            "Vulnerability details: arch=%s, harness=%s, sanitizer=%s, engine=%s, pov_id=%s", architecture, harness_name, sanitizer, engine, identifier
        )

        try:
            with data_file.open("rb") as f:
                data = base64.b64encode(f.read()).decode()
            LOG.debug(
                "Successfully read and encoded vulnerability data from %s", data_file
            )

            submission = POVSubmission(
                architecture=architecture,
                fuzzer_name=harness_name,
                sanitizer=sanitizer,
                testcase=data,
                engine=engine or "libfuzzer",
            )

            LOG.info(
                "Saving pending vulnerability submission for identifier %s", identifier
            )
            # Save pending submission
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.VULNERABILITY,
                identifier=identifier,
                submission_response=POVSubmissionResponse(
                    status=SubmissionStatus.SubmissionStatusAccepted, pov_id=NULL_UUID, project_id=self.crs_task.pdt_task_id
                ),
            )

            try:
                pov_node = PoVReportNode.nodes.get_or_none(key=identifier, pdt_project_id=self.crs_task.pdt_task_id)
                if pov_node:
                    pov_node.submitted_time = datetime.datetime.now(datetime.timezone.utc)
                    pov_node.save()
                    LOG.info("PoV node updated in analysis graph: %s", identifier)
                else:
                    LOG.warning("PoV node not found in analysis graph: %s", identifier)
            except Exception as e:
                LOG.error("Failed to get PoV node: %s", e, exc_info=True)

            if IS_CI:
                random_uuid = f"13370000-0000-0000-0000-{os.urandom(6).hex()}"
                response = POVSubmissionResponse(
                    status=SubmissionStatus.SubmissionStatusPassed,
                    pov_id=UUID(random_uuid),
                    project_id=self.crs_task.pdt_task_id
                )
            else:
                try:
                    response = Submitter.API.submit_pov(task_id, submission)
                    response.project_id = self.crs_task.pdt_task_id
                    span = get_current_span()
                    span.add_event(
                        "submitter.pov.submission",
                        {
                            "pov_id": response.pov_id,
                            "status": response.status.value,
                        },
                    )
                except CompetitionAPIError as e:
                    LOG.error("Failed to submit vulnerability: %s Will retry ", e)
                    self.tracker.delete_submission(task_id, SubmissionType.VULNERABILITY, identifier)
                    raise e
            LOG.info(
                "Vulnerability submission response received: status=%s", response.status
            )

            # Save submission data
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.VULNERABILITY,
                identifier=identifier,
                submission_response=response,
            )

            if response.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionStatusPassed, SubmissionStatus.SubmissionInconclusive):
                LOG.info("Vulnerability accepted with ID %s", response.pov_id)

            return response

        except Exception as e:
            LOG.error("Failed to submit vulnerability: %s", e, exc_info=True)
            raise

    @tracer.start_as_current_span("submit_patch")
    def submit_patch(
        self,
        task_id: UUID,
        patch_file: Path,
        description: str = "",
        vuln_id: Optional[UUID] = None,
    ) -> Optional[PatchSubmissionResponse]:
        """Submit a patch and return the submission response"""

        LOG.info("Submitting patch for task %s", task_id)
        LOG.debug("Patch details: file=%s, description=%s, vuln_id=%s", patch_file, description, vuln_id)
        LOG.debug("Patch Diff: %s", patch_file.read_text())

        if vuln_id:
            LOG.info("Patch is associated with vulnerability %s", vuln_id)

        LOG.debug("Patch details: file=%s, description=%s", patch_file, description)

        try:
            with patch_file.open("rb") as f:
                patch_data = base64.b64encode(f.read()).decode()
            LOG.debug("Successfully read and encoded patch data from %s", patch_file)

            submission = PatchSubmission(
                patch=patch_data, description=description, vuln_id=vuln_id
            )

            LOG.info("Saving pending patch submission for file %s", patch_file)
            # Save pending submission
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.PATCH,
                identifier=patch_file.stem,
                submission_response=PatchSubmissionResponse(
                    status=SubmissionStatus.SubmissionStatusAccepted, patch_id=NULL_UUID, project_id=self.crs_task.pdt_task_id
                ),
            )

            try:
                patch_node = GeneratedPatch.nodes.get_or_none(patch_key=patch_file.stem, pdt_project_id=self.crs_task.pdt_task_id)
                if patch_node:
                    patch_node.submitted_time = datetime.datetime.now(datetime.timezone.utc)
                    patch_node.save()
                else:
                    LOG.warning("Patch node not found in analysis graph: %s", patch_file.stem)
            except Exception as e:
                LOG.error("Failed to get patch node: %s", e, exc_info=True)

            if IS_CI:
                random_uuid = f"13370000-0000-0000-0000-{os.urandom(6).hex()}"
                response = PatchSubmissionResponse(
                    status=SubmissionStatus.SubmissionStatusPassed,
                    patch_id=UUID(random_uuid),
                    project_id=self.crs_task.pdt_task_id
                )
            else:
                try:
                    response = Submitter.API.submit_patch(task_id, submission)
                    response.project_id = self.crs_task.pdt_task_id
                    span = get_current_span()
                    span.add_event(
                        "submitter.patch.submission",
                        {
                            "patch_id": response.patch_id,
                            "status": response.status.value,
                            "functionality_tests_passing": response.functionality_tests_passing,
                        },
                    )
                except CompetitionAPIError as e:
                    LOG.error("Failed to submit patch: %s Will retry ", e)
                    self.tracker.delete_submission(task_id, SubmissionType.PATCH, patch_file.stem)
                    raise e

            LOG.info("Patch submission response received: status=%s", response.status)

            # Save submission data
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.PATCH,
                identifier=patch_file.stem,
                submission_response=response,
            )

            return response

        except Exception as e:
            LOG.error("Failed to submit patch: %s", e, exc_info=True)
            raise

    @tracer.start_as_current_span("submit_bundle")
    def submit_bundle(
        self,
        task_id: UUID,
        patch_identifier: Optional[str] = None,
        vuln_identifier: Optional[str] = None,
        sarif_identifier: Optional[str] = None,
        description: str = "",
    ) -> Optional[BundleSubmissionResponse]:
        """Submit a bundle linking related submissions"""
        LOG.info("Submitting bundle for task %s", task_id)
        LOG.debug(
            "Bundle details: patch_id=%s, vuln_id=%s, sarif_id=%s, description=%s", patch_identifier, vuln_identifier, sarif_identifier, description
        )

        # Generate a unique identifier for this bundle
        bundle_identifier = self.tracker.generate_bundle_identifier(
            patch_identifier, vuln_identifier, sarif_identifier
        )

        if not vuln_identifier and not patch_identifier:
            LOG.error("No vulnerability or patch identifier provided")
            return None

        vuln_submission = self.tracker.get_submission(task_id, SubmissionType.VULNERABILITY, vuln_identifier)
        patch_submission = self.tracker.get_submission(task_id, SubmissionType.PATCH, patch_identifier)

        if not vuln_submission and not patch_submission:
            LOG.error("No vulnerability or patch found for identifiers %s and %s", vuln_identifier, patch_identifier)

        LOG.info("Creating bundle submission for task_id=%s bundle_identifier=%s", task_id, bundle_identifier)
        # Create a failed response as default in case of errors
        failed_response = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed, bundle_id=NULL_UUID, project_id=self.crs_task.pdt_task_id
        )

        try:
            patch_id = patch_submission.patch_id if patch_submission else None
            pov_id = vuln_submission.pov_id if vuln_submission else None
            LOG.debug("Creating bundle submission: Patch ID: %s | PoV ID: %s | Sarif ID: %s", patch_id, pov_id, sarif_identifier)
            submission = BundleSubmission(
                description=description,
                patch_id=patch_id,
                pov_id=pov_id,
                broadcast_sarif_id=sarif_identifier,
            )

            # Save pending submission
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.BUNDLE,
                identifier=bundle_identifier,
                submission_response=failed_response,
            )

            if IS_CI:
                random_uuid = f"13370000-0000-0000-0000-{os.urandom(6).hex()}"
                response = BundleSubmissionResponse(
                    status=SubmissionStatus.SubmissionStatusAccepted,
                    bundle_id=UUID(random_uuid),
                    project_id=self.crs_task.pdt_task_id
                )
            else:
                try:
                    response = Submitter.API.submit_bundle(task_id, submission)
                    response.project_id = task_id
                    span = get_current_span()
                    span.add_event(
                        "submitter.bundle.submission",
                        {
                            "bundle_id": response.bundle_id,
                            "status": response.status.value,
                        },
                    )
                except CompetitionAPIError as e:
                    LOG.error("Failed to submit bundle: %s Will retry ", e)
                    self.tracker.delete_submission(task_id, SubmissionType.BUNDLE, bundle_identifier)
                    raise e

            LOG.info("Bundle submission response received: status=%s", response.status)

            # Save submission data
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.BUNDLE,
                identifier=bundle_identifier,
                submission_response=response,
            )

            if response.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionInconclusive):
                LOG.debug("Bundle accepted with ID %s", response.bundle_id)
            else:
                LOG.warning("Bundle submission was not accepted: %s", response.status)

            return response

        except Exception as e:
            LOG.error("Failed to submit bundle: %s", e, exc_info=True)
            # Don't raise the exception - bundle submission failure shouldn't stop the process
            return None

    def delete_bundle(self, identifier: str) -> None:
        """Delete a bundle"""
        try:
            bundle: BundleSubmissionResponse | None = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.BUNDLE, identifier)
            if bundle and self.API:
                self.API.delete_bundle(self.crs_task.task_id, bundle.bundle_id)
                LOG.info("Deleted bundle %s", bundle.bundle_id)
            # We don't delete the bundle from the tracker because we want to delete it every loop.
            # self.tracker.delete_submission(self.crs_task.task_id, SubmissionType.BUNDLE, identifier)
        except Exception as e:
            LOG.error("Failed to delete bundle %s: %s", identifier, e, exc_info=True)
    
    def delete_all_bundles(self) -> None:
        """Delete all bundles"""
        try:
            for bundle_identifier in self.tracker.list_submissions(self.crs_task.task_id, SubmissionType.BUNDLE):
                self.delete_bundle(bundle_identifier)
        except Exception as e:
            LOG.error("Failed to delete all bundles: %s", e, exc_info=True)

    @classmethod
    def check_pov_status(
        cls, task_id: UUID, submission: POVSubmissionResponse
    ) -> Optional[POVSubmissionResponse]:
        """Check status of a vulnerability submission"""
        try:
            LOG.info("Checking status of POV %s for task %s", submission.pov_id, task_id)
            response = Submitter.API.get_pov_status(task_id, submission.pov_id)
            return response
        except Exception as e:
            LOG.error("Failed to check vulnerability status: %s", e, exc_info=True)
            if artiphishell_should_fail_on_error():
                raise
            return None

    @classmethod
    def check_patch_status(
        cls, task_id: UUID, submission: PatchSubmissionResponse
    ) -> Optional[PatchSubmissionResponse]:
        """Check status of a patch submission"""
        try:
            response = Submitter.API.get_patch_status(task_id, submission.patch_id)
            return response
        except Exception as e:
            LOG.error("Failed to check patch status: %s", e, exc_info=True)
            if artiphishell_should_fail_on_error():
                raise
            return None

    @tracer.start_as_current_span("submit_sarif_assessment")
    def submit_sarif_assessment(
        self, task_id: UUID, sarif_id: UUID, assessment: str, description: str = ""
    ) -> Optional[ExtendedSarifAssessmentResponse]:
        """Submit a SARIF assessment and return the submission response"""
        LOG.info("Submitting SARIF assessment for task %s and SARIF %s", task_id, sarif_id)
        LOG.debug(
            "SARIF assessment details: assessment=%s, description=%s", assessment, description
        )

        # # Check if already submitted
        # if self.tracker.is_submitted(task_id, SubmissionType.SARIF, str(sarif_id)):
        #     LOG.info(
        #         "SARIF assessment for %s already submitted, returning existing response", sarif_id
        #     )
        #     return self.tracker.get_submission(
        #         task_id, SubmissionType.SARIF, str(sarif_id)
        #     )

        try:
            submission = SarifAssessmentSubmission(
                assessment=Assessment(assessment), description=description
            )

            LOG.info("Saving pending SARIF assessment submission for ID %s", sarif_id)
            # Save pending submission
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.SARIF,
                identifier=str(sarif_id),
                submission_response=ExtendedSarifAssessmentResponse(
                    status=SubmissionStatus.SubmissionStatusPassed,
                    assessment=submission.assessment,
                    project_id=self.crs_task.pdt_task_id
                ),
            )

            if IS_CI:
                response = ExtendedSarifAssessmentResponse(
                    status=SubmissionStatus.SubmissionStatusAccepted,
                    assessment=submission.assessment,
                    project_id=self.crs_task.pdt_task_id
                )
            else:
                try:
                    response = Submitter.API.submit_sarif_assessment(
                        task_id, sarif_id, submission
                    )
                    response.project_id = task_id
                    span = get_current_span()
                    span.add_event(
                        "submitter.sarif.submission",
                        {
                            "sarif_id": sarif_id,
                            "status": response.status.value,
                        },
                    )
                except CompetitionAPIError as e:
                    LOG.error("Failed to submit SARIF assessment: %s Will retry ", e)
                    self.tracker.delete_submission(task_id, SubmissionType.SARIF, str(sarif_id))
                    raise e

            LOG.info(
                "SARIF assessment submission response received: status=%s", response.status
            )

            # Save submission data
            self.tracker.save_submission(
                task_id=task_id,
                submission_type=SubmissionType.SARIF,
                identifier=str(sarif_id),
                submission_response=ExtendedSarifAssessmentResponse(
                    status=response.status,
                    assessment=submission.assessment,
                    project_id=self.crs_task.pdt_task_id
                ),
            )

            if response.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionInconclusive):
                LOG.info("SARIF assessment accepted for SARIF ID %s", sarif_id)

            return response

        except Exception as e:
            LOG.error("Failed to submit SARIF assessment: %s", e, exc_info=True)
            raise

    def _process_vulnerability_submissions(self):
        """Process new vulnerability submissions"""
        
        LOG.debug("Starting to process vulnerability submissions")
        crash_files = list(self.crash_dir.glob("*"))
        LOG.debug("Found %s vulnerability files to process", len(crash_files))
        cache = Path("/tmp/pov_cache.json")
        if cache.exists():
            cache_data = json.loads(cache.read_text())
        else:
            cache_data = {}

        for crash_file in crash_files:
            try:
                if crash_file.stat().st_size > 1024 * 1024 * 2:
                    LOG.warning("Skipping vulnerability file %s because it's too large %s MB", crash_file, crash_file.stat().st_size // (1024 * 1024))
                    continue
                if cache_data.get(crash_file.stem) is None:
                    cache_values = set(cache_data.values())
                    for vuln_id in self.vuln_dir.glob("*"):
                        if vuln_id.name in cache_values:
                            continue
                        metadata = yaml.load(vuln_id.read_text(), Loader=yaml.CLoader)
                        if metadata.get("original_crash_id", None) is not None:
                            cache_data[metadata["original_crash_id"]] = vuln_id.name
                    if cache_data.get(crash_file.stem) is None:
                        try:
                            pov_id = get_pov_id_from_crash_id(crash_file.stem)
                        except Exception as e:
                            LOG.error("Failed to get POV node for %s: %s", crash_file.stem, e, exc_info=True)
                            pov_id = None

                        if pov_id is not None:
                            cache_data[crash_file.stem] = pov_id

                    if cache_data.get(crash_file.stem) is None:
                        cache_data[crash_file.stem] = crash_file.stem
                    cache.write_text(json.dumps(cache_data, indent=2))

                LOG.debug("Processing vulnerability file: %s", {crash_file})
                vuln_file: Path = self.vuln_dir / (cache_data.get(crash_file.stem, "MISSING"))
                vuln_metadata_file: Path = self.vuln_metadata_dir / (cache_data.get(crash_file.stem, "MISSING") + ".yaml")
                if vuln_file.exists():
                    metadata = yaml.load(vuln_file.read_text(), Loader=yaml.CLoader)
                    metadata = DedupPoVReportRepresentativeMetadata.model_validate(metadata)
                    if metadata.project_id != self.crs_task.pdt_task_id:
                        LOG.debug("Skipping vulnerability %s because it's not for the PDT task %s", metadata.original_crash_id, self.crs_task.pdt_task_id)
                        continue
                elif vuln_metadata_file.exists():
                    metadata = yaml.load(vuln_metadata_file.read_text(), Loader=yaml.CLoader)
                    metadata = CrashingInputMetadata.model_validate(metadata)
                    if metadata.project_id is None or metadata.project_id != self.crs_task.pdt_task_id:
                        LOG.warning("Vulnerability metadata file %s does not have a project ID", vuln_metadata_file)
                        continue
                    vuln_file = vuln_metadata_file
                else:
                    LOG.warning(
                        "Vulnerability metadata file %s does not exist in %s", vuln_file, self.vuln_dir
                    )
                    continue

                # Skip if already fully submitted
                if self.tracker.is_submitted(
                    self.crs_task.task_id,
                    SubmissionType.VULNERABILITY,
                    vuln_file.stem,
                ):
                    LOG.debug(
                        "Skipping already submitted vulnerability %s", vuln_file.stem
                    )
                    continue

                if hasattr(metadata, "original_crash_id"):
                    LOG.info("Submitting new vulnerability %s", metadata.original_crash_id)
                else:
                    LOG.info("Submitting new vulnerability %s", vuln_file.stem)
                vuln_resp: POVSubmissionResponse | None = self.submit_pov(
                    task_id=self.crs_task.task_id,
                    identifier=vuln_file.stem,
                    architecture=metadata.architecture.value,
                    harness_name=metadata.cp_harness_name,
                    sanitizer=metadata.sanitizer.value,
                    data_file=crash_file,
                )

                if vuln_resp is None:
                    if hasattr(metadata, "original_crash_id"):
                        LOG.error("Failed to submit vulnerability %s", metadata.original_crash_id)
                    else:
                        LOG.error("Failed to submit vulnerability %s", vuln_file.stem)
                else:
                    LOG.info(
                        "Submitted vulnerability %s with ID %s status %s", vuln_file.stem, vuln_resp.pov_id, vuln_resp.status
                    )
            except Exception as e:
                LOG.error(
                    "Failed to process vulnerability file %s: %s", crash_file, e,
                    exc_info=True,
                )
                if artiphishell_should_fail_on_error():
                    raise
        LOG.debug("Finished processing vulnerability submissions")
        cache.write_text(json.dumps(cache_data))

    def _process_patch_submissions(self):
        """Process new patch submissions"""

        LOG.debug("Starting to process patch submissions")
        patch_files = list(self.patch_dir.glob("*"))
        LOG.debug("Found %s patch files to process", len(patch_files))

        for patch_file in patch_files:
            try:
                # Check if already submitted
                LOG.debug("Processing patch file: %s", patch_file)
                if self.tracker.is_submitted(
                    self.crs_task.task_id, SubmissionType.PATCH, patch_file.stem
                ):

                    LOG.debug("Skipping already submitted patch %s", patch_file.stem)
                    continue
                

                # Check if there's a matching vulnerability file
                patch_metadata_file = next(self.patch_metadata_dir.glob(f"{patch_file.stem}*"), None)
                if patch_metadata_file and patch_metadata_file.exists():
                    try:
                        patch_metadata = PatchMetaData.model_validate(yaml.safe_load(patch_metadata_file.read_text()))
                        vuln_submission = self.tracker.get_submission(
                            self.crs_task.task_id, SubmissionType.VULNERABILITY, patch_metadata.poi_report_id
                        )
                        if patch_metadata.pdt_project_id != self.crs_task.pdt_task_id:
                            LOG.debug("Skipping patch %s because it's not for the PDT task %s", patch_file.stem, self.crs_task.pdt_task_id)
                            continue
                    except Exception as e:
                        LOG.warning("Couldn't validate vulnerability submission for %s: %s", patch_file.stem, e)
                        vuln_submission = None
                else:
                    vuln_submission = None
                    LOG.warning(f"Couldn't find patch metadata for {patch_file.stem} (We'll try again later)")
                    continue
                
                vuln_id = None
                if vuln_submission:
                    try:
                        LOG.info(
                            f"Found matching vulnerability for patch: {patch_file.stem}"
                        )
                        if vuln_submission.status in [
                            SubmissionStatus.SubmissionStatusAccepted,
                            SubmissionStatus.SubmissionStatusPassed,
                            SubmissionStatus.SubmissionInconclusive,
                        ]:
                            vuln_id = vuln_submission.pov_id
                            LOG.info(f"Linking patch to vulnerability ID: {vuln_id}")
                        else:
                            LOG.warning(
                                f"Matching vulnerability {patch_file.stem} exists but status is not accepted: {vuln_submission.status}"
                            )
                    except Exception as e:
                        LOG.error(
                            f"Failed to read vulnerability data for {patch_file.stem}: {e}",
                            exc_info=True,
                        )
                        # Continue with submission without vuln_id
                else:
                    LOG.info(
                        f"No matching vulnerability found for patch: {patch_file.stem}"
                    )

                LOG.info("Submitting new patch: %s", patch_file.stem)
                # Submit the patch with optional vuln_id
                try:
                    patch_resp = self.submit_patch(
                        self.crs_task.task_id,
                        patch_file,
                        "",  # TODO: Add description if it exists
                        vuln_id,
                    )

                    LOG.info(
                        f"Submitted patch {patch_file.stem} with ID {patch_resp.patch_id} status {patch_resp.status}"
                    )
                except Exception as e:
                    LOG.error(
                        f"Failed to submit patch {patch_file.stem}: {e}", exc_info=True
                    )
                    if artiphishell_should_fail_on_error():
                        raise
                    continue  # Continue with next patch if this one fails

            except Exception as e:
                LOG.error(
                    f"Failed to process patch file {patch_file}: {e}", exc_info=True
                )
                LOG.error(traceback.format_exc())
                if artiphishell_should_fail_on_error():
                    raise
        LOG.debug("Finished processing patch submissions")

    def _process_retry_sarif_submissions(self):
        """Process new SARIF assessment submissions"""
        LOG.debug("Starting to process retry SARIF submissions")
        sarif_files = list(self.sarif_retry_dir.glob("*"))
        LOG.debug("Found %s retry SARIF files to process", len(sarif_files))

        for sarif_file in sarif_files:
            try:
                LOG.debug("Processing retry SARIF file: %s", sarif_file)
                sarif_metadata = SARIFMetadata.model_validate(yaml.safe_load(sarif_file.read_text()))
                if str(sarif_metadata.pdt_task_id) != str(self.crs_task.pdt_task_id):
                    LOG.warning("Skipping SARIF file %s due to project ID mismatch", sarif_file)
                    continue

                # Check if already submitted
                prev_sarif: ExtendedSarifAssessmentResponse | None  = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.SARIF, str(sarif_metadata.sarif_id))
                if prev_sarif is not None:
                    if prev_sarif.assessment == sarif_metadata.assessment:
                        LOG.debug("Skipping duplicate assessment for SARIF %s", sarif_metadata.sarif_id)
                        continue

                    if prev_sarif.assessment == Assessment.AssessmentCorrect:
                        LOG.debug("Skipping overwriting correct assessment for SARIF %s", sarif_metadata.sarif_id)
                        continue
                LOG.info("Submitting retry SARIF assessment for ID %s", sarif_metadata.sarif_id)

                response = self.submit_sarif_assessment(
                    task_id=sarif_metadata.task_id,
                    sarif_id=sarif_metadata.sarif_id,
                    assessment=sarif_metadata.assessment.value,
                    description=sarif_metadata.description or "",
                )

                if (
                    response
                    and response.status in (SubmissionStatus.SubmissionStatusAccepted, SubmissionStatus.SubmissionInconclusive)
                ):
                    LOG.info("Successfully submitted SARIF assessment %s", sarif_metadata.sarif_id)
                    # Note: We're not removing the file after submission to make the tests work
                    # sarif_file.unlink()  # Remove after successful submission
                    LOG.debug("Processed SARIF file %s", sarif_file)

            except Exception as e:
                LOG.error(
                    "Failed to process SARIF file %s: %s", sarif_file, e, exc_info=True
                )
                if artiphishell_should_fail_on_error():
                    raise
        LOG.debug("Finished processing SARIF submissions")
    
    def _process_bundle_patch_submissions(self):
        """Process new bundle patch submissions"""
        LOG.debug("Starting to process bundle patch submissions")
        for bucket in BucketNode.nodes.all():
            try:
                all_patches_in_bucket = [(x.patch_key, x.submitted_time) for x in bucket.contain_patches if x.submitted_time is not None]
                if not all_patches_in_bucket:
                    LOG.warning("Bucket %s has no submitted patches", bucket)
                    continue

                passed_patches = []
                for patch_key, sub_time in all_patches_in_bucket:
                    patch_sub = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.PATCH, patch_key)
                    if patch_sub is not None and patch_sub.status == SubmissionStatus.SubmissionStatusPassed:
                        passed_patches.append((patch_key, sub_time))
                best_patch = max(passed_patches, key=lambda x: x[1])[0] if passed_patches else None
                if best_patch is None:
                    LOG.warning("Bucket %s has no patches with status Passed; skipping bundle creation", bucket)
                    continue

                patch_submission: PatchSubmissionResponse | None = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.PATCH, best_patch)
                LOG.debug("Patch submission for %s: %s", best_patch, patch_submission)
                if patch_submission is None:
                    LOG.warning("We have no patch submission for bucket %s and best patch %s", bucket, best_patch)
                    continue

                if patch_submission.status != SubmissionStatus.SubmissionStatusPassed:
                    LOG.warning("Best patch %s for bucket %s is not passed (status %s)", best_patch, bucket, patch_submission.status)
                    continue

                patch_metadata_file = next(self.patch_metadata_dir.glob(f"{best_patch}*"), None)
                if not patch_metadata_file or not patch_metadata_file.exists():
                    LOG.warning("Couldn't find patch metadata for %s (We'll try again later)", best_patch)
                    continue

                patch_metadata = PatchMetaData.model_validate(yaml.safe_load(patch_metadata_file.read_text()))
                if patch_metadata.pdt_project_id != self.crs_task.pdt_task_id:
                    LOG.debug("Skipping patch %s because it's not for the PDT task %s", best_patch, self.crs_task.pdt_task_id)
                    continue

                vuln_submission: POVSubmissionResponse | None = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.VULNERABILITY, patch_metadata.poi_report_id)
                if vuln_submission is None:
                    LOG.warning("We have no vulnerability submission for bucket %s and best patch %s", bucket, best_patch)
                    continue

                if vuln_submission.status != SubmissionStatus.SubmissionStatusPassed:
                    LOG.warning("Vulnerability %s for bucket %s and best patch %s vuln is not passed (status: %s)", patch_metadata.poi_report_id, bucket, best_patch, vuln_submission.status)
                    continue


                try:
                    sarif_uuid, vuln_identifier = get_sarif_id_from_patch(best_patch)
                except Exception as e:
                    LOG.error(f"Failed to get SARIF ID for patch {best_patch}: {e}", exc_info=True)
                    sarif_uuid = None

                LOG.info("Submitting bundle for bucket %s and best patch %s", bucket, best_patch)
                bundle_resp: BundleSubmissionResponse | None = self.submit_bundle(
                    task_id=self.crs_task.task_id,
                    patch_identifier=best_patch,
                    vuln_identifier=patch_metadata.poi_report_id,
                    sarif_identifier=sarif_uuid,
                )
            except Exception:
                LOG.error("Failed to process bucket %s", bucket, exc_info=True)
                    
        LOG.debug("Finished processing bundle submissions")
    
    def _process_bundle_pov_submissions(self):
        """Process new bundle POV submissions"""
        LOG.debug("Starting to process bundle POV submissions")
        try:
            sarif_ids_and_pov_ids = get_all_sarif_ids_and_pov_ids_from_project(str(self.crs_task.pdt_task_id))
        except Exception as e:
            LOG.error(f"Failed to get any SARIF ID for project {self.crs_task.pdt_task_id}: {e}", exc_info=True)
            return
        
        for sarif_id, pov_id in sarif_ids_and_pov_ids.items():
            try:
                vuln_submission: POVSubmissionResponse | None = self.tracker.get_submission(self.crs_task.task_id, SubmissionType.VULNERABILITY, pov_id)
                if vuln_submission is None:
                    LOG.warning("We have no vulnerability submission for POV %s", pov_id)
                    continue

                if vuln_submission.status != SubmissionStatus.SubmissionStatusPassed:
                    LOG.warning("Vulnerability %s is not passed (status: %s)", pov_id, vuln_submission.status)
                    continue

                # Check if there's already a patch for this POV - if so, skip POV+SARIF bundle
                # Look for patch metadata files that reference this POV
                has_patch = False
                # Check both .yaml files and files without extensions
                for patch_metadata_file in self.patch_metadata_dir.glob("*"):
                    
                    try:
                        patch_metadata = PatchMetaData.model_validate(yaml.safe_load(patch_metadata_file.read_text()))
                        if (patch_metadata.poi_report_id == pov_id and 
                            patch_metadata.pdt_project_id == str(self.crs_task.pdt_task_id)):
                            # Check if the patch is actually submitted and passed
                            patch_submission = self.tracker.get_submission(
                                self.crs_task.task_id, SubmissionType.PATCH, patch_metadata_file.stem
                            )
                            if (patch_submission and 
                                patch_submission.status == SubmissionStatus.SubmissionStatusPassed):
                                has_patch = True
                                LOG.info("Skipping POV+SARIF bundle for POV %s because patch %s exists", 
                                        pov_id, patch_metadata_file.stem)
                                break
                    except Exception as e:
                        LOG.debug("Failed to check patch metadata file %s: %s", patch_metadata_file, e)
                        continue

                if has_patch:
                    continue

                LOG.info("Submitting bundle for POV %s and SARIF %s", pov_id, sarif_id)
                bundle_resp: BundleSubmissionResponse | None = self.submit_bundle(
                    task_id=self.crs_task.task_id,
                    patch_identifier=None,
                    vuln_identifier=pov_id,
                    sarif_identifier=sarif_id,
                )
            except Exception as e:
                LOG.error(f"Failed to submit bundle for POV {pov_id}: {e}", exc_info=True)
                if artiphishell_should_fail_on_error():
                    raise
           

    def _process_bundle_submissions(self):
        """Process new bundle submissions"""
        LOG.debug("Starting to process bundle submissions")
        self.delete_all_bundles()
        try:
            self._process_bundle_pov_submissions()
        except Exception as e:
            LOG.error(f"Failed to process bundle POV submissions: {e}", exc_info=True)
        try:
            self._process_bundle_patch_submissions()
        except Exception as e:
            LOG.error(f"Failed to process bundle patch submissions: {e}", exc_info=True)

    def _generate_submission_summary(self) -> None:
        """Generate a summary table of all submissions"""
        table = Table(title="Submission Summary")
        table.add_column("Type", style="cyan")
        table.add_column("Total", justify="right", style="white")
        table.add_column("Accepted", justify="right", style="green")
        table.add_column("Passed", justify="right", style="green")
        table.add_column("Inconclusive", justify="right", style="yellow")
        table.add_column("Failed", justify="right", style="red")
        table.add_column("Errored", justify="right", style="red")

        
        # Count successful submissions
        for submission_type in SubmissionType:
            total = 0
            accepted = 0
            passed = 0
            inconclusive = 0
            failed = 0
            errored = 0

            for submission_file in self.tracker.list_submissions(self.crs_task.task_id, submission_type):
                try:
                    submission = self.tracker.get_submission(self.crs_task.task_id, submission_type, submission_file)
                    if submission:
                        total += 1
                        if submission.status == SubmissionStatus.SubmissionStatusAccepted:
                            accepted += 1
                        elif submission.status == SubmissionStatus.SubmissionStatusPassed:
                            passed += 1
                        elif submission.status == SubmissionStatus.SubmissionInconclusive:
                            inconclusive += 1
                        elif submission.status == SubmissionStatus.SubmissionStatusFailed:
                            failed += 1
                        elif submission.status == SubmissionStatus.SubmissionStatusErrored:
                            errored += 1
                except Exception as e:
                    LOG.error(f"Error reading submission file {submission_file}: {e}")

            table.add_row(
                submission_type.value,
                str(total),
                str(accepted),
                str(passed),
                str(inconclusive),
                str(failed),
                str(errored)
            )
            LOG.info("Submission summary: %s: total %s, accepted %s, passed %s, inconclusive %s, failed %s, errored %s", 
                    submission_type.value, total, accepted, passed, inconclusive, failed, errored)

        console = Console()
        console.print(table)

    def process_new_submissions(self):
        """Process any new submissions found in input directories"""
        LOG.debug("Starting submission processing cycle")
        with tracer.start_as_current_span("submitter.vulnerability_submissions"):
            try:
                self._process_vulnerability_submissions()
            except Exception as e:
                LOG.error(
                    f"[FATAL] Failed to process vulnerability submissions: {e}",
                    exc_info=True,
                )

        with tracer.start_as_current_span("submitter.patch_submissions"):
            try:
                self._process_patch_submissions()
            except Exception as e:
                LOG.error(
                    f"[FATAL] Failed to process patch submissions: {e}", exc_info=True
                )
        with tracer.start_as_current_span("submitter.sarif_submissions"):
            try:
                self._process_retry_sarif_submissions()
            except Exception as e:
                LOG.error(
                    f"[FATAL] Failed to process retry SARIF submissions: {e}", exc_info=True
                )
        
        with tracer.start_as_current_span("submitter.bundle_submissions"):
            try:
                TIME_BEFORE_DEADLINE = 10 * 60 * 1000 # 10 minutes
                if int(time.time() * 1000) > self.crs_task.deadline - TIME_BEFORE_DEADLINE:
                    LOG.warning("Skipping bundle submissions because the deadline is within %s minutes", TIME_BEFORE_DEADLINE//60000)
                else:
                    self._process_bundle_submissions()
            except Exception as e:
                LOG.error(
                    f"[FATAL] Failed to process bundle submissions: {e}", exc_info=True
                )

        # Generate and print the submission summary table
        self._generate_submission_summary()

        LOG.debug("Completed submission processing cycle")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Process vulnerability, patch, and SARIF reports"
    )
    parser.add_argument(
        "--shared-dir",
        type=Path,
        required=True,
        help="Directory for tracking submission state",
    )
    parser.add_argument(
        "--vuln-dir",
        type=Path,
        required=True,
        help="Directory containing vulnerability reports to submit",
    )
    parser.add_argument(
        "--vuln-metadata-dir",
        type=Path,
        required=True,
        help="Directory containing vulnerability metadata reports to submit",
    )
    parser.add_argument(
        "--patch-dir",
        type=Path,
        required=True,
        help="Directory containing patch reports to submit",
    )
    parser.add_argument(
        "--patch-metadata-dir",
        type=Path,
        required=True,
        help="Directory containing patch metadata to submit",
    )   
    parser.add_argument(
        "--sarif-dir",
        type=Path,
        required=True,
        help="Directory containing SARIF reports to submit",
    )
    parser.add_argument(
        "--sarif-retry-dir",
        type=Path,
        required=True,
        help="Directory containing SARIF retry reports to submit",
    )
    parser.add_argument(
        "--crash-dir",
        type=Path,
        required=True,
        help="Directory containing crashing input submissions",
    )
    parser.add_argument(
        "--crs-task", type=Path, required=True, help="Path to the CRS task metadata"
    )

    parser.add_argument(
        "--submitted-vulns",
        type=Path,
        required=True,
        help="Path to the submitted vulns metadata",
    )
    parser.add_argument(
        "--submitted-patches",
        type=Path,
        required=True,
        help="Path to the submitted patches metadata",
    )
    parser.add_argument(
        "--submitted-sarifs",
        type=Path,
        required=True,
        help="Path to the submitted sarifs metadata",
    )
    parser.add_argument(
        "--submissions",
        type=Path,
        required=True,
        help="All submissions"
    )
    parser.add_argument(
        "--successful-submissions",
        type=Path,
        required=True,
        help="All successful submissions"
    )
    parser.add_argument(
        "--failed-submissions",
        type=Path,
        required=True,
        help="All failed submissions"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    competition_server_url = os.environ["COMPETITION_SERVER_URL"]
    competition_server_api_id = os.environ["COMPETITION_SERVER_API_ID"]
    competition_server_api_key = os.environ["COMPETITION_SERVER_API_KEY"]

    # Create submitter without task_id
    submitter = Submitter(
        shared_dir=args.shared_dir,
        vuln_dir=args.vuln_dir,
        vuln_metadata_dir=args.vuln_metadata_dir,
        patch_dir=args.patch_dir,
        patch_metadata_dir=args.patch_metadata_dir,
        sarif_dir=args.sarif_dir,
        sarif_retry_dir=args.sarif_retry_dir,
        crash_dir=args.crash_dir,
        crs_task=args.crs_task,
        submitted_vulns=args.submitted_vulns,
        submitted_patches=args.submitted_patches,
        submitted_sarifs=args.submitted_sarifs,
        submissions=args.submissions,
        successful_submissions=args.successful_submissions,
        failed_submissions=args.failed_submissions,
        competition_server_url=competition_server_url,
        competition_server_api_id=competition_server_api_id,
        competition_server_api_key=competition_server_api_key,
    )

    submitter.process_new_submissions()


if __name__ == "__main__":
    with tracer.start_as_current_span("submitter") as span:
        span.set_attribute("crs.action.category", "scoring_submission")
        span.set_attribute("crs.action.name", "submission")
        main()
