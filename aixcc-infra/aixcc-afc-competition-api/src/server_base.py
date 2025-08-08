from abc import ABC, abstractmethod
from uuid import UUID
from shellphish_crs_utils.models.aixcc_api import (
    BundleSubmission,
    BundleSubmissionResponse,
    BundleSubmissionResponseVerbose,
    PatchSubmission,
    PatchSubmissionResponse,
    POVSubmission,
    POVSubmissionResponse,
    SarifAssessmentSubmission,
    SarifAssessmentResponse,
    SARIFSubmission,
    SARIFSubmissionResponse,
)


class CompetitionServer(ABC):
    """Abstract base class defining the competition server interface"""

    @abstractmethod
    def submit_patch(
        self, task_id: UUID, submission: PatchSubmission
    ) -> PatchSubmissionResponse:
        """Submit a patch for testing"""
        raise NotImplementedError()

    @abstractmethod
    def get_patch_status(
        self, task_id: UUID, patch_id: UUID
    ) -> PatchSubmissionResponse:
        """Get status of a submitted patch"""
        raise NotImplementedError()

    @abstractmethod
    def submit_sarif_assessment(
        self, task_id: UUID, sarif_id: UUID, submission: SarifAssessmentSubmission
    ) -> SarifAssessmentResponse:
        """Submit a SARIF assessment"""
        raise NotImplementedError()

    @abstractmethod
    def submit_vulnerability(
        self, task_id: UUID, submission: POVSubmission
    ) -> POVSubmissionResponse:
        """Submit a vulnerability for testing"""
        raise NotImplementedError()

    @abstractmethod
    def get_vulnerability_status(
        self, task_id: UUID, vuln_id: UUID
    ) -> POVSubmissionResponse:
        """Get status of a submitted vulnerability"""
        raise NotImplementedError()

    @abstractmethod
    def submit_bundle(
        self, task_id: UUID, submission: BundleSubmission
    ) -> BundleSubmissionResponse:
        """Submit a bundle"""
        raise NotImplementedError()

    @abstractmethod
    def get_bundle(
        self, task_id: UUID, bundle_id: UUID
    ) -> BundleSubmissionResponseVerbose:
        """Get a bundle"""
        raise NotImplementedError()

    @abstractmethod
    def update_bundle(
        self, task_id: UUID, bundle_id: UUID, submission: BundleSubmission
    ) -> BundleSubmissionResponseVerbose:
        """Update a bundle"""
        raise NotImplementedError()

    @abstractmethod
    def delete_bundle(self, task_id: UUID, bundle_id: UUID) -> None:
        """Delete a bundle"""
        raise NotImplementedError()

    @abstractmethod
    def submit_sarif(
        self, task_id: UUID, submission: SARIFSubmission
    ) -> SARIFSubmissionResponse:
        """Submit a CRS generated SARIF"""
        raise NotImplementedError()
