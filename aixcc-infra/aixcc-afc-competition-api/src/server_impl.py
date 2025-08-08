from .server_base import CompetitionServer
from uuid import UUID
from pathlib import Path
from shellphish_crs_utils.models.aixcc_api import (
    PatchSubmission,
    PatchSubmissionResponse,
    SarifAssessmentSubmission,
    SarifAssessmentResponse,
    POVSubmission,
    POVSubmissionResponse,
    BundleSubmission,
    BundleSubmissionResponse,
    BundleSubmissionResponseVerbose,
    SARIFSubmission,
    SARIFSubmissionResponse,
    SubmissionStatus,
)
import os
import json

BASE = Path("/aixcc")

POV_DIR = BASE / "povs"
PATCH_DIR = BASE / "patches"
SARIF_DIR = BASE / "sarifs"
BUNDLE_DIR = BASE / "bundles"
SARIF_ASSESSMENT_DIR = BASE / "sarif_assessments"


class CompetitionServerImpl(CompetitionServer):
    """Implementation of the competition server interface"""

    @classmethod
    def submit_patch(
        cls, task_id: UUID, submission: PatchSubmission
    ) -> PatchSubmissionResponse:
        """Submit a patch for testing"""
        patch_dir = PATCH_DIR / str(task_id)
        patch_dir.mkdir(parents=True, exist_ok=True)

        # Generate a random UUID for the patch
        patch_id = UUID(bytes=os.urandom(16))

        # Create a data structure to store
        data = {
            "submission": submission.model_dump_json(),
            "status": SubmissionStatus.SubmissionStatusAccepted,
            "functionality_tests_passing": None,
            "patch_id": str(patch_id),
        }

        # Store the submission
        patch_path = patch_dir / f"{patch_id}.json"
        with open(patch_path, "w") as f:
            json.dump(data, f, indent=4)

        # Return accepted status
        return PatchSubmissionResponse(
            patch_id=patch_id,
            status=SubmissionStatus.SubmissionStatusAccepted,
            functionality_tests_passing=None,
        )

    @classmethod
    def get_patch_status(cls, task_id: UUID, patch_id: UUID) -> PatchSubmissionResponse:
        """Get status of a submitted patch"""
        patch_dir = PATCH_DIR / str(task_id)
        patch_path = patch_dir / f"{patch_id}.json"

        # Check if the patch exists
        if not patch_path.exists():
            raise FileNotFoundError(f"Patch {patch_id} not found for task {task_id}")

        # Read the stored data
        with open(patch_path, "r") as f:
            data = json.load(f)

        # Update the status to passed (simulating that processing has completed)
        data["status"] = SubmissionStatus.SubmissionStatusPassed
        data["functionality_tests_passing"] = True

        # Save the updated status
        with open(patch_path, "w") as f:
            json.dump(data, f)

        # Return passed status
        return PatchSubmissionResponse(
            patch_id=patch_id,
            status=SubmissionStatus.SubmissionStatusPassed,
            functionality_tests_passing=True,
        )

    @classmethod
    def submit_sarif_assessment(
        cls, task_id: UUID, sarif_id: UUID, submission: SarifAssessmentSubmission
    ) -> SarifAssessmentResponse:
        """Submit a SARIF assessment"""
        assessment_dir = SARIF_ASSESSMENT_DIR / str(task_id)
        assessment_dir.mkdir(parents=True, exist_ok=True)

        # Create a data structure to store
        data = {
            "submission": submission.model_dump_json(),
            "status": SubmissionStatus.SubmissionStatusAccepted,
            "sarif_id": str(sarif_id),
        }

        # Store the assessment
        assessment_path = assessment_dir / f"{sarif_id}.json"
        with open(assessment_path, "w") as f:
            json.dump(data, f)

        # Return accepted status
        return SarifAssessmentResponse(status=SubmissionStatus.SubmissionStatusAccepted)

    @classmethod
    def submit_vulnerability(
        cls, task_id: UUID, submission: POVSubmission
    ) -> POVSubmissionResponse:
        """Submit a vulnerability for testing"""
        pov_dir = POV_DIR / str(task_id)
        pov_dir.mkdir(parents=True, exist_ok=True)

        # Generate a random UUID for the vulnerability
        pov_id = UUID(bytes=os.urandom(16))

        # Create a data structure to store
        data = {
            "submission": submission.model_dump_json(),
            "status": SubmissionStatus.SubmissionStatusAccepted,
            "pov_id": str(pov_id),
        }

        # Store the submission
        pov_path = pov_dir / f"{pov_id}.json"
        with open(pov_path, "w") as f:
            json.dump(data, f)

        # Return accepted status
        return POVSubmissionResponse(
            pov_id=pov_id, status=SubmissionStatus.SubmissionStatusAccepted
        )

    @classmethod
    def get_vulnerability_status(cls, task_id: UUID, pov_id: UUID) -> POVSubmissionResponse:
        """Get status of a submitted POV"""
        pov_dir = POV_DIR / str(task_id)
        pov_path = pov_dir / f"{pov_id}.json"

        # Check if the POV exists
        if not pov_path.exists():
            raise FileNotFoundError(f"POV {pov_id} not found for task {task_id}")

        # Read the stored data
        with open(pov_path, "r") as f:
            data = json.load(f)

        # Update the status to passed (simulating that processing has completed)
        data["status"] = SubmissionStatus.SubmissionStatusPassed

        # Save the updated status
        with open(pov_path, "w") as f:
            json.dump(data, f)

        # Return passed status
        return POVSubmissionResponse(
            pov_id=pov_id, status=SubmissionStatus.SubmissionStatusPassed
        )

    @classmethod
    def submit_bundle(
        cls, task_id: UUID, submission: BundleSubmission
    ) -> BundleSubmissionResponse:
        """Submit a bundle"""
        bundle_dir = BUNDLE_DIR / str(task_id)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Generate a random UUID for the bundle
        bundle_id = UUID(bytes=os.urandom(16))

        # Create a data structure to store
        data = {
            "submission": submission.model_dump_json(),
            "status": SubmissionStatus.SubmissionStatusAccepted,
            "bundle_id": str(bundle_id),
        }

        # Store the submission
        bundle_path = bundle_dir / f"{bundle_id}.json"
        with open(bundle_path, "w") as f:
            json.dump(data, f)

        # Return accepted status
        return BundleSubmissionResponse(
            bundle_id=bundle_id, status=SubmissionStatus.SubmissionStatusAccepted
        )

    @classmethod
    def get_bundle(
        cls, task_id: UUID, bundle_id: UUID
    ) -> BundleSubmissionResponseVerbose:
        """Get a bundle"""
        bundle_dir = BUNDLE_DIR / str(task_id)
        bundle_path = bundle_dir / f"{bundle_id}.json"

        # Check if the bundle exists
        if not bundle_path.exists():
            raise FileNotFoundError(f"Bundle {bundle_id} not found for task {task_id}")

        # Read the stored data
        with open(bundle_path, "r") as f:
            data = json.load(f)

        submission = data.get("submission", {})

        # Update the status to passed (simulating that processing has completed)
        data["status"] = SubmissionStatus.SubmissionStatusPassed

        # Save the updated status
        with open(bundle_path, "w") as f:
            json.dump(data, f)

        # Extract fields from the stored submission
        description = submission.get("description")
        patch_id = submission.get("patch_id")
        pov_id = submission.get("pov_id")
        broadcast_sarif_id = submission.get("broadcast_sarif_id")
        submitted_sarif_id = submission.get("submitted_sarif_id")

        # Convert string UUIDs to UUID objects if they exist
        patch_id = UUID(patch_id) if patch_id else None
        pov_id = UUID(pov_id) if pov_id else None
        broadcast_sarif_id = UUID(broadcast_sarif_id) if broadcast_sarif_id else None
        submitted_sarif_id = UUID(submitted_sarif_id) if submitted_sarif_id else None

        # Return bundle with passed status
        return BundleSubmissionResponseVerbose(
            bundle_id=bundle_id,
            status=SubmissionStatus.SubmissionStatusPassed,
            description=description,
            patch_id=patch_id,
            pov_id=pov_id,
            broadcast_sarif_id=broadcast_sarif_id,
            submitted_sarif_id=submitted_sarif_id,
        )

    @classmethod
    def update_bundle(
        cls, task_id: UUID, bundle_id: UUID, submission: BundleSubmission
    ) -> BundleSubmissionResponseVerbose:
        """Update a bundle"""
        bundle_dir = BUNDLE_DIR / str(task_id)
        bundle_path = bundle_dir / f"{bundle_id}.json"

        # Check if the bundle exists
        if not bundle_path.exists():
            raise FileNotFoundError(f"Bundle {bundle_id} not found for task {task_id}")

        # Read the existing data
        with open(bundle_path, "r") as f:
            data = json.load(f)

        # Update the submission data
        data["submission"] = submission.model_dump()
        data["status"] = SubmissionStatus.SubmissionStatusPassed

        # Save the updated data
        with open(bundle_path, "w") as f:
            json.dump(data, f)

        # Return updated bundle with passed status
        return BundleSubmissionResponseVerbose(
            bundle_id=bundle_id,
            status=SubmissionStatus.SubmissionStatusPassed,
            description=submission.description,
            patch_id=submission.patch_id,
            pov_id=submission.pov_id,
            broadcast_sarif_id=submission.broadcast_sarif_id,
            submitted_sarif_id=submission.submitted_sarif_id,
        )

    @classmethod
    def delete_bundle(cls, task_id: UUID, bundle_id: UUID) -> None:
        """Delete a bundle"""
        bundle_dir = BUNDLE_DIR / str(task_id)
        bundle_path = bundle_dir / f"{bundle_id}.json"

        # Check if the bundle exists
        if not bundle_path.exists():
            raise FileNotFoundError(f"Bundle {bundle_id} not found for task {task_id}")

        # Delete the bundle file
        bundle_path.unlink()

    @classmethod
    def submit_sarif(
        cls, task_id: UUID, submission: SARIFSubmission
    ) -> SARIFSubmissionResponse:
        """Submit a CRS generated SARIF"""
        sarif_dir = SARIF_DIR / str(task_id)
        sarif_dir.mkdir(parents=True, exist_ok=True)

        # Generate a random UUID for the SARIF
        sarif_id = UUID(bytes=os.urandom(16))

        # Create a data structure to store
        data = {
            "submission": submission.model_dump_json(),
            "status": SubmissionStatus.SubmissionStatusAccepted,
            "sarif_id": str(sarif_id),
        }

        # Store the submission
        sarif_path = sarif_dir / f"{sarif_id}.json"
        with open(sarif_path, "w") as f:
            json.dump(data, f)

        # Return accepted status
        return SARIFSubmissionResponse(
            submitted_sarif_id=sarif_id,
            status=SubmissionStatus.SubmissionStatusAccepted,
        )
