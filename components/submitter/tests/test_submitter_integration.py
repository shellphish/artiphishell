import json
import os
import pytest
from uuid import uuid4

import yaml
from shellphish_crs_utils.models.aixcc_api import (
    SubmissionStatus,
    Assessment,
)

from submitter import (
    Submitter,
    SubmissionType,
)

from crs_api.competition_api import CompetitionAPI
from test_submitter import (
    test_dirs,
    crs_task,
    pdt_id_gen,
    mock_uuid,
    representative_crashing_input_metadata,
)

test_dirs = test_dirs
crs_task = crs_task
pdt_id_gen = pdt_id_gen
mock_uuid = mock_uuid
representative_crashing_input_metadata = representative_crashing_input_metadata

# Constants for real API connection
API_URL = os.environ.get("COMPETITION_SERVER_URL", "http://localhost:80")
API_USER = os.environ.get("COMPETITION_SERVER_API_ID", "admin")
API_TOKEN = os.environ.get("COMPETITION_SERVER_API_KEY", "secret")


@pytest.fixture
def real_api():
    """Create a real CompetitionAPI instance"""
    api = CompetitionAPI(
        base_url=API_URL,
        username=API_USER,
        password=API_TOKEN,
    )
    return api


@pytest.fixture
def submitter_real_api(test_dirs, real_api, crs_task):
    """Create submitter instance with real API"""
    submitter = Submitter(
        shared_dir=test_dirs["shared_dir"],
        vuln_dir=test_dirs["vuln_dir"],
        patch_dir=test_dirs["patch_dir"],
        patch_metadata_dir=test_dirs["patch_metadata_dir"],
        sarif_dir=test_dirs["sarif_dir"],
        crash_dir=test_dirs["crashing_input_dir"],
        crs_task=crs_task,
        submitted_vulns=test_dirs["submitted_vulns"],
        submitted_patches=test_dirs["submitted_patches"],
        submitted_sarifs=test_dirs["submitted_sarifs"],
        submissions=test_dirs["submissions"],
        successful_submissions=test_dirs["successful_submissions"],
        failed_submissions=test_dirs["failed_submissions"],
        competition_server_url=API_URL,
        competition_server_api_id=API_USER,
        competition_server_api_key=API_TOKEN,
    )
    # Explicitly set the real API
    Submitter.API = real_api
    return submitter


# Mark these tests as integration tests that require the real API
pytestmark = pytest.mark.integration


def test_vulnerability_submission_real_api(
    submitter_real_api,
    test_dirs,
    real_api,
    pdt_id_gen,
    representative_crashing_input_metadata,
):
    """Test vulnerability submission flow with real API"""
    # Create a unique identifier for this test run
    test_id = str(uuid4())[:8]

    # Create test vulnerability file
    vuln_file = test_dirs["vuln_dir"] / f"test_vuln_{test_id}.json"
    vuln_file.write_text(representative_crashing_input_metadata.model_dump_json())

    # Submit vulnerability
    vuln_response = submitter_real_api.submit_pov(
        submitter_real_api.crs_task.task_id,
        f"test_vuln_{test_id}",
        "x86_64",
        "test_harness",
        "address",
        vuln_file,
    )

    # Check if submission was successful
    assert vuln_response is not None

    # Verify the vulnerability was saved in the tracker
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        f"test_vuln_{test_id}",
    )

    # Check the status of the vulnerability
    status = submitter_real_api.check_pov_status(
        submitter_real_api.crs_task.task_id, vuln_response
    )
    assert status is not None


def test_patch_submission_real_api(submitter_real_api, test_dirs, real_api, pdt_id_gen):
    """Test patch submission flow with real API"""
    # First submit a vulnerability to get a vuln_id
    test_id = str(uuid4())[:8]

    # Create test vulnerability file
    vuln_file = test_dirs["vuln_dir"] / f"test_vuln_for_patch_{test_id}.json"
    vuln_metadata = {
        "crash_report": {
            "crash_type": "test_crash",
            "crash_state": ["test_state"],
            "crash_address": "0x1234",
            "crash_instruction": "test_instruction",
            "crash_registers": {"rip": "0x1234"},
            "crash_stack_trace": ["frame1", "frame2"],
            "crash_module": "test_module",
            "crash_function": "test_function",
            "crash_line": 123,
            "triggered_sanitizers": ["address"],
        },
        "dedup_crash_report": {
            "crash_type": "test_crash",
            "crash_state": ["test_state"],
        },
    }
    vuln_file.write_text(json.dumps(vuln_metadata))

    # Submit vulnerability
    vuln_response = submitter_real_api.submit_pov(
        submitter_real_api.crs_task.task_id,
        f"test_vuln_for_patch_{test_id}",
        "x86_64",
        "test_harness",
        "address",
        vuln_file,
    )

    assert vuln_response is not None

    # Create patch file
    patch_file = test_dirs["patch_dir"] / f"test_patch_{test_id}"
    patch_file.write_text("test patch content")

    # Submit patch
    patch_response = submitter_real_api.submit_patch(
        submitter_real_api.crs_task.task_id,
        patch_file,
        f"Test patch description {test_id}",
        vuln_response.pov_id,
    )

    # Check if submission was successful
    assert patch_response is not None

    # Verify the patch was saved in the tracker
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id,
        SubmissionType.PATCH,
        str(patch_file.stem),
    )


def test_sarif_assessment_submission_real_api(submitter_real_api, test_dirs, real_api):
    """Test SARIF assessment submission flow with real API"""
    # Create a unique identifier for this test run
    test_id = str(uuid4())[:8]
    sarif_id = uuid4()

    # Submit SARIF assessment
    response = submitter_real_api.submit_sarif_assessment(
        submitter_real_api.crs_task.task_id,
        sarif_id,
        Assessment.AssessmentCorrect.value,
        f"Test SARIF assessment {test_id}",
    )

    # Check if submission was successful
    assert response is not None

    # Verify the SARIF assessment was saved in the tracker
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )


def test_bundle_submission_real_api(submitter_real_api, test_dirs, real_api):
    """Test bundle submission flow with real API"""
    # First submit a vulnerability to get a vuln_id
    test_id = str(uuid4())[:8]

    # Create test vulnerability file
    vuln_file = test_dirs["vuln_dir"] / f"test_vuln_for_bundle_{test_id}.json"
    vuln_metadata = {
        "crash_report": {
            "crash_type": "test_crash",
            "crash_state": ["test_state"],
            "crash_address": "0x1234",
            "crash_instruction": "test_instruction",
            "crash_registers": {"rip": "0x1234"},
            "crash_stack_trace": ["frame1", "frame2"],
            "crash_module": "test_module",
            "crash_function": "test_function",
            "crash_line": 123,
            "triggered_sanitizers": ["address"],
        },
        "dedup_crash_report": {
            "crash_type": "test_crash",
            "crash_state": ["test_state"],
        },
    }
    vuln_file.write_text(json.dumps(vuln_metadata))

    # Submit vulnerability
    vuln_response = submitter_real_api.submit_pov(
        submitter_real_api.crs_task.task_id,
        f"test_vuln_for_bundle_{test_id}",
        "x86_64",
        "test_harness",
        "address",
        vuln_file,
    )

    assert vuln_response is not None

    # Create patch file
    patch_file = test_dirs["patch_dir"] / f"test_patch_for_bundle_{test_id}"
    patch_file.write_text("test patch content for bundle")

    # Submit patch
    patch_response = submitter_real_api.submit_patch(
        submitter_real_api.crs_task.task_id,
        patch_file,
        f"Test patch description for bundle {test_id}",
        vuln_response.pov_id,
    )

    assert patch_response is not None

    # Submit bundle
    bundle_response = submitter_real_api.submit_bundle(
        task_id=submitter_real_api.crs_task.task_id,
        vuln_id=vuln_response.pov_id,
        patch_id=patch_response.patch_id,
        description=f"Test bundle {test_id}",
    )

    # Check if submission was successful
    assert bundle_response is not None

    # Verify the bundle was saved
    submission_id = submitter_real_api.tracker.generate_bundle_identifier(
        patch_id=patch_response.patch_id,
        vuln_id=vuln_response.pov_id,
        sarif_id=None,
    )
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id,
        SubmissionType.BUNDLE,
        submission_id,
    )


def test_process_new_submissions_workflow(
    submitter_real_api,
    test_dirs,
    real_api,
    pdt_id_gen,
    representative_crashing_input_metadata,
):
    """Test the entire process_new_submissions workflow with real API"""
    # Create unique identifiers for this test run
    test_id = str(uuid4())[:8]

    # 1. Set up vulnerability files
    # Create first vulnerability
    vuln1_id = f"test_vuln1_{test_id}"
    vuln1_file = test_dirs["vuln_dir"] / f"{vuln1_id}.yaml"
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    vuln1_file.write_text(yaml.dump(clean_dict))

    # Create crash file for first vulnerability
    crash1_file = test_dirs["crashing_input_dir"] / vuln1_id
    crash1_file.write_bytes(b"Test crash data 1" * 100)

    # Create second vulnerability
    vuln2_id = f"test_vuln2_{test_id}"
    vuln2_file = test_dirs["vuln_dir"] / f"{vuln2_id}.yaml"
    vuln2_file.write_text(yaml.dump(clean_dict))

    # Create crash file for second vulnerability
    crash2_file = test_dirs["crashing_input_dir"] / vuln2_id
    crash2_file.write_bytes(b"Test crash data 2" * 100)

    # 2. Set up patch files
    # Create patch related to first vulnerability
    related_patch_file = test_dirs["patch_dir"] / vuln1_id
    related_patch_file.write_text("Related patch content for vulnerability 1")

    # Create unrelated patch
    unrelated_patch_id = f"unrelated_patch_{test_id}"
    unrelated_patch_file = test_dirs["patch_dir"] / unrelated_patch_id
    unrelated_patch_file.write_text("Unrelated patch content")

    # 3. Process all submissions
    submitter_real_api.process_new_submissions()

    # 4. Verify vulnerability submissions were processed
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY, vuln1_id
    )
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY, vuln2_id
    )

    # Get the vulnerability submission responses
    vuln1_submission = submitter_real_api.tracker.get_submission(
        submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY, vuln1_id
    )
    vuln2_submission = submitter_real_api.tracker.get_submission(
        submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY, vuln2_id
    )

    assert vuln1_submission is not None
    assert vuln1_submission.status == SubmissionStatus.SubmissionStatusPassed
    assert vuln1_submission.pov_id is not None

    assert vuln2_submission is not None
    assert vuln2_submission.status == SubmissionStatus.SubmissionStatusPassed
    assert vuln2_submission.pov_id is not None

    # 5. Verify patch submissions were processed
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id, SubmissionType.PATCH, vuln1_id
    )
    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id, SubmissionType.PATCH, unrelated_patch_id
    )

    # Get the patch submission responses
    related_patch_submission = submitter_real_api.tracker.get_submission(
        submitter_real_api.crs_task.task_id, SubmissionType.PATCH, vuln1_id
    )
    unrelated_patch_submission = submitter_real_api.tracker.get_submission(
        submitter_real_api.crs_task.task_id, SubmissionType.PATCH, unrelated_patch_id
    )

    assert related_patch_submission is not None
    assert related_patch_submission.status == SubmissionStatus.SubmissionStatusPassed
    assert related_patch_submission.patch_id is not None

    assert unrelated_patch_submission is not None
    assert unrelated_patch_submission.status == SubmissionStatus.SubmissionStatusPassed
    assert unrelated_patch_submission.patch_id is not None

    # 6. Verify bundle submissions were created for the related patch
    # Generate the expected bundle identifier
    bundle_identifier = submitter_real_api.tracker.generate_bundle_identifier(
        related_patch_submission.patch_id, vuln1_submission.pov_id, None
    )

    assert submitter_real_api.tracker.is_submitted(
        submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
    )

    # Get the bundle submission response
    bundle_submission = submitter_real_api.tracker.get_submission(
        submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
    )

    assert bundle_submission is not None
    assert bundle_submission.status == SubmissionStatus.SubmissionStatusAccepted
    assert bundle_submission.bundle_id is not None

    # 7. Verify no bundle was created for the unrelated patch
    # Check all bundle submissions to ensure none contain the unrelated patch ID
    bundle_submissions = submitter_real_api.tracker.list_submissions(
        submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE
    )

    for bundle_id in bundle_submissions:
        if bundle_id == bundle_identifier:
            continue  # Skip the bundle we already verified

        submitter_real_api.tracker.get_submission(
            submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE, bundle_id
        )

        # Verify this bundle doesn't contain the unrelated patch
        assert str(unrelated_patch_submission.patch_id) not in bundle_id

    # 8. Store the current submission counts to verify no duplicates are created
    vuln_submissions_before = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY
        )
    )

    patch_submissions_before = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.PATCH
        )
    )

    bundle_submissions_before = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE
        )
    )

    # 9. Call process_new_submissions again
    for _ in range(10):
        submitter_real_api.process_new_submissions()

    # 10. Verify no duplicate submissions were created
    vuln_submissions_after = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.VULNERABILITY
        )
    )

    patch_submissions_after = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.PATCH
        )
    )

    bundle_submissions_after = len(
        submitter_real_api.tracker.list_submissions(
            submitter_real_api.crs_task.task_id, SubmissionType.BUNDLE
        )
    )

    # Verify counts remain the same (no duplicates)
    assert vuln_submissions_before == vuln_submissions_after, (
        "Duplicate vulnerability submissions were created"
    )
    assert patch_submissions_before == patch_submissions_after, (
        "Duplicate patch submissions were created"
    )
    assert bundle_submissions_before == bundle_submissions_after, (
        "Duplicate bundle submissions were created"
    )
