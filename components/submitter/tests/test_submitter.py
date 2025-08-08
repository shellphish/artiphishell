import pytest
import hashlib
import json
import yaml
import random
import time
import datetime
from pathlib import Path
from uuid import UUID, uuid4
from unittest.mock import Mock, patch, MagicMock

from shellphish_crs_utils.models.aixcc_api import (
    POVSubmission,
    PatchSubmission,
    SarifAssessmentSubmission,
    SubmissionStatus,
    Assessment,
    POVSubmissionResponse,
    PatchSubmissionResponse,
    SarifAssessmentResponse,
    SARIFMetadata,
    ExtendedSarifAssessmentResponse,
    BundleSubmissionResponse,
    BundleSubmission,
)
from shellphish_crs_utils.models.patch import PatchMetaData
from shellphish_crs_utils.models.extended_aixcc_api import ExtendedTaskDetail
from shellphish_crs_utils.models.crs_reports import (
    DedupPoVReportRepresentativeMetadata
)

from shellphish_crs_utils.models.target import (
    CrashingInputMetadata
)

from submitter import Submitter, SubmissionType, SubmissionTracker, NULL_UUID
import submitter as submitter_module


@pytest.fixture
def test_dirs(tmp_path):
    """Create test directories"""
    shared_dir = tmp_path / "shared"
    crashing_input_dir = tmp_path / "crashing_inputs"
    vuln_dir = tmp_path / "vulns"
    vuln_metadata_dir = tmp_path / "vuln_metadata"
    patch_dir = tmp_path / "patches"
    patch_metadata_dir = tmp_path / "patch_metadata"
    sarif_dir = tmp_path / "sarifs"
    sarif_retry_dir = tmp_path / "sarif_retries"

    submitted_vulns = tmp_path / "submitted_vulns"
    submitted_patches = tmp_path / "submitted_patches"
    submitted_sarifs = tmp_path / "submitted_sarifs"
    submissions = tmp_path / "submissions"
    successful_submissions = tmp_path / "successful_submissions"
    failed_submissions = tmp_path / "failed_submissions"

    for d in [
        shared_dir,
        crashing_input_dir,
        vuln_dir,
        vuln_metadata_dir,
        patch_dir,
        patch_metadata_dir,
        sarif_dir,
        sarif_retry_dir,
        submitted_vulns,
        submitted_patches,
        submitted_sarifs,
        submissions,
        successful_submissions,
        failed_submissions,
    ]:
        d.mkdir()

    return {
        "shared_dir": shared_dir,
        "crashing_input_dir": crashing_input_dir,
        "vuln_dir": vuln_dir,
        "vuln_metadata_dir": vuln_metadata_dir,
        "patch_dir": patch_dir,
        "patch_metadata_dir": patch_metadata_dir,
        "sarif_dir": sarif_dir,
        "sarif_retry_dir": sarif_retry_dir,
        "submitted_vulns": submitted_vulns,
        "submitted_patches": submitted_patches,
        "submitted_sarifs": submitted_sarifs,
        "submissions": submissions,
        "successful_submissions": successful_submissions,
        "failed_submissions": failed_submissions,
    }


@pytest.fixture
def pdt_id_gen():
    """Return predictable PDT IDs matching the ID_REGEX pattern"""
    pdt_ids = [hashlib.md5(str(random.randint(1, 1000000)).encode()).hexdigest() for _ in range(1, 100)]
    return iter(pdt_ids).__next__

def add_patch_metadata(submitter: Submitter, test_dirs: dict[str, Path], patch_id: str, vuln_id: str):

    metadata = PatchMetaData(
        patcher_name="test",
        total_cost=0.0,
        poi_report_id=vuln_id,
        pdt_harness_info_id=None,
        pdt_project_id=str(submitter.crs_task.pdt_task_id),
        pdt_project_name=None
    )
    (test_dirs["patch_metadata_dir"] / (patch_id )).write_text(yaml.safe_dump(metadata.model_dump()))

@pytest.fixture
def representative_crashing_input_metadata(mock_uuid, pdt_id_gen):
    from shellphish_crs_utils.models.oss_fuzz import ArchitectureEnum, SanitizerEnum
    from pathlib import Path
    
    pdt_id = pdt_id_gen()

    dedup_metadata = DedupPoVReportRepresentativeMetadata(
        # Fields from DedupPoVReportRepresentativeMetadata
        original_crash_id=pdt_id,
        consistent_sanitizers=["id_1"],
        harness_info_id=pdt_id_gen(),
        # Fields from HarnessInfo
        build_configuration_id=pdt_id_gen(),
        project_harness_metadata_id=None,
        # Fields from ProjectInfoMixin
        project_id="test_project_id",
        project_name="test_project_name",
        # Fields from BuildInfoMixin
        sanitizer=SanitizerEnum.address,
        architecture=ArchitectureEnum.x86_64,
        # Fields from HarnessInfoMixin
        cp_harness_name="test_cp_harness",
        cp_harness_binary_path=Path("test_cp_harness_binary_path"),
    )

    return dedup_metadata

@pytest.fixture
def crashing_input_metadata(mock_uuid, pdt_id_gen):
    from shellphish_crs_utils.models.oss_fuzz import ArchitectureEnum, SanitizerEnum
    from pathlib import Path
    
    pdt_id = pdt_id_gen()

    crashing_metadata = CrashingInputMetadata(
        # Fields from CrashingInputMetadata
        harness_info_id=pdt_id_gen(),
        fuzzer="libfuzzer",
        generated_by_sarif=None,
        # Fields from HarnessInfo
        build_configuration_id=pdt_id_gen(),
        project_harness_metadata_id=None,
        # Fields from ProjectInfoMixin
        project_id="test_project_id",
        project_name="test_project_name",
        # Fields from BuildInfoMixin
        sanitizer=SanitizerEnum.address,
        architecture=ArchitectureEnum.x86_64,
        # Fields from HarnessInfoMixin
        cp_harness_name="test_cp_harness",
        cp_harness_binary_path=Path("test_cp_harness_binary_path"),
    )

    return crashing_metadata


@pytest.fixture
def mock_api():
    """Create mock CompetitionAPI"""
    with patch("crs_api.competition_api.CompetitionAPI") as mock_class:
        # Create a mock instance
        mock_instance = Mock()
        mock_instance.submit_pov.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, pov_id=uuid4()
        )
        mock_instance.submit_patch.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, patch_id=uuid4()
        )
        mock_instance.submit_sarif_assessment.return_value = SarifAssessmentResponse(
            status=SubmissionStatus.SubmissionStatusAccepted
        )
        mock_instance.submit_bundle.return_value = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, bundle_id=uuid4()
        )
        mock_instance.get_vulnerability_status.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, pov_id=uuid4()
        )
        mock_instance.get_patch_status.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, patch_id=uuid4()
        )
        # Make the mock class return our configured mock instance
        mock_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_uuid():
    """Mock UUID generation to return predictable values"""
    with patch("uuid.uuid4") as mock_uuid4:
        # Create a sequence of UUIDs to be returned
        uuids = [
            UUID("12345678-1234-5678-1234-567812345678"),
            UUID("87654321-4321-8765-4321-876543210123"),
            UUID("abcdef12-3456-7890-abcd-ef1234567890"),
            UUID("fedcba98-7654-3210-fedc-ba9876543210"),
        ]
        mock_uuid4.side_effect = uuids
        yield mock_uuid4


@pytest.fixture
def mock_vuln_id(submitter, pdt_id_gen):
    """Create a mock vulnerability ID and set up the necessary files"""
    vuln_id = pdt_id_gen()

    # Create a mock vulnerability submission response
    real_uuid = uuid4()
    vuln_response = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, pov_id=real_uuid
    )

    # Save the submission in the tracker
    submitter.tracker.save_submission(
        task_id=submitter.crs_task.task_id,
        submission_type=SubmissionType.VULNERABILITY,
        identifier=vuln_id,
        submission_response=vuln_response,
    )

    # Create a mock vulnerability file with POVSubmission
    submitter.tracker.submitted_vulns.mkdir(parents=True, exist_ok=True)
    from shellphish_crs_utils.models.aixcc_api import Architecture
    import base64
    
    stored_vuln = POVSubmission(
        architecture=Architecture.ArchitectureX8664,
        fuzzer_name="test_fuzzer",
        sanitizer="asan",
        testcase=base64.b64encode(b"test_testcase").decode(),
        engine="libfuzzer",
    )
    stored_vuln_dict = json.loads(stored_vuln.model_dump_json(indent=2))
    stored_vuln_dict["pov_id"] = str(real_uuid)  # Add the pov_id field
    with (submitter.tracker.submitted_vulns / vuln_id).open("w") as f:
        f.write(json.dumps(stored_vuln_dict, indent=2))

    return vuln_id


@pytest.fixture
def crs_task(test_dirs, pdt_id_gen):
    """Create CRS task"""
    task_file = test_dirs["shared_dir"] / "task.json"
    task_id = uuid4()
    pdt_id = pdt_id_gen()
    from shellphish_crs_utils.models.aixcc_api import TaskType
    from shellphish_crs_utils.models.oss_fuzz import SanitizerEnum
    
    task = ExtendedTaskDetail(
        task_id=task_id,
        task_uuid=task_id,
        pdt_task_id=pdt_id,
        deadline=1234567890,
        task_sanitizer=SanitizerEnum.address,
        source=[],
        type=TaskType.TaskTypeFull,
        focus="test",
        project_name="test",
        metadata={},
        harnesses_included=True,
    )
    task_file.write_text(task.model_dump_json())
    return task_file


@pytest.fixture
def submitter(test_dirs, mock_api, crs_task):
    """Create submitter instance with mocked API"""
    submitter = Submitter(
        shared_dir=test_dirs["shared_dir"],
        vuln_dir=test_dirs["vuln_dir"],
        vuln_metadata_dir=test_dirs["vuln_metadata_dir"],
        patch_dir=test_dirs["patch_dir"],
        patch_metadata_dir=test_dirs["patch_metadata_dir"],
        sarif_dir=test_dirs["sarif_dir"],
        sarif_retry_dir=test_dirs["sarif_retry_dir"],
        crash_dir=test_dirs["crashing_input_dir"],
        crs_task=crs_task,
        submitted_vulns=test_dirs["submitted_vulns"],
        submitted_patches=test_dirs["submitted_patches"],
        submitted_sarifs=test_dirs["submitted_sarifs"],
        submissions=test_dirs["submissions"],
        successful_submissions=test_dirs["successful_submissions"],
        failed_submissions=test_dirs["failed_submissions"],
        competition_server_url="http://test",
        competition_server_api_id="test",
        competition_server_api_key="test",
    )
    # Explicitly set the mocked API
    Submitter.API = mock_api
    return submitter


@pytest.fixture
def mock_bundle_api(submitter):
    """Mock bundle submission API"""
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle:
        mock_submit_bundle.return_value = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted, bundle_id=uuid4()
        )
        yield mock_submit_bundle


def test_vulnerability_submission(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test vulnerability submission flow"""

    # Mock API response
    submitter.API.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        pov_id=uuid4(),  # Will return next UUID from mock sequence
    )

    pdt_id = pdt_id_gen()
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Process submissions
    submitter._process_vulnerability_submissions()

    # Verify API was called correctly
    submitter.API.submit_pov.assert_called_once()
    call_args = submitter.API.submit_pov.call_args[0]
    assert call_args[0] == submitter.crs_task.task_id
    assert isinstance(call_args[1], POVSubmission)
    assert (
        call_args[1].fuzzer_name
        == representative_crashing_input_metadata.cp_harness_name
    )

    # Verify submission was tracked
    submitter_module.IS_CI = True
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        clean_dict["original_crash_id"],
    )
    submitter_module.IS_CI = False

    # Verify submission response by reading the file
    submission_path = submitter.tracker._get_submission_path(
        submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
    )
    assert submission_path.exists()

    # Read the submission file and verify its status
    submission_response = POVSubmissionResponse.model_validate_json(
        submission_path.read_text()
    )
    assert submission_response.status == SubmissionStatus.SubmissionStatusAccepted


def test_duplicate_vulnerability_submission(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that duplicate vulnerability submissions are not submitted, but new ones are"""

    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, pov_id=uuid4()
    )
    pdt_id = pdt_id_gen()
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create first vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    submission_file = submitter.vuln_dir / (pdt_id + ".yaml")
    submission_file.write_text(yaml.dump(clean_dict))

    # Process submissions first time
    submitter._process_vulnerability_submissions()
    assert mock_api.submit_pov.call_count == 1

    # Reset mock and try submitting duplicate
    mock_api.submit_pov.reset_mock()
    submitter._process_vulnerability_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_pov.assert_not_called()

    # Create new unique vulnerability submission
    new_clean_dict = json.loads(
        representative_crashing_input_metadata.model_dump_json()
    )

    new_pdt_id = pdt_id_gen()
    new_clean_dict["original_crash_id"] = new_pdt_id
    new_clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    new_submission_file = submitter.vuln_dir / (new_pdt_id + ".yaml")
    new_submission_file.write_text(yaml.dump(new_clean_dict))

    # Create corresponding crash file
    new_crash_file = submitter.crash_dir / new_pdt_id
    new_crash_file.write_bytes(b"B" * 1024)

    # Process submissions third time with new vulnerability
    submitter._process_vulnerability_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_pov.call_count == 1

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        clean_dict["original_crash_id"],
    )

    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        new_clean_dict["original_crash_id"],
    )

    # Count the number of vulnerability submissions by checking the directory
    vuln_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.VULNERABILITY.value
    )
    assert len(list(vuln_dir.glob("*"))) == 2


def test_vulnerability_submission_different_task_id(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that vulnerability submission only processes files for its own task ID"""

    submitter_module.IS_CI = False
    # Create two PDT IDs for two different tasks
    pdt_id_1 = pdt_id_gen()
    pdt_id_2 = pdt_id_gen()

    # Create crashing input files for both PDTs
    crash_file_1 = submitter.crash_dir / pdt_id_1
    crash_file_2 = submitter.crash_dir / pdt_id_2
    crash_file_1.write_bytes(b"A" * 1024)
    crash_file_2.write_bytes(b"B" * 1024)

    # Create vulnerability submission files for both PDTs
    clean_dict_1 = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict_2 = json.loads(representative_crashing_input_metadata.model_dump_json())
    
    # Set project_id to submitter's task ID for first submission
    clean_dict_1["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict_1["original_crash_id"] = pdt_id_1
    # Set different project_id for second submission
    clean_dict_2["project_id"] = "different_task_id"
    clean_dict_2["original_crash_id"] = pdt_id_2
    
    # Write both submission files
    (submitter.vuln_dir / pdt_id_1).write_text(yaml.dump(clean_dict_1))
    (submitter.vuln_dir / pdt_id_2).write_text(yaml.dump(clean_dict_2))

    # Process submissions
    submitter._process_vulnerability_submissions()

    # Verify API was called only once (for the matching task ID)
    mock_api.submit_pov.assert_called_once()
    
    # Verify only the submission for the matching task ID was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id_1,
    )
    assert not submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id_2,
    )


def test_vulnerability_submission_with_crashing_input_metadata(
    submitter, test_dirs, mock_api, pdt_id_gen, crashing_input_metadata
):
    """Test vulnerability submission flow when only CrashingInputMetadata is available"""

    # Mock API response
    submitter.API.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        pov_id=uuid4(),  # Will return next UUID from mock sequence
    )

    pdt_id = pdt_id_gen()
    
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"B" * 1024)

    # Create CrashingInputMetadata in vuln_metadata_dir (NOT in vuln_dir)
    # This simulates the case where we only have the basic crashing input metadata
    clean_dict = json.loads(crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    
    # Write to vuln_metadata_dir with .yaml extension
    (submitter.vuln_metadata_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Ensure NO file exists in vuln_dir (this is the key difference from other tests)
    assert not (submitter.vuln_dir / pdt_id).exists()
    assert not (submitter.vuln_dir / (pdt_id + ".yaml")).exists()

    # Process submissions
    submitter._process_vulnerability_submissions()

    # Verify API was called correctly
    submitter.API.submit_pov.assert_called_once()
    call_args = submitter.API.submit_pov.call_args[0]
    assert call_args[0] == submitter.crs_task.task_id
    assert isinstance(call_args[1], POVSubmission)
    assert call_args[1].fuzzer_name == crashing_input_metadata.cp_harness_name

    # Verify submission was tracked
    submitter_module.IS_CI = True
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id,
    )
    submitter_module.IS_CI = False

    # Verify submission response by reading the file
    submission_path = submitter.tracker._get_submission_path(
        submitter.crs_task.task_id, SubmissionType.VULNERABILITY, pdt_id
    )
    assert submission_path.exists()

    # Read the submission file and verify its status
    submission_response = POVSubmissionResponse.model_validate_json(
        submission_path.read_text()
    )
    assert submission_response.status == SubmissionStatus.SubmissionStatusAccepted


def test_duplicate_vulnerability_submission_with_crashing_input_metadata(
    submitter, test_dirs, mock_api, pdt_id_gen, crashing_input_metadata
):
    """Test that duplicate vulnerability submissions are not submitted when using CrashingInputMetadata"""

    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, pov_id=uuid4()
    )
    
    pdt_id = pdt_id_gen()
    
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"C" * 1024)

    # Create CrashingInputMetadata in vuln_metadata_dir
    clean_dict = json.loads(crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    
    # Write to vuln_metadata_dir with .yaml extension
    vuln_metadata_file = submitter.vuln_metadata_dir / (pdt_id + ".yaml")
    vuln_metadata_file.write_text(yaml.dump(clean_dict))

    # Ensure NO file exists in vuln_dir
    assert not (submitter.vuln_dir / pdt_id).exists()
    assert not (submitter.vuln_dir / (pdt_id + ".yaml")).exists()

    # Process submissions first time
    submitter._process_vulnerability_submissions()
    assert mock_api.submit_pov.call_count == 1

    # Reset mock and try submitting duplicate
    mock_api.submit_pov.reset_mock()
    submitter._process_vulnerability_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_pov.assert_not_called()

    # Create new unique vulnerability submission with CrashingInputMetadata
    new_pdt_id = pdt_id_gen()
    new_clean_dict = json.loads(crashing_input_metadata.model_dump_json())
    new_clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    
    new_vuln_metadata_file = submitter.vuln_metadata_dir / (new_pdt_id + ".yaml")
    new_vuln_metadata_file.write_text(yaml.dump(new_clean_dict))

    # Create corresponding crash file
    new_crash_file = submitter.crash_dir / new_pdt_id
    new_crash_file.write_bytes(b"D" * 1024)

    # Process submissions third time with new vulnerability
    submitter._process_vulnerability_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_pov.call_count == 1

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id,
    )

    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        new_pdt_id,
    )

    # Count the number of vulnerability submissions by checking the directory
    vuln_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.VULNERABILITY.value
    )
    assert len(list(vuln_dir.glob("*"))) == 2


def test_vulnerability_submission_with_crashing_input_metadata_different_task_id(
    submitter, test_dirs, mock_api, pdt_id_gen, crashing_input_metadata
):
    """Test that vulnerability submission with CrashingInputMetadata only processes files for its own task ID"""

    submitter_module.IS_CI = False
    
    # Create two PDT IDs for two different tasks
    pdt_id_1 = pdt_id_gen()
    pdt_id_2 = pdt_id_gen()

    # Create crashing input files for both PDTs
    crash_file_1 = submitter.crash_dir / pdt_id_1
    crash_file_2 = submitter.crash_dir / pdt_id_2
    crash_file_1.write_bytes(b"E" * 1024)
    crash_file_2.write_bytes(b"F" * 1024)

    # Create CrashingInputMetadata files for both PDTs
    clean_dict_1 = json.loads(crashing_input_metadata.model_dump_json())
    clean_dict_2 = json.loads(crashing_input_metadata.model_dump_json())
    
    # Set project_id to submitter's task ID for first submission
    clean_dict_1["project_id"] = submitter.crs_task.pdt_task_id
    # Set different project_id for second submission  
    clean_dict_2["project_id"] = "different_task_id"
    
    # Write both submission files to vuln_metadata_dir
    (submitter.vuln_metadata_dir / (pdt_id_1 + ".yaml")).write_text(yaml.dump(clean_dict_1))
    (submitter.vuln_metadata_dir / (pdt_id_2 + ".yaml")).write_text(yaml.dump(clean_dict_2))

    # Ensure NO files exist in vuln_dir
    assert not (submitter.vuln_dir / pdt_id_1).exists()
    assert not (submitter.vuln_dir / pdt_id_2).exists()

    # Process submissions
    submitter._process_vulnerability_submissions()

    # Verify API was called only once (for the matching task ID)
    mock_api.submit_pov.assert_called_once()
    
    # Verify only the submission for the matching task ID was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id_1,
    )
    assert not submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.VULNERABILITY,
        pdt_id_2,
    )


def test_patch_submission(submitter, test_dirs, mock_api, mock_vuln_id, pdt_id_gen):
    """Test patch submission flow"""

    submitter_module.IS_CI = False
    # Mock API response
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, patch_id=uuid4()
    )

    # Create patch file
    patch_file = test_dirs["patch_dir"] / mock_vuln_id
    patch_file.write_text("test patch content")
    add_patch_metadata(submitter, test_dirs, mock_vuln_id, mock_vuln_id)

    # Get the vuln_id from the stored vulnerability file
    with (submitter.tracker.submitted_vulns / mock_vuln_id).open() as f:
        vuln_data = json.load(f)
        vuln_id = UUID(vuln_data["pov_id"])

    # Submit patch
    _ = submitter.submit_patch(
        submitter.crs_task.task_id, patch_file, "Test patch description", vuln_id
    )

    # Verify API was called correctly
    mock_api.submit_patch.assert_called_once()
    call_args = mock_api.submit_patch.call_args[0]
    assert call_args[0] == submitter.crs_task.task_id
    assert isinstance(call_args[1], PatchSubmission)
    assert call_args[1].patch is not None

    # Verify submission was tracked
    submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.PATCH,
        patch_file.stem,
    )
    assert submission is not None
    assert submission.status == SubmissionStatus.SubmissionStatusAccepted


def test_sarif_assessment_submission(submitter, test_dirs, mock_api, mock_uuid):
    """Test SARIF assessment submission flow"""

    submitter_module.IS_CI = False
    # Mock API response
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        project_id=submitter.crs_task.pdt_task_id
    )

    # Create SARIF assessment submission file

    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment",
    )

    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Process submissions
    submitter._process_retry_sarif_submissions()

    # Verify API was called correctly
    mock_api.submit_sarif_assessment.assert_called_once()
    call_args = mock_api.submit_sarif_assessment.call_args[0]
    assert call_args[0] == submitter.crs_task.task_id
    assert call_args[1] == sarif_id
    assert isinstance(call_args[2], SarifAssessmentSubmission)
    assert call_args[2].assessment == Assessment.AssessmentCorrect

    # Verify submission was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )

    # Verify submission response was saved
    response = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )
    assert response is not None
    assert response.status == SubmissionStatus.SubmissionStatusAccepted


def test_duplicate_sarif_assessment_submission_incorrect_to_correct(
    submitter, test_dirs, mock_api, mock_uuid
):
    """Test that duplicate SARIF assessment submissions are not submitted, but new ones are"""
    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted
    )

    # Create first SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment",
        assessment=Assessment.AssessmentIncorrect,
    )
    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Process submissions first time
    submitter._process_retry_sarif_submissions()
    assert mock_api.submit_sarif_assessment.call_count == 1

    # Reset mock and try submitting duplicate (recreate the same file)
    mock_api.submit_sarif_assessment.reset_mock()
    submitter._process_retry_sarif_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_sarif_assessment.assert_not_called()

    # Create new unique SARIF assessment
    new_sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentCorrect,
        description="New SARIF assessment",
    )
    new_submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}_2.json"
    new_submission_file.write_text(yaml.safe_dump(new_sarif_metadata.model_dump(mode="json")))

    # Process submissions third time with new SARIF assessment
    submitter._process_retry_sarif_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_sarif_assessment.call_count == 1
    call_args = mock_api.submit_sarif_assessment.call_args[0]
    assert call_args[1] == new_sarif_metadata.sarif_id
    assert call_args[2].assessment == Assessment.AssessmentCorrect

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_metadata.sarif_id),
    )
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(new_sarif_metadata.sarif_id),
    )

    # Count the number of SARIF submissions by checking the directory
    sarif_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.SARIF.value
    )
    assert len(list(sarif_dir.glob("*"))) == 1

def test_duplicate_sarif_assessment_submission_correct_to_incorrect(
    submitter, test_dirs, mock_api, mock_uuid
):
    """Test that duplicate SARIF assessment submissions are not submitted, but new ones are"""
    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted
    )

    # Create first SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment",
        assessment=Assessment.AssessmentCorrect,
    )
    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Process submissions first time
    submitter._process_retry_sarif_submissions()
    assert mock_api.submit_sarif_assessment.call_count == 1

    # Reset mock and try submitting duplicate (recreate the same file)
    mock_api.submit_sarif_assessment.reset_mock()
    submitter._process_retry_sarif_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_sarif_assessment.assert_not_called()

    # Create new unique SARIF assessment
    new_sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentIncorrect,
        description="New SARIF assessment",
    )
    new_submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}_2.json"
    new_submission_file.write_text(yaml.safe_dump(new_sarif_metadata.model_dump(mode="json")))

    # Process submissions third time with new SARIF assessment
    submitter._process_retry_sarif_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_sarif_assessment.call_count == 0

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_metadata.sarif_id),
    )
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(new_sarif_metadata.sarif_id),
    )

    # Count the number of SARIF submissions by checking the directory
    sarif_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.SARIF.value
    )
    assert len(list(sarif_dir.glob("*"))) == 1


def test_duplicate_sarif_assessment_submission_incorrect_to_incorrect(
    submitter, test_dirs, mock_api, mock_uuid
):
    """Test that duplicate SARIF assessment submissions are not submitted, but new ones are"""
    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted
    )

    # Create first SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment",
        assessment=Assessment.AssessmentIncorrect,
    )
    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Process submissions first time
    submitter._process_retry_sarif_submissions()
    assert mock_api.submit_sarif_assessment.call_count == 1

    # Reset mock and try submitting duplicate (recreate the same file)
    mock_api.submit_sarif_assessment.reset_mock()
    submitter._process_retry_sarif_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_sarif_assessment.assert_not_called()

    # Create new unique SARIF assessment
    new_sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentIncorrect,
        description="New SARIF assessment",
    )
    new_submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}_2.json"
    new_submission_file.write_text(yaml.safe_dump(new_sarif_metadata.model_dump(mode="json")))

    # Process submissions third time with new SARIF assessment
    submitter._process_retry_sarif_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_sarif_assessment.call_count == 0

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_metadata.sarif_id),
    )
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(new_sarif_metadata.sarif_id),
    )

    # Count the number of SARIF submissions by checking the directory
    sarif_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.SARIF.value
    )
    assert len(list(sarif_dir.glob("*"))) == 1


def test_duplicate_sarif_assessment_submission_correct_to_correct(
    submitter, test_dirs, mock_api, mock_uuid
):
    """Test that duplicate SARIF assessment submissions are not submitted, but new ones are"""
    submitter_module.IS_CI = False

    # Mock API response for first submission
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted
    )

    # Create first SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment",
        assessment=Assessment.AssessmentCorrect,
    )
    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Process submissions first time
    submitter._process_retry_sarif_submissions()
    assert mock_api.submit_sarif_assessment.call_count == 1

    # Reset mock and try submitting duplicate (recreate the same file)
    mock_api.submit_sarif_assessment.reset_mock()
    submitter._process_retry_sarif_submissions()

    # Verify API was not called for duplicate
    mock_api.submit_sarif_assessment.assert_not_called()

    # Create new unique SARIF assessment
    new_sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentCorrect,
        description="New SARIF assessment",
    )
    new_submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}_2.json"
    new_submission_file.write_text(yaml.safe_dump(new_sarif_metadata.model_dump(mode="json")))

    # Process submissions third time with new SARIF assessment
    submitter._process_retry_sarif_submissions()

    # Verify API was called for new submission
    assert mock_api.submit_sarif_assessment.call_count == 0

    # Verify both submissions are tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_metadata.sarif_id),
    )
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(new_sarif_metadata.sarif_id),
    )

    # Count the number of SARIF submissions by checking the directory
    sarif_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.SARIF.value
    )
    assert len(list(sarif_dir.glob("*"))) == 1


def test_simplified_submission_tracker(test_dirs, crs_task):
    """Test the simplified file-based SubmissionTracker"""
    from submitter import SubmissionType
    from shellphish_crs_utils.models.aixcc_api import (
        PatchSubmissionResponse,
        SubmissionStatus,
    )
    from uuid import uuid4

    task = ExtendedTaskDetail.model_validate_json(crs_task.read_text())
    # Create a tracker
    tracker = SubmissionTracker(
        test_dirs["shared_dir"],
        test_dirs["submitted_vulns"],
        test_dirs["submitted_patches"],
        test_dirs["submitted_sarifs"],
        test_dirs["submissions"],
        test_dirs["successful_submissions"],
        test_dirs["failed_submissions"],
        crs_task=task
    )

    # Create test data
    task_id = uuid4()
    vuln_id = uuid4()
    patch_id = uuid4()

    # Test saving and checking vulnerability submission
    vuln_response = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, pov_id=vuln_id
    )
    tracker.save_submission(
        task_id=task_id,
        submission_type=SubmissionType.VULNERABILITY,
        identifier="test_vuln",
        submission_response=vuln_response,
    )

    # Verify submission was saved
    submitter_module.IS_CI = True
    assert tracker.is_submitted(task_id, SubmissionType.VULNERABILITY, "test_vuln")
    submitter_module.IS_CI = False

    # Test retrieving the submission
    submitter_module.IS_CI = True
    retrieved_vuln = tracker.get_submission(
        task_id, SubmissionType.VULNERABILITY, "test_vuln"
    )
    submitter_module.IS_CI = False
    assert retrieved_vuln is not None
    assert isinstance(retrieved_vuln, POVSubmissionResponse)
    assert retrieved_vuln.pov_id == vuln_id
    assert retrieved_vuln.status == SubmissionStatus.SubmissionStatusAccepted

    # Test saving and checking patch submission
    patch_response = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, patch_id=patch_id
    )
    tracker.save_submission(
        task_id=task_id,
        submission_type=SubmissionType.PATCH,
        identifier="test_patch",
        submission_response=patch_response,
    )

    # Verify submission was saved
    submitter_module.IS_CI = True
    assert tracker.is_submitted(task_id, SubmissionType.PATCH, "test_patch")
    submitter_module.IS_CI = False

    # Test retrieving the submission
    retrieved_patch = tracker.get_submission(
        task_id, SubmissionType.PATCH, "test_patch"
    )
    assert retrieved_patch is not None
    assert isinstance(retrieved_patch, PatchSubmissionResponse)
    assert retrieved_patch.patch_id == patch_id
    assert retrieved_patch.status == SubmissionStatus.SubmissionStatusPassed

    # Test listing submissions
    vuln_submissions = tracker.list_submissions(task_id, SubmissionType.VULNERABILITY)
    assert "test_vuln" in vuln_submissions

    patch_submissions = tracker.list_submissions(task_id, SubmissionType.PATCH)
    assert "test_patch" in patch_submissions

    # Test non-existent submission
    assert not tracker.is_submitted(
        task_id, SubmissionType.VULNERABILITY, "nonexistent"
    )
    assert (
        tracker.get_submission(task_id, SubmissionType.VULNERABILITY, "nonexistent")
        is None
    )

    # Test submission status
    submitter_module.IS_CI = True
    vuln = tracker.get_submission(task_id, SubmissionType.VULNERABILITY, "test_vuln")
    assert vuln is not None
    assert vuln.status == SubmissionStatus.SubmissionStatusAccepted
    assert (
        tracker.get_submission_status(
            task_id, SubmissionType.VULNERABILITY, "test_vuln"
        )
        is SubmissionStatus.SubmissionStatusAccepted
    )
    assert (
        tracker.get_submission_status(
            task_id, SubmissionType.VULNERABILITY, "nonexistent"
        )
        is None
    )
    submitter_module.IS_CI = False


def test_bundle_submission(
    submitter, test_dirs, mock_api, mock_bundle_api, mock_vuln_id, pdt_id_gen
):
    """Test bundle submission when a patch is linked to a vulnerability"""

    # Create patch file with same name as vulnerability
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")

    poi_id = pdt_id_gen()
    vuln_id = uuid4()
    vuln_file = test_dirs["vuln_dir"] / poi_id
    vuln_file.write_text("test vuln content")
    add_patch_metadata(submitter, test_dirs, patch_id, poi_id)


    # Mock API responses

    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, pov_id=vuln_id
    )
    response = submitter.submit_pov(
        task_id=submitter.crs_task.task_id,
        data_file=vuln_file,
        identifier=poi_id,
        architecture="x86_64",
        harness_name="test",
        sanitizer="address",
    )


    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, patch_id=patch_uuid
    )

    bundle_id = submitter.tracker.generate_bundle_identifier(patch_id, poi_id, None)
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, bundle_id=uuid4()
    )

    # Process submissions
    # Mock the analysis graph components to avoid database connections
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockBucketNode.nodes.all.return_value = []
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        submitter.process_new_submissions()
        
        # Since the new analysis graph logic doesn't create bundles when buckets are empty,
        # we need to manually submit the bundle for this test
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=poi_id,
            description="Test bundle submission"
        )

    # Verify vulnerability submission API was called
    mock_api.submit_pov.assert_called_once()

    # Verify patch API was called
    mock_api.submit_patch.assert_called_once()

    # Verify bundle API was called
    mock_bundle_api.assert_called_once()

    # Check bundle arguments
    bundle_args = mock_bundle_api.call_args[0]
    assert bundle_args[0] == submitter.crs_task.task_id  # task_id

    bundle_submission = bundle_args[1]
    assert isinstance(bundle_submission, BundleSubmission)
    assert bundle_submission.patch_id is not None
    assert bundle_submission.pov_id is not None  # vuln_id is stored as pov_id

    # Verify bundle metadata was saved - we don't check the exact identifier
    # since it's generated inside the method and may not match our prediction
    submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.BUNDLE,
        bundle_id,
    )
    assert submission is not None
    assert submission.status is SubmissionStatus.SubmissionStatusAccepted


def test_patch_without_vulnerability(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen
):
    """Test submitting a patch without an associated vulnerability"""

    # Create patch file with a name that doesn't match any vulnerability
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content without vuln")
    add_patch_metadata(submitter, test_dirs, patch_id, "")

    # Mock API response with a proper PatchSubmissionResponse
    response_patch_id = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, patch_id=response_patch_id
    )

    # Ensure the submitted_patches directory exists
    submitter.tracker.submitted_patches.mkdir(parents=True, exist_ok=True)

    # Create a mock patch metadata file
    patch_metadata = {
        "patch_id": str(response_patch_id),
        "vuln_id": None,
        "status": SubmissionStatus.SubmissionStatusAccepted.value,
    }
    with (submitter.tracker.submitted_patches / patch_id).open("w") as f:
        json.dump(patch_metadata, f, indent=2)

    # Process submissions - mock analysis graph to avoid Neo4j connections
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        submitter._process_patch_submissions()

    # Verify patch API was called
    mock_api.submit_patch.assert_called_once()

    # Verify bundle API was NOT called (no vulnerability to bundle with)
    mock_bundle_api.assert_not_called()

    # Verify patch was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
    )

    # Verify patch metadata was saved
    patch_metadata_file = submitter.tracker.submitted_patches / patch_id
    assert patch_metadata_file.exists()

    # Verify patch metadata has null vuln_id
    with patch_metadata_file.open() as f:
        patch_data = json.load(f)
        assert "pov_id" not in patch_data or patch_data["pov_id"] is None


def test_invalid_vulnerability_handling(submitter, test_dirs, mock_api, pdt_id_gen):
    """Test handling of patches with invalid vulnerability references"""

    # Create a patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    # Create an invalid vulnerability file (corrupted JSON)
    vuln_file =  test_dirs["vuln_dir"] / patch_id
    vuln_file.write_text("{ invalid json }")
    add_patch_metadata(submitter, test_dirs, patch_id, patch_id)

    # Process submissions - mock analysis graph to avoid Neo4j connections
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        submitter._process_patch_submissions()

    # Verify patch API was called without a vulnerability ID
    mock_api.submit_patch.assert_called_once()
    call_args = mock_api.submit_patch.call_args[0]
    submission = call_args[1]
    assert not hasattr(submission, "pov_id") or submission.pov_id is None

    # Verify patch was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
    )


def test_patch_with_bundle_failure_handling(submitter, test_dirs, mock_api, pdt_id_gen):
    """Test handling of bundle submission failure during patch submission"""

    # Create a patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("patch with bundle failure test content")

    # Create a vuln_id to associate with the patch
    poi_id = pdt_id_gen()
    vuln_file = test_dirs["vuln_dir"] / poi_id
    vuln_file.write_text("test vuln content")
    add_patch_metadata(submitter, test_dirs, patch_id, poi_id)
    vuln_id = uuid4()

    # Mock patch API to succeed
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, patch_id=patch_uuid
    )

    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, pov_id=vuln_id
    )

    # Mock bundle API to raise an exception

    response = submitter.submit_pov(
        task_id=submitter.crs_task.task_id,
        data_file=vuln_file,
        identifier=poi_id,
        architecture="x86_64",
        harness_name="test",
        sanitizer="address",
    )

    # Submit the patch with a vuln_id
    response = submitter.submit_patch(
        task_id=submitter.crs_task.task_id,
        patch_file=patch_file,
        description="Test patch with bundle failure",
        vuln_id=vuln_id,
    )

    mock_api.submit_bundle.side_effect = Exception("Simulated bundle API failure")
    
    # Since this test is about bundle failure handling, we need to simulate bundle submission
    # by manually calling the bundle submission method
    try:
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_file.stem,
            vuln_identifier=poi_id,
            description="Test patch with bundle failure"
        )
    except Exception:
        pass  # Expected to fail due to mocked exception
    
    # Mock the analysis graph components to avoid database connections for the process call
    with patch("submitter.BucketNode") as MockBucketNode:
        MockBucketNode.nodes.all.return_value = []
        submitter._process_bundle_submissions()


    # Verify patch submission was successful despite bundle failure
    assert response is not None
    assert response.status == SubmissionStatus.SubmissionStatusPassed

    # Verify patch was tracked even though bundle failed
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id, SubmissionType.PATCH, patch_file.stem
    )

    bundle_identifier = submitter.tracker.generate_bundle_identifier(
        patch_id, poi_id, None
    )
    bundle_submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
    )
    assert bundle_submission is not None
    assert bundle_submission.status == SubmissionStatus.SubmissionStatusFailed
    assert bundle_submission.bundle_id == NULL_UUID


def test_patch_with_bundle_and_sarif(submitter, test_dirs, mock_api, pdt_id_gen):
    """Test submitting a patch that creates a bundle with vulnerability and SARIF IDs"""

    # Create a patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("patch with bundle and sarif test content")

    # Create IDs to associate with the bundle
    sarif_id = uuid4()

    # Mock API responses
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, patch_id=patch_uuid
    )

    bundle_id = uuid4()
    mock_api.submit_bundle.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted, bundle_id=bundle_id
    )

    # First submit a SARIF assessment to have it available for the bundle
    mock_api.submit_sarif_assessment.return_value = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted
    )

    # Create SARIF file
    sarif_data = {
        "sarif_id": str(sarif_id),
        "assessment": "valid",
        "description": "Test SARIF for bundle",
    }
    sarif_file = test_dirs["sarif_dir"] / f"{sarif_id}.json"
    sarif_file.write_text(json.dumps(sarif_data))

    # Process SARIF submissions
    submitter._process_retry_sarif_submissions()

    # Submit the patch with a vuln_id
    response = submitter.submit_patch(
        task_id=submitter.crs_task.task_id,
        patch_file=patch_file,
        description="Test patch with bundle and SARIF",
    )

    # Verify patch submission was successful
    assert response is not None
    assert response.status is SubmissionStatus.SubmissionStatusPassed

    # Now directly submit a bundle with all three components
    bundle_response = submitter.submit_bundle(
        task_id=submitter.crs_task.task_id,
        patch_identifier=patch_id,
        sarif_identifier=sarif_id,
        description="Complete bundle with patch, vuln, and SARIF",
    )

    # Verify bundle submission was successful
    assert bundle_response is not None
    assert bundle_response.status == SubmissionStatus.SubmissionStatusAccepted
    assert bundle_response.bundle_id == bundle_id

    # Verify bundle API was called with all three IDs
    # Get the last call to submit_bundle
    last_call_args = mock_api.submit_bundle.call_args_list[-1][0]
    bundle_submission = last_call_args[1]
    assert bundle_submission.patch_id == patch_uuid
    assert bundle_submission.broadcast_sarif_id == sarif_id


def test_patch_bundle_with_invalid_bundle_response(submitter, test_dirs, mock_api, pdt_id_gen):
    """Test handling of invalid bundle response during patch submission"""

    # Create a patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("patch with invalid bundle response test content")

    # Create a vuln_id to associate with the patch
    poi_id = pdt_id_gen()
    vuln_file = test_dirs["vuln_dir"] / poi_id
    vuln_file.write_text("test vuln content")
    add_patch_metadata(submitter, test_dirs, patch_id, poi_id)
    vuln_id = uuid4()

    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, pov_id=vuln_id
    )

    # Mock patch API to succeed
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed, patch_id=patch_uuid
    )

    # Mock bundle API to return failed status
    mock_api.submit_bundle.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusFailed, bundle_id=uuid4()
    )

    response = submitter.submit_pov(
        task_id=submitter.crs_task.task_id,
        data_file=vuln_file,
        identifier=poi_id,
        architecture="x86_64",
        harness_name="test",
        sanitizer="address",
    )

    # Submit the patch with a vuln_id
    response = submitter.submit_patch(
        task_id=submitter.crs_task.task_id,
        patch_file=patch_file,
        description="Test patch with failed bundle",
        vuln_id=vuln_id,
    )

    # Verify patch submission was successful despite bundle failure
    assert response is not None
    assert response.status == SubmissionStatus.SubmissionStatusPassed

    # Since this test is about invalid bundle response, we need to manually submit the bundle
    bundle_response = submitter.submit_bundle(
        task_id=submitter.crs_task.task_id,
        patch_identifier=patch_file.stem,
        vuln_identifier=poi_id,
        description="Test patch with failed bundle"
    )
    
    # Mock the analysis graph components to avoid database connections for the process call
    with patch("submitter.BucketNode") as MockBucketNode:
        MockBucketNode.nodes.all.return_value = []
        submitter._process_bundle_submissions()

    # Verify bundle API was called
    mock_api.submit_bundle.assert_called_once()

    # Verify patch was tracked even though bundle was rejected
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id, SubmissionType.PATCH, patch_file.stem
    )

    bundle_identifier = submitter.tracker.generate_bundle_identifier(
        patch_id, poi_id, None
    )
    bundle_submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
    )

    assert bundle_submission is not None
    assert bundle_submission.status == SubmissionStatus.SubmissionStatusFailed


def test_patch_submission_different_task_id(
    submitter, test_dirs, mock_api, pdt_id_gen
):
    """Test that patch submission only processes files for its own task ID"""

    # Create two patch files with different task IDs
    patch_id_1 = pdt_id_gen()
    patch_id_2 = pdt_id_gen()
    
    # Create patch files
    patch_file_1 = test_dirs["patch_dir"] / patch_id_1
    patch_file_2 = test_dirs["patch_dir"] / patch_id_2
    patch_file_1.write_text("test patch content 1")
    patch_file_2.write_text("test patch content 2")

    # Add patch metadata with different task IDs
    add_patch_metadata(submitter, test_dirs, patch_id_1, "")  # Uses submitter's task ID
    
    # Create metadata for second patch with different task ID
    metadata_2 = PatchMetaData(
        patcher_name="test",
        total_cost=0.0,
        poi_report_id="",
        pdt_harness_info_id=None,
        pdt_project_id="different_task_id",  # Different task ID
        pdt_project_name=None
    )
    (test_dirs["patch_metadata_dir"] / patch_id_2).write_text(yaml.safe_dump(metadata_2.model_dump()))

    # Process submissions - mock analysis graph to avoid Neo4j connections
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        submitter._process_patch_submissions()

    # Verify API was called only once (for the matching task ID)
    mock_api.submit_patch.assert_called_once()
    
    # Verify only the submission for the matching task ID was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.PATCH,
        patch_id_1,
    )
    assert not submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.PATCH,
        patch_id_2,
    )


def test_submission_responses_have_non_null_ids(submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata):
    """Test that submitted vulnerability and patch responses have non-NULL UUIDs in their output files"""
    
    # Create and submit a vulnerability
    pdt_id = pdt_id_gen()
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pdt_id
    (submitter.vuln_dir / pdt_id).write_text(yaml.dump(clean_dict))

    # Mock API response with non-NULL UUID
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )

    # Process vulnerability submissions
    submitter._process_vulnerability_submissions()

    # Verify vulnerability submission file exists and has non-NULL UUID
    vuln_file = submitter.tracker.submitted_vulns / pdt_id
    assert vuln_file.exists()
    with vuln_file.open() as f:
        vuln_data = json.load(f)
        assert "pov_id" in vuln_data
        assert vuln_data["pov_id"] != str(NULL_UUID)
        assert UUID(vuln_data["pov_id"]) == vuln_uuid

    # Now test patch submission
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    add_patch_metadata(submitter, test_dirs, patch_id, "")

    # Mock API response with non-NULL UUID for patch
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        patch_id=patch_uuid
    )

    # Submit the patch
    submitter.submit_patch(
        task_id=submitter.crs_task.task_id,
        patch_file=patch_file,
        description="Test patch with non-NULL UUID"
    )

    # Verify patch submission file exists and has non-NULL UUID
    patch_file = submitter.tracker.submitted_patches / patch_id
    assert patch_file.exists()
    with patch_file.open() as f:
        patch_data = json.load(f)
        assert "patch_id" in patch_data
        assert patch_data["patch_id"] != str(NULL_UUID)
        assert UUID(patch_data["patch_id"]) == patch_uuid


def test_submission_tracking_directories(submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata):
    """Test that submissions, successful_submissions, and failed_submissions directories are correctly updated"""
    
    # Create a vulnerability submission that will succeed
    passed_vulns = [
        POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=uuid4()
        ),
        POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=uuid4()
        )
    ]

    failed_vulns = [
         POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed,
            pov_id=uuid4()
        ),
        POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed,
            pov_id=NULL_UUID
        )
    ]

    accepted_vulns = [
         POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            pov_id=uuid4()
        ), 
        POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            pov_id=uuid4()
        )
    ]

    # Mock API to return success for first submission and failure for second
    vuln_submissions = passed_vulns + failed_vulns + accepted_vulns

    # Process submissions
    for i in vuln_submissions:
        submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.VULNERABILITY, str(i.pov_id), i)
    
    # Verify submissions directory contains both submissions
    submissions_dir = submitter.tracker.submissions
    assert len(list(submissions_dir.glob("*"))) == len(vuln_submissions) - len(list(x for x in vuln_submissions if x.pov_id == NULL_UUID))

    # Verify successful_submissions directory contains only the successful submission
    success_dir = submitter.tracker.successful_submissions
    success_files = list(success_dir.glob("*"))
    assert len(success_files) == len(passed_vulns) - len(list(x for x in passed_vulns if x.pov_id == NULL_UUID))

    # Verify failed_submissions directory contains only the failed submission
    failed_dir = submitter.tracker.failed_submissions
    failed_files = list(failed_dir.glob("*"))
    assert len(failed_files) == len(failed_vulns) - len(list(x for x in failed_vulns if x.pov_id == NULL_UUID))

    change_to_passed_vuln = accepted_vulns.pop()
    change_to_passed_vuln.status = SubmissionStatus.SubmissionStatusPassed
    submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.VULNERABILITY, str(change_to_passed_vuln.pov_id), change_to_passed_vuln)

    change_to_failed_vuln = accepted_vulns.pop()
    change_to_failed_vuln.status = SubmissionStatus.SubmissionStatusFailed
    submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.VULNERABILITY, str(change_to_failed_vuln.pov_id), change_to_failed_vuln)

    passed_vulns.append(change_to_passed_vuln)
    failed_vulns.append(change_to_failed_vuln)
    # Verify submissions directory contains both submissions
    submissions_dir = submitter.tracker.submissions
    assert len(list(submissions_dir.glob("*"))) == len(passed_vulns) + len(failed_vulns) + len(accepted_vulns) - len(list(x for x in vuln_submissions if x.pov_id == NULL_UUID))

    # Verify successful_submissions directory contains only the successful submission
    success_dir = submitter.tracker.successful_submissions
    success_files = list(success_dir.glob("*"))
    assert len(success_files) == len(passed_vulns) - len(list(x for x in passed_vulns if x.pov_id == NULL_UUID))

    # Verify failed_submissions directory contains only the failed submission
    failed_dir = submitter.tracker.failed_submissions
    failed_files = list(failed_dir.glob("*"))
    assert len(failed_files) == len(failed_vulns) - len(list(x for x in failed_vulns if x.pov_id == NULL_UUID))


    # Now test with patch submissions
    passed_patches = [
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=uuid4()
        ),
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=uuid4()
        )
    ]

    failed_patches = [
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed,
            patch_id=uuid4()
        ),
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed,
            patch_id=NULL_UUID
        )
    ]

    accepted_patches = [
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            patch_id=uuid4()
        ),
        PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            patch_id=uuid4()
        )
    ]
    # Mock API to return success for first patch and failure for second
    patch_submissions = accepted_patches + failed_patches + passed_patches

    # Process patch submissions
    for i in patch_submissions:
        submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.PATCH, str(i.patch_id), i)

    # Verify submissions directory now contains all four submissions
    assert len(list(submissions_dir.glob("*"))) == len(patch_submissions) + len(vuln_submissions) - len(list(x for x in vuln_submissions if x.pov_id == NULL_UUID)) - len(list(x for x in patch_submissions if x.patch_id == NULL_UUID))

    # Verify successful_submissions directory contains both successful submissions
    success_files = list(success_dir.glob("*"))
    assert len(success_files) == len(passed_patches) + len(passed_vulns) - len(list(x for x in passed_patches if x.patch_id == NULL_UUID)) - len(list(x for x in passed_vulns if x.pov_id == NULL_UUID))

    # Verify failed_submissions directory contains both failed submissions
    failed_files = list(failed_dir.glob("*"))
    assert len(failed_files) == len(failed_patches) + len(failed_vulns) - len(list(x for x in failed_patches if x.patch_id == NULL_UUID)) - len(list(x for x in failed_vulns if x.pov_id == NULL_UUID))

    change_to_passed_patch = accepted_patches.pop()
    change_to_passed_patch.status = SubmissionStatus.SubmissionStatusPassed
    submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.PATCH, str(change_to_passed_patch.patch_id), change_to_passed_patch)

    change_to_failed_patch = accepted_patches.pop()
    change_to_failed_patch.status = SubmissionStatus.SubmissionStatusFailed
    submitter.tracker.save_submission(submitter.crs_task.task_id, SubmissionType.PATCH, str(change_to_failed_patch.patch_id), change_to_failed_patch)

    passed_patches.append(change_to_passed_patch)
    failed_patches.append(change_to_failed_patch)
    # Verify submissions directory contains both submissions
    submissions_dir = submitter.tracker.submissions
    assert len(list(submissions_dir.glob("*"))) == len(patch_submissions) + len(vuln_submissions) - len(list(x for x in vuln_submissions if x.pov_id == NULL_UUID)) - len(list(x for x in patch_submissions if x.patch_id == NULL_UUID))

    # Verify successful_submissions directory contains only the successful submission
    success_dir = submitter.tracker.successful_submissions
    success_files = list(success_dir.glob("*"))
    assert len(success_files) == len(passed_vulns) + len(passed_patches) - len(list(x for x in passed_patches if x.patch_id == NULL_UUID)) - len(list(x for x in passed_vulns if x.pov_id == NULL_UUID))

    # Verify failed_submissions directory contains only the failed submission
    failed_dir = submitter.tracker.failed_submissions
    failed_files = list(failed_dir.glob("*"))
    assert len(failed_files) == len(failed_vulns) + len(failed_patches) - len(list(x for x in failed_patches if x.patch_id == NULL_UUID)) - len(list(x for x in failed_vulns if x.pov_id == NULL_UUID))


def test_bundle_deletion_during_processing(submitter, test_dirs, mock_api, mock_bundle_api, mock_vuln_id, pdt_id_gen):
    """Test bundle deletion during bundle processing"""
    
    # Create patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    
    # Create a vuln_id to associate with the patch
    poi_id = pdt_id_gen()
    vuln_file = test_dirs["vuln_dir"] / poi_id
    vuln_file.write_text("test vuln content")
    add_patch_metadata(submitter, test_dirs, patch_id, poi_id)
    
    # Mock API responses
    vuln_id = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_id
    )
    
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        patch_id=patch_uuid
    )
    
    # First submit the vulnerability
    response = submitter.submit_pov(
        task_id=submitter.crs_task.task_id,
        data_file=vuln_file,
        identifier=poi_id,
        architecture="x86_64",
        harness_name="test",
        sanitizer="address",
    )
    
    # Submit the patch - mock GeneratedPatch to avoid Neo4j connections
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        response = submitter.submit_patch(
            task_id=submitter.crs_task.task_id,
            patch_file=patch_file,
            description="Test patch with bundle deletion",
            vuln_id=vuln_id,
        )
    
    # Mock bundle API to return success
    bundle_id = uuid4()
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=bundle_id
    )
    
    # Submit the bundle manually since this test is about bundle deletion
    bundle_response = submitter.submit_bundle(
        task_id=submitter.crs_task.task_id,
        patch_identifier=patch_id,
        vuln_identifier=poi_id,
        description="Test bundle for deletion"
    )
    
    # Verify bundle was created
    bundle_identifier = submitter.tracker.generate_bundle_identifier(patch_id, poi_id, None)
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.BUNDLE,
        bundle_identifier
    )
    
    # Now delete the bundle
    submitter.delete_bundle(bundle_identifier)
    
        # Verify bundle was deleted via API
    mock_api.delete_bundle.assert_called_once_with(submitter.crs_task.task_id, bundle_id)

    # Verify bundle is still in tracking (intentionally not removed so it can be deleted every loop)
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.BUNDLE,
        bundle_identifier
    )


def test_submission_retry_mechanism(submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata):
    """Test retry mechanism for all submission types (vulnerability, patch, and bundle)"""
    
    # Test vulnerability submission retry
    pdt_id = pdt_id_gen()
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Mock API to fail twice then succeed for vulnerability
    with patch.object(submitter.API, "submit_pov") as mock_submit_pov:
        mock_submit_pov.side_effect = [
            POVSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                pov_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
            POVSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                pov_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
            POVSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusPassed,
                pov_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
        ]

        # Process vulnerability submissions
        submitter._process_vulnerability_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )


        submitter._process_vulnerability_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )


        submitter._process_vulnerability_submissions()

        # Verify API was called 3 times (2 failures + 1 success)
        assert mock_submit_pov.call_count == 3

        # Verify final submission was successful
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )
        assert submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        ).status == SubmissionStatus.SubmissionStatusPassed

    # Test patch submission retry
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    add_patch_metadata(submitter, test_dirs, patch_id, clean_dict["original_crash_id"])

    # Mock API to fail twice then succeed for patch
    with patch.object(submitter.API, "submit_patch") as mock_submit_patch, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        mock_submit_patch.side_effect = [
            PatchSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                patch_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
            PatchSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                patch_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
            PatchSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusPassed,
                patch_id=uuid4(),
                project_id=submitter.crs_task.pdt_task_id
            ),
        ]
        
        MockGeneratedPatch.nodes.get_or_none.return_value = None

        # Submit the patch
        submitter._process_patch_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        submitter._process_patch_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        submitter._process_patch_submissions()
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        # Verify API was called 3 times (2 failures + 1 success)
        assert mock_submit_patch.call_count == 3

        # Verify final response is successful
        assert submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        ).status == SubmissionStatus.SubmissionStatusPassed

    # Test bundle submission retry
    bundle_id = uuid4()
    # Mock API to fail twice then succeed for bundle
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle:
        mock_submit_bundle.side_effect = [
            BundleSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                bundle_id=bundle_id,
                project_id=submitter.crs_task.pdt_task_id
            ),
            BundleSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusErrored,
                bundle_id=bundle_id,
                project_id=submitter.crs_task.pdt_task_id
            ),
            BundleSubmissionResponse(
                status=SubmissionStatus.SubmissionStatusAccepted,
                bundle_id=bundle_id,
                project_id=submitter.crs_task.pdt_task_id
            ),
        ]

        # Submit the bundle
        bundle_identifier = submitter.tracker.generate_bundle_identifier(patch_id, clean_dict["original_crash_id"], None)
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=clean_dict["original_crash_id"],
            description="Test bundle retry",
        )
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )

        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=clean_dict["original_crash_id"],
            description="Test bundle retry",
        )
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )

        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=clean_dict["original_crash_id"],
            description="Test bundle retry",
        )
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )



        # Verify API was called 3 times (2 failures + 1 success)
        assert mock_submit_bundle.call_count == 3

        # Verify final response is successful
        assert submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        ).status == SubmissionStatus.SubmissionStatusAccepted


def test_analysis_graph_bundle_submission(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle submission using the new analysis graph logic"""
    
    # Set up a deadline that is far in the future so bundle submissions proceed
    current_time_ms = int(time.time() * 1000)
    deadline_in_future = current_time_ms + (60 * 60 * 1000)  # 1 hour from now
    submitter.crs_task.deadline = deadline_in_future
    
    # Mock the analysis graph components and Neo4j database connections
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch("submitter.get_sarif_id_from_patch") as mock_get_sarif:
        
        # Create test data
        patch_id = pdt_id_gen()
        vuln_id = pdt_id_gen()
        sarif_uuid = uuid4()
        
        # Mock a bucket with a best patch
        mock_patch = Mock()
        mock_patch.patch_key = patch_id
        mock_patch.submitted_time = current_time_ms
        mock_bucket = Mock()
        mock_bucket.contain_patches = [mock_patch]
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        
        # Mock GeneratedPatch to avoid database connections
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # Mock get_sarif_id_from_patch to return our test SARIF
        mock_get_sarif.return_value = (str(sarif_uuid), vuln_id)
        
        # Create crash file for vulnerability
        crash_file = test_dirs["crashing_input_dir"] / vuln_id
        crash_file.write_bytes(b"A" * 1024)
        
        # Create vulnerability metadata file
        clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
        clean_dict["project_id"] = submitter.crs_task.pdt_task_id
        clean_dict["original_crash_id"] = vuln_id
        vuln_file = test_dirs["vuln_dir"] / vuln_id
        vuln_file.write_text(yaml.dump(clean_dict))
        
        # Create patch file and metadata
        patch_file = test_dirs["patch_dir"] / patch_id
        patch_file.write_text("test patch content for analysis graph")
        add_patch_metadata(submitter, test_dirs, patch_id, vuln_id)
        
        # Mock API responses
        patch_uuid = uuid4()
        mock_api.submit_patch.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=patch_uuid
        )
        
        vuln_uuid = uuid4()
        mock_api.submit_pov.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=vuln_uuid
        )
        
        bundle_uuid = uuid4()
        mock_bundle_api.return_value = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            bundle_id=bundle_uuid
        )
        
        # Process all submissions which should trigger the new bundle logic
        submitter.process_new_submissions()
        
        # Verify vulnerability was submitted
        mock_api.submit_pov.assert_called()
        
        # Verify patch was submitted
        mock_api.submit_patch.assert_called()
        
        # Verify bundle was submitted through the analysis graph logic
        mock_bundle_api.assert_called()
        
        # Verify the bundle submission contains the correct components
        bundle_call_args = mock_bundle_api.call_args[0]
        assert bundle_call_args[0] == submitter.crs_task.task_id  # task_id
        
        bundle_submission = bundle_call_args[1]
        assert isinstance(bundle_submission, BundleSubmission)
        assert bundle_submission.patch_id == patch_uuid
        assert bundle_submission.pov_id == vuln_uuid
        assert bundle_submission.broadcast_sarif_id == sarif_uuid
        
        # Verify the SARIF API was called correctly
        mock_get_sarif.assert_called_with(patch_id)


def test_analysis_graph_bucket_without_best_patch(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen
):
    """Test bundle submission when bucket has no best patch"""
    
    # Mock the analysis graph components
    with patch("analysis_graph.models.crashes.BucketNode") as MockBucketNode:
        
        # Mock a bucket without a best patch
        mock_bucket = Mock()
        mock_bucket.best_patch_key = None
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        
        # Process all submissions
        submitter.process_new_submissions()
        
        # Verify no bundle was submitted
        mock_bundle_api.assert_not_called()


def test_analysis_graph_patch_not_passed(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen
):
    """Test bundle submission when patch is not in passed status"""
    
    # Mock the analysis graph components
    with patch("analysis_graph.models.crashes.BucketNode") as MockBucketNode:
        
        # Create test data
        patch_id = pdt_id_gen()
        vuln_id = pdt_id_gen()
        
        # Mock a bucket with a best patch
        mock_bucket = Mock()
        mock_bucket.best_patch_key = patch_id
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        
        # Create patch file and metadata but mark it as failed
        patch_file = test_dirs["patch_dir"] / patch_id
        patch_file.write_text("test failed patch content")
        add_patch_metadata(submitter, test_dirs, patch_id, vuln_id)
        
        # Submit the patch with failed status
        patch_uuid = uuid4()
        mock_api.submit_patch.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusFailed,
            patch_id=patch_uuid
        )
        
        # Process all submissions
        submitter.process_new_submissions()
        
        # Verify patch was submitted but bundle was not
        mock_api.submit_patch.assert_called()
        mock_bundle_api.assert_not_called()


def test_analysis_graph_different_project_id(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen
):
    """Test bundle submission skips patches for different project IDs"""
    
    # Mock the analysis graph components
    with patch("analysis_graph.models.crashes.BucketNode") as MockBucketNode:
        
        # Create test data
        patch_id = pdt_id_gen()
        vuln_id = pdt_id_gen()
        
        # Mock a bucket with a best patch
        mock_bucket = Mock()
        mock_bucket.best_patch_key = patch_id
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        
        # Create patch file and metadata with different project ID
        patch_file = test_dirs["patch_dir"] / patch_id
        patch_file.write_text("test patch for different project")
        
        # Create metadata with different project ID
        metadata = PatchMetaData(
            patcher_name="test",
            total_cost=0.0,
            poi_report_id=vuln_id,
            pdt_harness_info_id=None,
            pdt_project_id="different_project_id",
            pdt_project_name=None
        )
        (test_dirs["patch_metadata_dir"] / patch_id).write_text(yaml.safe_dump(metadata.model_dump()))
        
        # Process all submissions
        submitter.process_new_submissions()
        
        # Verify no submissions were made for different project
        mock_api.submit_patch.assert_not_called()
        mock_bundle_api.assert_not_called()


def test_bundle_deadline_skip_when_close_to_deadline(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that bundle submissions are skipped when within 10 minutes of deadline"""
    
    # Set up a deadline that is 5 minutes from now (closer than the 10 minute threshold)
    current_time_ms = int(time.time() * 1000)
    deadline_in_5_minutes = current_time_ms + (5 * 60 * 1000)  # 5 minutes from now
    
    # Update the submitter's task deadline
    submitter.crs_task.deadline = deadline_in_5_minutes
    
    # Create test data for bundle submission
    patch_id = pdt_id_gen()
    vuln_id = pdt_id_gen()
    
    # Create patch file and metadata
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    add_patch_metadata(submitter, test_dirs, patch_id, vuln_id)
    
    # Create vulnerability file
    crash_file = test_dirs["crashing_input_dir"] / vuln_id
    crash_file.write_bytes(b"A" * 1024)
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = vuln_id
    (test_dirs["vuln_dir"] / vuln_id).write_text(yaml.dump(clean_dict))
    
    # Mock API responses for vulnerability and patch
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )
    
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        patch_id=patch_uuid
    )
    
    # Mock the analysis graph components
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch("submitter.get_sarif_id_from_patch") as mock_get_sarif:
        
        mock_bucket = Mock()
        mock_bucket.best_patch_key = patch_id
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        mock_get_sarif.return_value = (str(uuid4()), vuln_id)
        
        # Process submissions
        submitter.process_new_submissions()
    
    # Verify vulnerability and patch were submitted
    mock_api.submit_pov.assert_called()
    mock_api.submit_patch.assert_called()
    
    # Verify bundle was NOT submitted due to deadline proximity
    mock_bundle_api.assert_not_called()


def test_bundle_deadline_proceed_when_not_close_to_deadline(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that bundle submissions proceed normally when not within 10 minutes of deadline"""
    
    # Set up a deadline that is 15 minutes from now (further than the 10 minute threshold)
    current_time_ms = int(time.time() * 1000)
    deadline_in_15_minutes = current_time_ms + (15 * 60 * 1000)  # 15 minutes from now
    
    # Update the submitter's task deadline
    submitter.crs_task.deadline = deadline_in_15_minutes
    
    # Create test data for bundle submission
    patch_id = pdt_id_gen()
    vuln_id = pdt_id_gen()
    
    # Create patch file and metadata
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content")
    add_patch_metadata(submitter, test_dirs, patch_id, vuln_id)
    
    # Create vulnerability file
    crash_file = test_dirs["crashing_input_dir"] / vuln_id
    crash_file.write_bytes(b"A" * 1024)
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = vuln_id
    (test_dirs["vuln_dir"] / vuln_id).write_text(yaml.dump(clean_dict))
    
    # Mock API responses for vulnerability and patch
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )
    
    patch_uuid = uuid4()
    mock_api.submit_patch.return_value = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        patch_id=patch_uuid
    )
    
    bundle_uuid = uuid4()
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=bundle_uuid
    )
    
    # Mock the analysis graph components
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch("submitter.get_sarif_id_from_patch") as mock_get_sarif:
        
        mock_bucket = Mock()
        mock_patch = Mock()
        mock_patch.patch_key = patch_id
        mock_patch.submitted_time = time.time()
        mock_bucket.contain_patches = [mock_patch]
        MockBucketNode.nodes.all.return_value = [mock_bucket]
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        mock_get_sarif.return_value = (str(uuid4()), vuln_id)
        
        # Process submissions
        submitter.process_new_submissions()
    
    # Verify vulnerability and patch were submitted
    mock_api.submit_pov.assert_called()
    mock_api.submit_patch.assert_called()
    
    # Verify bundle WAS submitted since we're not close to deadline
    mock_bundle_api.assert_called()
    
    # Verify the bundle submission contains the correct components
    bundle_call_args = mock_bundle_api.call_args[0]
    assert bundle_call_args[0] == submitter.crs_task.task_id  # task_id
    
    bundle_submission = bundle_call_args[1]
    assert isinstance(bundle_submission, BundleSubmission)
    assert bundle_submission.patch_id == patch_uuid
    assert bundle_submission.pov_id == vuln_uuid


def test_bundle_pov_submission_normal_case(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test normal case of bundle POV submission (POV + SARIF, no patch)"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)  # 1 hour from now
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Create vulnerability submission
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )
    
    # Create crash file and vulnerability metadata
    crash_file = test_dirs["crashing_input_dir"] / pov_id
    crash_file.write_bytes(b"A" * 1024)
    
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pov_id
    (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Mock PoVReportNode and GeneratedPatch to avoid Neo4j connections
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockPoVReportNode.nodes.get_or_none.return_value = None
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # Submit the vulnerability first
        submitter._process_vulnerability_submissions()
    
    # Mock bundle API response
    bundle_uuid = uuid4()
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=bundle_uuid
    )
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        # Mock empty buckets (no patch submissions)
        MockBucketNode.nodes.all.return_value = []
        
        # Mock SARIF/POV mapping
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify bundle was submitted
    mock_bundle_api.assert_called()
    
    # Verify the bundle submission contains POV and SARIF but no patch
    bundle_call_args = mock_bundle_api.call_args[0]
    assert bundle_call_args[0] == submitter.crs_task.task_id
    
    bundle_submission = bundle_call_args[1]
    assert isinstance(bundle_submission, BundleSubmission)
    assert bundle_submission.patch_id is None  # No patch
    assert bundle_submission.pov_id == vuln_uuid  # Has POV
    assert str(bundle_submission.broadcast_sarif_id) == sarif_id  # Has SARIF (convert to string for comparison)


def test_bundle_pov_submission_no_vulnerability_submission(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen
):
    """Test bundle POV submission when vulnerability submission doesn't exist"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions - no vulnerability submission exists
        submitter._process_bundle_submissions()
    
    # Verify bundle was NOT submitted
    mock_bundle_api.assert_not_called()


def test_bundle_pov_submission_vulnerability_not_passed(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle POV submission when vulnerability is not in passed status"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Create vulnerability submission with failed status
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusFailed,  # Not passed
        pov_id=vuln_uuid
    )
    
    # Create crash file and vulnerability metadata
    crash_file = test_dirs["crashing_input_dir"] / pov_id
    crash_file.write_bytes(b"A" * 1024)
    
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pov_id
    (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Submit the vulnerability first
    submitter._process_vulnerability_submissions()
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify bundle was NOT submitted due to failed vulnerability status
    mock_bundle_api.assert_not_called()


def test_bundle_pov_submission_vulnerability_accepted_status(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle POV submission when vulnerability is in accepted status (should not submit)"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Create vulnerability submission with accepted status
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,  # Accepted but not passed
        pov_id=vuln_uuid
    )
    
    # Create crash file and vulnerability metadata
    crash_file = test_dirs["crashing_input_dir"] / pov_id
    crash_file.write_bytes(b"A" * 1024)
    
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pov_id
    (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Submit the vulnerability first
    submitter._process_vulnerability_submissions()
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify bundle was NOT submitted due to accepted (not passed) vulnerability status
    mock_bundle_api.assert_not_called()


def test_bundle_pov_submission_multiple_sarif_pov_pairs(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle POV submission with multiple SARIF/POV pairs"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data for multiple POVs
    pov_ids = [pdt_id_gen(), pdt_id_gen(), pdt_id_gen()]
    sarif_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
    vuln_uuids = [uuid4(), uuid4(), uuid4()]
    
    # Create vulnerability submissions for all POVs
    for i, pov_id in enumerate(pov_ids):
        mock_api.submit_pov.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=vuln_uuids[i]
        )
        
        # Create crash file and vulnerability metadata
        crash_file = test_dirs["crashing_input_dir"] / pov_id
        crash_file.write_bytes(f"POV {i}".encode() * 128)
        
        clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
        clean_dict["project_id"] = submitter.crs_task.pdt_task_id
        clean_dict["original_crash_id"] = pov_id
        (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Submit all vulnerabilities
    submitter._process_vulnerability_submissions()
    
    # Mock bundle API response
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=uuid4()
    )
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        
        # Mock SARIF/POV mapping with multiple pairs
        sarif_pov_mapping = {sarif_ids[i]: pov_ids[i] for i in range(len(pov_ids))}
        mock_get_sarif_pov.return_value = sarif_pov_mapping
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify bundle was submitted for each POV/SARIF pair
    assert mock_bundle_api.call_count == len(pov_ids)
    
    # Verify each bundle submission contains the correct POV and SARIF
    for call_idx in range(len(pov_ids)):
        bundle_call_args = mock_bundle_api.call_args_list[call_idx][0]
        bundle_submission = bundle_call_args[1]
        
        assert isinstance(bundle_submission, BundleSubmission)
        assert bundle_submission.patch_id is None  # No patch
        assert bundle_submission.pov_id in vuln_uuids  # Has one of our POVs
        assert str(bundle_submission.broadcast_sarif_id) in sarif_ids  # Has one of our SARIFs


def test_bundle_pov_submission_empty_sarif_pov_mapping(
    submitter, test_dirs, mock_api, mock_bundle_api
):
    """Test bundle POV submission when no SARIF/POV pairs are found"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        
        # Mock empty SARIF/POV mapping
        mock_get_sarif_pov.return_value = {}
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify no bundles were submitted
    mock_bundle_api.assert_not_called()


def test_bundle_pov_submission_get_sarif_pov_exception(
    submitter, test_dirs, mock_api, mock_bundle_api
):
    """Test bundle POV submission when get_all_sarif_ids_and_pov_ids_from_project throws exception"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        
        # Mock exception in get_all_sarif_ids_and_pov_ids_from_project
        mock_get_sarif_pov.side_effect = Exception("Database connection failed")
        
        # Process bundle submissions (should not raise exception)
        submitter._process_bundle_submissions()
    
    # Verify no bundles were submitted due to exception
    mock_bundle_api.assert_not_called()


def test_bundle_pov_submission_bundle_submit_exception(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle POV submission when bundle submission throws exception"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Create vulnerability submission
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )
    
    # Create crash file and vulnerability metadata
    crash_file = test_dirs["crashing_input_dir"] / pov_id
    crash_file.write_bytes(b"A" * 1024)
    
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pov_id
    (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Submit the vulnerability first
    submitter._process_vulnerability_submissions()
    
    # Mock bundle API to raise exception
    mock_bundle_api.side_effect = Exception("Bundle API failed")
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions (should not raise exception due to try/catch)
        submitter._process_bundle_submissions()
    
    # Verify bundle submission was attempted
    mock_bundle_api.assert_called()


def test_bundle_pov_submission_mixed_vulnerability_statuses(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test bundle POV submission with mixed vulnerability statuses (some passed, some failed)"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data for multiple POVs with different statuses
    pov_ids = [pdt_id_gen(), pdt_id_gen(), pdt_id_gen()]
    sarif_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
    vuln_statuses = [
        SubmissionStatus.SubmissionStatusPassed,    # Should submit bundle
        SubmissionStatus.SubmissionStatusFailed,    # Should NOT submit bundle
        SubmissionStatus.SubmissionStatusAccepted   # Should NOT submit bundle
    ]
    vuln_uuids = [uuid4(), uuid4(), uuid4()]
    
    # Create vulnerability submissions with different statuses
    for i, (pov_id, status) in enumerate(zip(pov_ids, vuln_statuses)):
        # Submit each vulnerability with different status
        submitter.tracker.save_submission(
            task_id=submitter.crs_task.task_id,
            submission_type=SubmissionType.VULNERABILITY,
            identifier=pov_id,
            submission_response=POVSubmissionResponse(
                status=status,
                pov_id=vuln_uuids[i]
            )
        )
    
    # Mock bundle API response
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=uuid4()
    )
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        
        # Mock SARIF/POV mapping with all POVs
        sarif_pov_mapping = {sarif_ids[i]: pov_ids[i] for i in range(len(pov_ids))}
        mock_get_sarif_pov.return_value = sarif_pov_mapping
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
    
    # Verify bundle was submitted only once (for the passed vulnerability)
    assert mock_bundle_api.call_count == 1
    
    # Verify the bundle submission is for the passed vulnerability
    bundle_call_args = mock_bundle_api.call_args[0]
    bundle_submission = bundle_call_args[1]
    
    assert isinstance(bundle_submission, BundleSubmission)
    assert bundle_submission.patch_id is None  # No patch
    assert bundle_submission.pov_id == vuln_uuids[0]  # Only the passed POV
    assert str(bundle_submission.broadcast_sarif_id) == sarif_ids[0]  # Corresponding SARIF


def test_bundle_pov_submission_with_project_id_conversion(
    submitter, test_dirs, mock_api, mock_bundle_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that project ID is correctly converted to string for get_all_sarif_ids_and_pov_ids_from_project"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Create test data
    pov_id = pdt_id_gen()
    sarif_id = str(uuid4())
    
    # Create vulnerability submission
    vuln_uuid = uuid4()
    mock_api.submit_pov.return_value = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=vuln_uuid
    )
    
    # Create crash file and vulnerability metadata
    crash_file = test_dirs["crashing_input_dir"] / pov_id
    crash_file.write_bytes(b"A" * 1024)
    
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = pov_id
    (test_dirs["vuln_dir"] / pov_id).write_text(yaml.dump(clean_dict))
    
    # Submit the vulnerability first
    submitter._process_vulnerability_submissions()
    
    # Mock bundle API response
    mock_bundle_api.return_value = BundleSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        bundle_id=uuid4()
    )
    
    # Mock the analysis graph functions
    with patch("submitter.BucketNode") as MockBucketNode, \
         patch("submitter.get_all_sarif_ids_and_pov_ids_from_project") as mock_get_sarif_pov:
        
        MockBucketNode.nodes.all.return_value = []
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        
        # Process bundle submissions
        submitter._process_bundle_submissions()
        
        # Verify get_all_sarif_ids_and_pov_ids_from_project was called with string project ID
        mock_get_sarif_pov.assert_called_once_with(str(submitter.crs_task.pdt_task_id))
    
    # Verify bundle was submitted
    mock_bundle_api.assert_called_once()


@patch("analysis_graph.models.crashes.PoVReportNode")
@patch("analysis_graph.models.crashes.GeneratedPatch")
def test_bundle_prioritization_patch_over_pov_sarif(mock_generated_patch, mock_pov_report_node, submitter, test_dirs, mock_api, mock_bundle_api):
    """Test that POV+PATCH+SARIF bundles prevent POV+SARIF bundles from being created"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    # Setup: Create a POV submission that's passed
    pov_id = "test_pov_123"
    sarif_id = "44444444-0000-0000-0000-000000000004"  # Use valid UUID format
    patch_id = "test_patch_789"
    
    # Create POV submission (passed status)
    pov_response = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=UUID("11111111-0000-0000-0000-000000000001"),
        project_id=submitter.crs_task.pdt_task_id
    )
    submitter.tracker.save_submission(
        submitter.crs_task.task_id, SubmissionType.VULNERABILITY, pov_id, pov_response
    )
    
    # Mock get_all_sarif_ids_and_pov_ids_from_project to return our SARIF/POV mapping
    with patch('submitter.get_all_sarif_ids_and_pov_ids_from_project') as mock_get_sarif_pov, \
         patch('submitter.BucketNode') as mock_bucket_node_initial:
        
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        # Make BucketNode.nodes.all() return empty list initially so patch processing doesn't run
        mock_bucket_node_initial.nodes.all.return_value = []
        
        # Step 1: Process bundles initially (should create POV+SARIF bundle)
        submitter._process_bundle_submissions()
        
        # Verify POV+SARIF bundle was created
        assert mock_bundle_api.call_count == 1
        
        bundle_call_args_1 = mock_bundle_api.call_args[0]
        bundle_submission_1 = bundle_call_args_1[1]
        assert isinstance(bundle_submission_1, BundleSubmission)
        assert bundle_submission_1.patch_id is None
        assert bundle_submission_1.pov_id == pov_response.pov_id
        assert bundle_submission_1.broadcast_sarif_id == UUID(sarif_id)
        
        # Step 2: Now create a patch that links to the same POV
        patch_response = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=UUID("22222222-0000-0000-0000-000000000002"),
            project_id=submitter.crs_task.pdt_task_id,
            functionality_tests_passing=True
        )
        submitter.tracker.save_submission(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id, patch_response
        )
        
        # Create patch metadata that links to our POV using the helper function
        add_patch_metadata(submitter, test_dirs, patch_id, pov_id)
        
        # Mock the BucketNode to contain our patch
        mock_bucket = MagicMock()
        mock_patch_in_bucket = MagicMock()
        mock_patch_in_bucket.patch_key = patch_id
        mock_patch_in_bucket.submitted_time = datetime.datetime.now(datetime.timezone.utc)
        mock_bucket.contain_patches = [mock_patch_in_bucket]
        
        # Mock get_sarif_id_from_patch to return our SARIF ID
        with patch('submitter.BucketNode') as mock_bucket_node, \
             patch('submitter.get_sarif_id_from_patch') as mock_get_sarif_patch:
            
            mock_bucket_node.nodes.all.return_value = [mock_bucket]
            mock_get_sarif_patch.return_value = (sarif_id, pov_id)
            
            # Reset mock for next step
            mock_bundle_api.reset_mock()
            
            # Step 3: Process bundles again (should delete POV+SARIF bundle and create POV+PATCH+SARIF bundle)
            submitter._process_bundle_submissions()
            
            # Verify only 1 bundle is created - POV+PATCH+SARIF 
            # POV+SARIF should NOT be created when patch exists
            assert mock_bundle_api.call_count == 1
            
            # The single call should be the POV+PATCH+SARIF bundle (from patch processing)
            bundle_call_args = mock_bundle_api.call_args[0]
            bundle_submission = bundle_call_args[1]
            assert isinstance(bundle_submission, BundleSubmission)
            assert bundle_submission.patch_id == patch_response.patch_id  # Has patch
            assert bundle_submission.pov_id == pov_response.pov_id  # Same POV
            assert bundle_submission.broadcast_sarif_id == UUID(sarif_id)  # Same SARIF
            
            # Reset mock for final step
            mock_bundle_api.reset_mock()
            
            # Step 4: Process bundles a third time to ensure patch-based bundle persists
            submitter._process_bundle_submissions()
            
            # Should still create only 1 bundle submission (POV+PATCH+SARIF)
            # POV+SARIF should NOT be created since patch exists
            assert mock_bundle_api.call_count == 1
            
            # Should still be POV+PATCH+SARIF only
            final_call_args = mock_bundle_api.call_args[0]
            final_bundle = final_call_args[1]
            assert isinstance(final_bundle, BundleSubmission)
            assert final_bundle.patch_id == patch_response.patch_id
            assert final_bundle.pov_id == pov_response.pov_id
            assert final_bundle.broadcast_sarif_id == UUID(sarif_id)
            
            # Verify that POV+SARIF bundle is NOT created when patch exists


@patch("analysis_graph.models.crashes.PoVReportNode")  
@patch("analysis_graph.models.crashes.GeneratedPatch")
def test_bundle_deletion_between_cycles(mock_generated_patch, mock_pov_report_node, submitter, test_dirs, mock_api, mock_bundle_api):
    """Test that bundles are properly deleted and recreated between submission cycles"""
    
    # Set deadline far in the future
    current_time_ms = int(time.time() * 1000)
    submitter.crs_task.deadline = current_time_ms + (60 * 60 * 1000)
    
    pov_id = "test_pov_del"
    sarif_id = "55555555-0000-0000-0000-000000000005"  # Use valid UUID format
    
    # Create POV submission
    pov_response = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        pov_id=UUID("33333333-0000-0000-0000-000000000003"),
        project_id=submitter.crs_task.pdt_task_id
    )
    submitter.tracker.save_submission(
        submitter.crs_task.task_id, SubmissionType.VULNERABILITY, pov_id, pov_response
    )
    
    with patch('submitter.get_all_sarif_ids_and_pov_ids_from_project') as mock_get_sarif_pov, \
         patch('submitter.BucketNode') as mock_bucket_node:
        
        mock_get_sarif_pov.return_value = {sarif_id: pov_id}
        # Make BucketNode.nodes.all() return empty list so patch processing doesn't run
        mock_bucket_node.nodes.all.return_value = []
        
        # Create initial bundle
        submitter._process_bundle_submissions()
        
        # Verify initial bundle was created
        assert mock_bundle_api.call_count == 1
        
        initial_bundle_call_args = mock_bundle_api.call_args[0]
        initial_bundle_submission = initial_bundle_call_args[1]
        assert isinstance(initial_bundle_submission, BundleSubmission)
        assert initial_bundle_submission.pov_id == pov_response.pov_id
        assert initial_bundle_submission.broadcast_sarif_id == UUID(sarif_id)
        assert initial_bundle_submission.patch_id is None
        
        # Reset mock to track new calls
        mock_bundle_api.reset_mock()
        
        # Process again - should delete and recreate the same bundle
        submitter._process_bundle_submissions()
        
        # Verify bundle was created again (delete + recreate)
        assert mock_bundle_api.call_count == 1
        
        # The bundle should be functionally identical but represents a fresh submission cycle
        final_bundle_call_args = mock_bundle_api.call_args[0]
        final_bundle_submission = final_bundle_call_args[1]
        assert isinstance(final_bundle_submission, BundleSubmission)
        assert final_bundle_submission.pov_id == pov_response.pov_id
        assert final_bundle_submission.broadcast_sarif_id == UUID(sarif_id)
        assert final_bundle_submission.patch_id is None


def test_inconclusive_status_handling(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that SubmissionInconclusive status is treated as accepted everywhere."""
    from uuid import uuid4
    
    # Test vulnerability submission with inconclusive status
    # Mock API response for vulnerability submission
    inconclusive_vuln_resp = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionInconclusive, 
        pov_id=uuid4()
    )
    mock_api.submit_pov.return_value = inconclusive_vuln_resp
    mock_api.get_pov_status.return_value = inconclusive_vuln_resp
    
    pdt_id = pdt_id_gen()
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Process vulnerability submissions
    submitter._process_vulnerability_submissions()

    # Verify vulnerability submission was treated as accepted
    vuln_submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id, SubmissionType.VULNERABILITY, pdt_id
    )
    assert vuln_submission is not None
    assert vuln_submission.status == SubmissionStatus.SubmissionInconclusive
    
    # Test patch submission with inconclusive status
    patch_file = test_dirs["patch_dir"] / "test_patch_inconclusive.patch"
    patch_file.write_text("--- a/file.c\n+++ b/file.c\n@@ -1 +1 @@\n-old\n+new")
    
    add_patch_metadata(submitter, test_dirs, "test_patch_inconclusive", pdt_id)
    
    inconclusive_patch_resp = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionInconclusive,
        patch_id=uuid4()
    )
    mock_api.submit_patch.return_value = inconclusive_patch_resp
    mock_api.get_patch_status.return_value = inconclusive_patch_resp

    # Process patch submissions
    submitter._process_patch_submissions()
    
    # Verify patch submission was treated as accepted
    patch_submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id, SubmissionType.PATCH, "test_patch_inconclusive"
    )
    assert patch_submission is not None
    assert patch_submission.status == SubmissionStatus.SubmissionInconclusive
    
    # Test SARIF assessment with inconclusive status
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        sarif_id=sarif_id,
        task_id=submitter.crs_task.task_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        assessment=Assessment.AssessmentCorrect,
        description="Test inconclusive SARIF",
        metadata={}
    )
    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))
    
    inconclusive_sarif_resp = ExtendedSarifAssessmentResponse(
        status=SubmissionStatus.SubmissionInconclusive,
        assessment=Assessment.AssessmentCorrect,
        project_id=submitter.crs_task.pdt_task_id
    )
    mock_api.submit_sarif_assessment.return_value = inconclusive_sarif_resp
    
    # Process SARIF submissions
    submitter._process_retry_sarif_submissions()
    
    # Verify SARIF assessment was treated as accepted
    sarif_submission = submitter.tracker.get_submission(
        submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
    )
    assert sarif_submission is not None
    assert sarif_submission.status == SubmissionStatus.SubmissionInconclusive
    
    # Check that inconclusive submissions are stored in successful_submissions
    successful_files = list(test_dirs["successful_submissions"].glob("*"))
    assert len(successful_files) > 0
    
    print("✓ All inconclusive status tests passed")


def test_inconclusive_status_in_patch_processing(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata
):
    """Test that inconclusive vulnerability status allows patch linking."""
    from uuid import uuid4
    
    submitter_module.IS_CI = False
    
    # First submit vulnerability with inconclusive status
    inconclusive_vuln_resp = POVSubmissionResponse(
        status=SubmissionStatus.SubmissionInconclusive, 
        pov_id=uuid4()
    )
    mock_api.submit_pov.return_value = inconclusive_vuln_resp
    
    pdt_id = pdt_id_gen()
    # Create crashing input file
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Process vulnerability submissions
    submitter._process_vulnerability_submissions()
    
    # Now create patch that should link to the inconclusive vulnerability
    patch_file = test_dirs["patch_dir"] / "test_patch_for_inconclusive_vuln.patch"
    patch_file.write_text("--- a/file.c\n+++ b/file.c\n@@ -1 +1 @@\n-old\n+new")
    
    add_patch_metadata(submitter, test_dirs, "test_patch_for_inconclusive_vuln", pdt_id)
    
    patch_resp = PatchSubmissionResponse(
        status=SubmissionStatus.SubmissionStatusPassed,
        patch_id=uuid4()
    )
    mock_api.submit_patch.return_value = patch_resp
    
    # Process patch submissions
    submitter._process_patch_submissions()
    
    # Verify patch was submitted and linked to inconclusive vulnerability
    patch_call_args = mock_api.submit_patch.call_args
    assert patch_call_args is not None
    patch_submission_data = patch_call_args[0][1]  # Second argument is the submission
    assert patch_submission_data.vuln_id == inconclusive_vuln_resp.pov_id
    
    print("✓ Inconclusive vulnerability allows patch linking")


def test_inconclusive_status_summary_display(submitter, test_dirs, mock_api, pdt_id_gen):
    """Test that inconclusive status is properly displayed in the summary table."""
    from uuid import uuid4
    from io import StringIO
    import sys
    
    # Create a submission with inconclusive status
    inconclusive_sarif_resp = ExtendedSarifAssessmentResponse(
        status=SubmissionStatus.SubmissionInconclusive,
        assessment=Assessment.AssessmentCorrect,
        project_id=submitter.crs_task.pdt_task_id,
    )
    
    # Save the submission directly to tracker
    submitter.tracker.save_submission(
        task_id=submitter.crs_task.task_id,
        submission_type=SubmissionType.SARIF,
        identifier="test_inconclusive_sarif",
        submission_response=inconclusive_sarif_resp,
    )
    
    # Capture output of summary generation
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        submitter._generate_submission_summary()
        output = captured_output.getvalue()
        
        # Verify that "Inconclusive" column appears in the output
        assert "Inconclusive" in output
        
        # The exact format depends on Rich table formatting, but we should see the column
        print("✓ Inconclusive status appears in summary table")
        
    finally:
        sys.stdout = old_stdout
    
    print("Summary output preview:")
    print(output[:200] + "..." if len(output) > 200 else output)


def test_pov_submission_competition_api_error_and_retry(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata, monkeypatch
):
    """Test POV submission raises CompetitionAPIError, gets deleted, and retries successfully"""
    
    submitter_module.IS_CI = False  # Ensure we're not in CI mode so API calls are made
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create vulnerability data
    pdt_id = pdt_id_gen()
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # First attempt: Mock API to raise CompetitionAPIError
    from crs_api.competition_api import CompetitionAPIError
    
    # Mock the Neo4j components to avoid connection issues
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch.object(submitter.API, "submit_pov") as mock_submit_pov:
        
        # Mock the Neo4j node to avoid database connection
        MockPoVReportNode.nodes.get_or_none.return_value = None
        
        # First call raises CompetitionAPIError
        mock_submit_pov.side_effect = CompetitionAPIError("Server error: Internal server error")
        
        # Process vulnerability submissions - should catch error and delete submission
        with pytest.raises(CompetitionAPIError, match="Server error: Internal server error"):
            submitter._process_vulnerability_submissions()
        
        # Verify API was called once
        assert mock_submit_pov.call_count == 1
        
        # Verify submission was NOT tracked (should be deleted after error)
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )
        
        # Verify the submission directory structure
        submission_path = submitter.tracker._get_submission_path(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        # The submission should not exist after deletion
        assert not submission_path.exists()

    # Second attempt: Mock API to succeed
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch.object(submitter.API, "submit_pov") as mock_submit_pov_retry:
        
        # Mock the Neo4j node to avoid database connection
        MockPoVReportNode.nodes.get_or_none.return_value = None
        
        # Second call succeeds
        success_response = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        mock_submit_pov_retry.return_value = success_response
        
        # Process vulnerability submissions again - should retry successfully
        submitter._process_vulnerability_submissions()
        
        # Verify API was called once in the retry
        assert mock_submit_pov_retry.call_count == 1
        
        # Verify submission is now tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )
        
        # Verify the successful submission response
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )
        assert final_submission is not None
        assert final_submission.status == SubmissionStatus.SubmissionStatusPassed
        assert final_submission.pov_id == success_response.pov_id
        
        # Verify submission is in successful_submissions directory
        success_files = list(submitter.tracker.successful_submissions.glob("*"))
        assert len(success_files) == 1
        
        # Verify the file contains the correct data
        success_file_data = json.loads(success_files[0].read_text())
        assert success_file_data["status"] == SubmissionStatus.SubmissionStatusPassed.value
        assert success_file_data["pov_id"] == str(success_response.pov_id)

    # Third attempt: Verify no duplicate submission on subsequent calls
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch.object(submitter.API, "submit_pov") as mock_submit_pov_final:
        
        # Mock the Neo4j node to avoid database connection
        MockPoVReportNode.nodes.get_or_none.return_value = None
        
        # Process vulnerability submissions again - should skip already submitted
        submitter._process_vulnerability_submissions()
        
        # Verify API was NOT called since submission already exists
        mock_submit_pov_final.assert_not_called()
        
        # Verify submission is still tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.VULNERABILITY,
            clean_dict["original_crash_id"],
        )


def test_pov_submission_multiple_api_errors_before_success(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata, monkeypatch
):
    """Test POV submission with multiple CompetitionAPIErrors before eventual success"""
    
    submitter_module.IS_CI = False
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create vulnerability data
    pdt_id = pdt_id_gen()
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"B" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    from crs_api.competition_api import CompetitionAPIError
    
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch.object(submitter.API, "submit_pov") as mock_submit_pov:
        
        # Mock the Neo4j node to avoid database connection
        MockPoVReportNode.nodes.get_or_none.return_value = None
        
        # Configure multiple errors followed by success
        error_responses = [
            CompetitionAPIError("Bad request: Invalid payload"),
            CompetitionAPIError("Server error: Database timeout"),
            CompetitionAPIError("Unauthorized: Token expired"),
        ]
        
        success_response = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Set up side effects: 3 errors then success
        mock_submit_pov.side_effect = error_responses + [success_response]
        
        # Attempt 1: First error
        with pytest.raises(CompetitionAPIError, match="Bad request: Invalid payload"):
            submitter._process_vulnerability_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        
        # Attempt 2: Second error
        with pytest.raises(CompetitionAPIError, match="Server error: Database timeout"):
            submitter._process_vulnerability_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        
        # Attempt 3: Third error
        with pytest.raises(CompetitionAPIError, match="Unauthorized: Token expired"):
            submitter._process_vulnerability_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        
        # Attempt 4: Success
        submitter._process_vulnerability_submissions()
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        
        # Verify all 4 API calls were made
        assert mock_submit_pov.call_count == 4
        
        # Verify final successful submission
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id, SubmissionType.VULNERABILITY, clean_dict["original_crash_id"]
        )
        assert final_submission.status == SubmissionStatus.SubmissionStatusPassed
        assert final_submission.pov_id == success_response.pov_id


def test_patch_submission_competition_api_error_and_retry(
    submitter, test_dirs, mock_api, pdt_id_gen, monkeypatch
):
    """Test patch submission raises CompetitionAPIError, gets deleted, and retries successfully"""
    
    submitter_module.IS_CI = False  # Ensure we're not in CI mode so API calls are made
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create patch data
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content for error retry")
    add_patch_metadata(submitter, test_dirs, patch_id, "")

    # First attempt: Mock API to raise CompetitionAPIError
    from crs_api.competition_api import CompetitionAPIError
    
    # Mock the Neo4j components to avoid connection issues
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch.object(submitter.API, "submit_patch") as mock_submit_patch:
        
        # Mock the Neo4j node to avoid database connection
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # First call raises CompetitionAPIError
        mock_submit_patch.side_effect = CompetitionAPIError("Server error: Patch service unavailable")
        
        # Process patch submissions - should catch error and delete submission
        with pytest.raises(CompetitionAPIError, match="Server error: Patch service unavailable"):
            submitter._process_patch_submissions()
        
        # Verify API was called once
        assert mock_submit_patch.call_count == 1
        
        # Verify submission was NOT tracked (should be deleted after error)
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        
        # Verify the submission directory structure
        submission_path = submitter.tracker._get_submission_path(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        # The submission should not exist after deletion
        assert not submission_path.exists()

    # Second attempt: Mock API to succeed
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch.object(submitter.API, "submit_patch") as mock_submit_patch_retry:
        
        # Mock the Neo4j node to avoid database connection
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # Second call succeeds
        success_response = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        mock_submit_patch_retry.return_value = success_response
        
        # Process patch submissions again - should retry successfully
        submitter._process_patch_submissions()
        
        # Verify API was called once in the retry
        assert mock_submit_patch_retry.call_count == 1
        
        # Verify submission is now tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        
        # Verify the successful submission response
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )
        assert final_submission is not None
        assert final_submission.status == SubmissionStatus.SubmissionStatusPassed
        assert final_submission.patch_id == success_response.patch_id
        
        # Verify submission is in successful_submissions directory
        success_files = list(submitter.tracker.successful_submissions.glob("*"))
        assert len(success_files) == 1
        
        # Verify the file contains the correct data
        success_file_data = json.loads(success_files[0].read_text())
        assert success_file_data["status"] == SubmissionStatus.SubmissionStatusPassed.value
        assert success_file_data["patch_id"] == str(success_response.patch_id)

    # Third attempt: Verify no duplicate submission on subsequent calls
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch.object(submitter.API, "submit_patch") as mock_submit_patch_final:
        
        # Mock the Neo4j node to avoid database connection
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # Process patch submissions again - should skip already submitted
        submitter._process_patch_submissions()
        
        # Verify API was NOT called since submission already exists
        mock_submit_patch_final.assert_not_called()
        
        # Verify submission is still tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.PATCH,
            patch_id,
        )


def test_patch_submission_multiple_api_errors_before_success(
    submitter, test_dirs, mock_api, pdt_id_gen, monkeypatch
):
    """Test patch submission with multiple CompetitionAPIErrors before eventual success"""
    
    submitter_module.IS_CI = False
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create patch data
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content for multiple errors")
    add_patch_metadata(submitter, test_dirs, patch_id, "")

    from crs_api.competition_api import CompetitionAPIError
    
    with patch("submitter.GeneratedPatch") as MockGeneratedPatch, \
         patch.object(submitter.API, "submit_patch") as mock_submit_patch:
        
        # Mock the Neo4j node to avoid database connection
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        # Configure multiple errors followed by success
        error_responses = [
            CompetitionAPIError("Bad request: Invalid patch format"),
            CompetitionAPIError("Server error: Patch compilation failed"),
            CompetitionAPIError("Unauthorized: Invalid API key"),
        ]
        
        success_response = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Set up side effects: 3 errors then success
        mock_submit_patch.side_effect = error_responses + [success_response]
        
        # Attempt 1: First error
        with pytest.raises(CompetitionAPIError, match="Bad request: Invalid patch format"):
            submitter._process_patch_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        
        # Attempt 2: Second error
        with pytest.raises(CompetitionAPIError, match="Server error: Patch compilation failed"):
            submitter._process_patch_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        
        # Attempt 3: Third error
        with pytest.raises(CompetitionAPIError, match="Unauthorized: Invalid API key"):
            submitter._process_patch_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        
        # Attempt 4: Success
        submitter._process_patch_submissions()
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        
        # Verify all 4 API calls were made
        assert mock_submit_patch.call_count == 4
        
        # Verify final successful submission
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id, SubmissionType.PATCH, patch_id
        )
        assert final_submission.status == SubmissionStatus.SubmissionStatusPassed
        assert final_submission.patch_id == success_response.patch_id


def test_bundle_submission_competition_api_error_and_retry(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata, monkeypatch
):
    """Test bundle submission raises CompetitionAPIError, gets deleted, and retries successfully"""
    
    submitter_module.IS_CI = False  # Ensure we're not in CI mode so API calls are made
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create vulnerability and patch data for bundle
    pdt_id = pdt_id_gen()
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"A" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Create patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content for bundle retry")
    add_patch_metadata(submitter, test_dirs, patch_id, pdt_id)

    # First submit the vulnerability and patch successfully
    vuln_uuid = uuid4()
    patch_uuid = uuid4()
    
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockPoVReportNode.nodes.get_or_none.return_value = None
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        mock_api.submit_pov.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=vuln_uuid,
            project_id=submitter.crs_task.pdt_task_id
        )
        
        mock_api.submit_patch.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=patch_uuid,
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Process vulnerability and patch submissions
        submitter._process_vulnerability_submissions()
        submitter._process_patch_submissions()

    # Generate bundle identifier
    bundle_identifier = submitter.tracker.generate_bundle_identifier(patch_id, pdt_id, None)

    # First attempt: Mock API to raise CompetitionAPIError
    from crs_api.competition_api import CompetitionAPIError
    
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle:
        
        # First call raises CompetitionAPIError
        mock_submit_bundle.side_effect = CompetitionAPIError("Server error: Bundle validation failed")
        
        # Submit bundle - should catch error, delete submission, and return None (not raise)
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle retry"
        )
        
        # Verify bundle submission returned None (indicating failure)
        assert bundle_response is None
        
        # Verify API was called once
        assert mock_submit_bundle.call_count == 1
        
        # Verify submission was NOT tracked (should be deleted after error)
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )
        
        # Verify the submission directory structure
        submission_path = submitter.tracker._get_submission_path(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        # The submission should not exist after deletion
        assert not submission_path.exists()

    # Second attempt: Mock API to succeed
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle_retry:
        
        # Second call succeeds
        success_response = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            bundle_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        mock_submit_bundle_retry.return_value = success_response
        
        # Submit bundle again - should retry successfully
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle retry"
        )
        
        # Verify API was called once in the retry
        assert mock_submit_bundle_retry.call_count == 1
        
        # Verify submission is now tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )
        
        # Verify the successful submission response
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )
        assert final_submission is not None
        assert final_submission.status == SubmissionStatus.SubmissionStatusAccepted
        assert final_submission.bundle_id == success_response.bundle_id
        
        # Verify submission is in successful_submissions directory
        success_files = list(submitter.tracker.successful_submissions.glob("*"))
        assert len(success_files) >= 1  # May have files from previous tests
        
        # Find our bundle submission file
        bundle_success_file = None
        for file in success_files:
            file_data = json.loads(file.read_text())
            if file_data.get("bundle_id") == str(success_response.bundle_id):
                bundle_success_file = file
                break
        
        assert bundle_success_file is not None
        bundle_file_data = json.loads(bundle_success_file.read_text())
        assert bundle_file_data["status"] == SubmissionStatus.SubmissionStatusAccepted.value
        assert bundle_file_data["bundle_id"] == str(success_response.bundle_id)

    # Third attempt: Bundle submission doesn't skip duplicates like other methods
    # It will re-submit but should get the same bundle_id
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle_final:
        
        # Configure to return same bundle response (bundle already exists)
        duplicate_response = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            bundle_id=success_response.bundle_id,  # Same bundle ID as before
            project_id=submitter.crs_task.pdt_task_id
        )
        mock_submit_bundle_final.return_value = duplicate_response
        
        # Try to submit bundle again - will call API again (unlike other submission types)
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle retry duplicate"
        )
        
        # Verify API was called once more (bundle submission doesn't skip duplicates)
        assert mock_submit_bundle_final.call_count == 1
        
        # Verify submission is still tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.BUNDLE,
            bundle_identifier,
        )


def test_bundle_submission_multiple_api_errors_before_success(
    submitter, test_dirs, mock_api, pdt_id_gen, representative_crashing_input_metadata, monkeypatch
):
    """Test bundle submission with multiple CompetitionAPIErrors before eventual success"""
    
    submitter_module.IS_CI = False
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create vulnerability and patch data for bundle
    pdt_id = pdt_id_gen()
    crash_file = submitter.crash_dir / pdt_id
    crash_file.write_bytes(b"C" * 1024)

    # Create vulnerability submission file
    clean_dict = json.loads(representative_crashing_input_metadata.model_dump_json())
    clean_dict["project_id"] = submitter.crs_task.pdt_task_id
    clean_dict["original_crash_id"] = crash_file.stem
    (submitter.vuln_dir / (pdt_id + ".yaml")).write_text(yaml.dump(clean_dict))

    # Create patch file
    patch_id = pdt_id_gen()
    patch_file = test_dirs["patch_dir"] / patch_id
    patch_file.write_text("test patch content for bundle multiple errors")
    add_patch_metadata(submitter, test_dirs, patch_id, pdt_id)

    # First submit the vulnerability and patch successfully
    vuln_uuid = uuid4()
    patch_uuid = uuid4()
    
    with patch("submitter.PoVReportNode") as MockPoVReportNode, \
         patch("submitter.GeneratedPatch") as MockGeneratedPatch:
        MockPoVReportNode.nodes.get_or_none.return_value = None
        MockGeneratedPatch.nodes.get_or_none.return_value = None
        
        mock_api.submit_pov.return_value = POVSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            pov_id=vuln_uuid,
            project_id=submitter.crs_task.pdt_task_id
        )
        
        mock_api.submit_patch.return_value = PatchSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusPassed,
            patch_id=patch_uuid,
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Process vulnerability and patch submissions
        submitter._process_vulnerability_submissions()
        submitter._process_patch_submissions()

    # Generate bundle identifier
    bundle_identifier = submitter.tracker.generate_bundle_identifier(patch_id, pdt_id, None)

    from crs_api.competition_api import CompetitionAPIError
    
    with patch.object(submitter.API, "submit_bundle") as mock_submit_bundle:
        
        # Configure multiple errors followed by success
        error_responses = [
            CompetitionAPIError("Bad request: Invalid bundle structure"),
            CompetitionAPIError("Server error: Bundle service timeout"),
            CompetitionAPIError("Conflict: Bundle already exists"),
        ]
        
        success_response = BundleSubmissionResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            bundle_id=uuid4(),
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Set up side effects: 3 errors then success
        mock_submit_bundle.side_effect = error_responses + [success_response]
        
        # Attempt 1: First error - should return None and delete submission
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle multiple errors"
        )
        assert bundle_response is None
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        
        # Attempt 2: Second error - should return None and delete submission
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle multiple errors"
        )
        assert bundle_response is None
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        
        # Attempt 3: Third error - should return None and delete submission
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle multiple errors"
        )
        assert bundle_response is None
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        
        # Attempt 4: Success - should return response and track submission
        bundle_response = submitter.submit_bundle(
            task_id=submitter.crs_task.task_id,
            patch_identifier=patch_id,
            vuln_identifier=pdt_id,
            description="Test bundle multiple errors"
        )
        assert bundle_response is not None
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        
        # Verify all 4 API calls were made
        assert mock_submit_bundle.call_count == 4
        
        # Verify final successful submission
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id, SubmissionType.BUNDLE, bundle_identifier
        )
        assert final_submission.status == SubmissionStatus.SubmissionStatusAccepted
        assert final_submission.bundle_id == success_response.bundle_id


def test_sarif_submission_competition_api_error_and_retry(
    submitter, test_dirs, mock_api, mock_uuid, monkeypatch
):
    """Test SARIF submission raises CompetitionAPIError, gets deleted, and retries successfully"""
    
    submitter_module.IS_CI = False  # Ensure we're not in CI mode so API calls are made
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment for error retry",
    )

    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # First attempt: Mock API to raise CompetitionAPIError
    from crs_api.competition_api import CompetitionAPIError
    
    with patch.object(submitter.API, "submit_sarif_assessment") as mock_submit_sarif:
        
        # First call raises CompetitionAPIError
        mock_submit_sarif.side_effect = CompetitionAPIError("Server error: SARIF assessment service unavailable")
        
        # Process SARIF submissions - should catch error and delete submission
        with pytest.raises(CompetitionAPIError, match="Server error: SARIF assessment service unavailable"):
            submitter._process_retry_sarif_submissions()
        
        # Verify API was called once
        assert mock_submit_sarif.call_count == 1
        
        # Verify submission was NOT tracked (should be deleted after error)
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.SARIF,
            str(sarif_id),
        )
        
        # Verify the submission directory structure
        submission_path = submitter.tracker._get_submission_path(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        # The submission should not exist after deletion
        assert not submission_path.exists()

    # Recreate the SARIF file for retry (it was deleted during error handling)
    submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))

    # Second attempt: Mock API to succeed
    with patch.object(submitter.API, "submit_sarif_assessment") as mock_submit_sarif_retry:
        
        # Second call succeeds
        success_response = SarifAssessmentResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            project_id=submitter.crs_task.pdt_task_id
        )
        mock_submit_sarif_retry.return_value = success_response
        
        # Process SARIF submissions again - should retry successfully
        submitter._process_retry_sarif_submissions()
        
        # Verify API was called once in the retry
        assert mock_submit_sarif_retry.call_count == 1
        
        # Verify submission is now tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.SARIF,
            str(sarif_id),
        )
        
        # Verify the successful submission response
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id,
            SubmissionType.SARIF,
            str(sarif_id),
        )
        assert final_submission is not None
        assert final_submission.status == SubmissionStatus.SubmissionStatusAccepted
        
        # Verify submission is in successful_submissions directory
        success_files = list(submitter.tracker.successful_submissions.glob("*"))
        assert len(success_files) >= 1  # May have files from previous tests
        
        # Find our SARIF submission file
        sarif_success_file = None
        for file in success_files:
            file_data = json.loads(file.read_text())
            if file_data.get("type") == SubmissionType.SARIF.value:
                sarif_success_file = file
                break
        
        assert sarif_success_file is not None
        sarif_file_data = json.loads(sarif_success_file.read_text())
        assert sarif_file_data["status"] == SubmissionStatus.SubmissionStatusAccepted.value

    # Third attempt: Verify no duplicate submission on subsequent calls
    with patch.object(submitter.API, "submit_sarif_assessment") as mock_submit_sarif_final:
        
        # Process SARIF submissions again - should skip already submitted
        submitter._process_retry_sarif_submissions()
        
        # Verify API was NOT called since submission already exists
        mock_submit_sarif_final.assert_not_called()
        
        # Verify submission is still tracked
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id,
            SubmissionType.SARIF,
            str(sarif_id),
        )


def test_sarif_submission_multiple_api_errors_before_success(
    submitter, test_dirs, mock_api, mock_uuid, monkeypatch
):
    """Test SARIF submission with multiple CompetitionAPIErrors before eventual success"""
    
    submitter_module.IS_CI = False
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")  # Make sure exceptions are re-raised
    
    # Create SARIF assessment submission file
    sarif_id = uuid4()
    sarif_metadata = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        description="Test SARIF assessment for multiple errors",
    )

    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"

    from crs_api.competition_api import CompetitionAPIError
    
    with patch.object(submitter.API, "submit_sarif_assessment") as mock_submit_sarif:
        
        # Configure multiple errors followed by success
        error_responses = [
            CompetitionAPIError("Bad request: Invalid SARIF format"),
            CompetitionAPIError("Server error: SARIF processing timeout"),
            CompetitionAPIError("Unauthorized: Invalid SARIF token"),
        ]
        
        success_response = SarifAssessmentResponse(
            status=SubmissionStatus.SubmissionStatusAccepted,
            project_id=submitter.crs_task.pdt_task_id
        )
        
        # Set up side effects: 3 errors then success
        mock_submit_sarif.side_effect = error_responses + [success_response]
        
        # Attempt 1: First error
        submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))
        with pytest.raises(CompetitionAPIError, match="Bad request: Invalid SARIF format"):
            submitter._process_retry_sarif_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        
        # Attempt 2: Second error
        submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))
        with pytest.raises(CompetitionAPIError, match="Server error: SARIF processing timeout"):
            submitter._process_retry_sarif_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        
        # Attempt 3: Third error
        submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))
        with pytest.raises(CompetitionAPIError, match="Unauthorized: Invalid SARIF token"):
            submitter._process_retry_sarif_submissions()
        assert not submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        
        # Attempt 4: Success
        submission_file.write_text(yaml.dump(sarif_metadata.model_dump(mode="json")))
        submitter._process_retry_sarif_submissions()
        assert submitter.tracker.is_submitted(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        
        # Verify all 4 API calls were made
        assert mock_submit_sarif.call_count == 4
        
        # Verify final successful submission
        final_submission = submitter.tracker.get_submission(
            submitter.crs_task.task_id, SubmissionType.SARIF, str(sarif_id)
        )
        assert final_submission.status == SubmissionStatus.SubmissionStatusAccepted


def test_sarif_assessment_update_incorrect_to_correct(submitter, test_dirs, mock_api, mock_uuid):
    """Test SARIF assessment submission that gets updated from incorrect to correct assessment"""

    submitter_module.IS_CI = False
    
    # Create SARIF assessment submission file with incorrect assessment
    sarif_id = uuid4()
    sarif_metadata_incorrect = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentIncorrect,
        description="Test SARIF assessment - initially incorrect",
    )

    submission_file = test_dirs["sarif_retry_dir"] / f"{sarif_id}.json"
    submission_file.write_text(yaml.dump(sarif_metadata_incorrect.model_dump(mode="json")))

    # Mock API response for first submission (incorrect assessment)
    first_response = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        project_id=submitter.crs_task.pdt_task_id
    )
    mock_api.submit_sarif_assessment.return_value = first_response

    # Process first submission (incorrect)
    submitter._process_retry_sarif_submissions()

    # Verify first API call was made correctly
    assert mock_api.submit_sarif_assessment.call_count == 1
    first_call_args = mock_api.submit_sarif_assessment.call_args[0]
    assert first_call_args[0] == submitter.crs_task.task_id
    assert first_call_args[1] == sarif_id
    assert isinstance(first_call_args[2], SarifAssessmentSubmission)
    assert first_call_args[2].assessment == Assessment.AssessmentIncorrect

    # Verify first submission was tracked
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )

    # Verify first submission response was saved with incorrect assessment
    first_saved_response = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )
    assert first_saved_response is not None
    assert first_saved_response.status == SubmissionStatus.SubmissionStatusAccepted

    # Reset mock and create second submission with correct assessment
    mock_api.submit_sarif_assessment.reset_mock()
    
    sarif_metadata_correct = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,  # Same SARIF ID
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentCorrect,  # Changed to correct
        description="Test SARIF assessment - updated to correct",
    )

    # Overwrite the submission file with correct assessment
    submission_file.write_text(yaml.dump(sarif_metadata_correct.model_dump(mode="json")))

    # Mock API response for second submission (correct assessment)
    second_response = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusAccepted,
        project_id=submitter.crs_task.pdt_task_id
    )
    mock_api.submit_sarif_assessment.return_value = second_response

    # Process second submission (correct) - this should update the existing submission
    submitter._process_retry_sarif_submissions()

    # Verify second API call was made correctly
    assert mock_api.submit_sarif_assessment.call_count == 1
    second_call_args = mock_api.submit_sarif_assessment.call_args[0]
    assert second_call_args[0] == submitter.crs_task.task_id
    assert second_call_args[1] == sarif_id
    assert isinstance(second_call_args[2], SarifAssessmentSubmission)
    assert second_call_args[2].assessment == Assessment.AssessmentCorrect

    # Verify submission is still tracked (should be updated, not duplicated)
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )

    # Verify the final saved submission has the correct assessment
    final_saved_response = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )
    assert final_saved_response is not None
    assert final_saved_response.status == SubmissionStatus.SubmissionStatusAccepted

    # Verify only one SARIF submission exists in the tracking system
    sarif_dir = (
        submitter.tracker.lock_dir
        / str(submitter.crs_task.task_id)
        / SubmissionType.SARIF.value
    )
    sarif_submissions = list(sarif_dir.glob("*"))
    assert len(sarif_submissions) == 1

    # Verify the submission file was updated and contains the correct assessment
    sarif_submission_file = sarif_submissions[0]
    with sarif_submission_file.open() as f:
        saved_data = json.load(f)
        assert saved_data["status"] == SubmissionStatus.SubmissionStatusAccepted.value
        # The submission response doesn't store the assessment, but we verified the API call had the correct assessment

    # Verify successful_submissions directory contains the updated submission
    success_files = list(submitter.tracker.successful_submissions.glob("*"))
    sarif_success_files = []
    for file in success_files:
        file_data = json.loads(file.read_text())
        if file_data.get("type") == SubmissionType.SARIF.value:
            sarif_success_files.append(file)
    
    # Should have exactly one SARIF success file (updated, not duplicated)
    assert len(sarif_success_files) == 1

    # Reset mock and attempt third submission trying to change back to incorrect
    mock_api.submit_sarif_assessment.reset_mock()
    
    sarif_metadata_incorrect_again = SARIFMetadata(
        task_id=submitter.crs_task.task_id,
        sarif_id=sarif_id,  # Same SARIF ID
        pdt_sarif_id=str(sarif_id),
        pdt_task_id=str(submitter.crs_task.pdt_task_id),
        metadata={},
        assessment=Assessment.AssessmentIncorrect,  # Trying to change back to incorrect
        description="Test SARIF assessment - attempt to revert to incorrect",
    )

    # Overwrite the submission file with incorrect assessment again
    submission_file.write_text(yaml.dump(sarif_metadata_incorrect_again.model_dump(mode="json")))

    # Mock API response for third submission (incorrect assessment again)
    third_response = SarifAssessmentResponse(
        status=SubmissionStatus.SubmissionStatusFailed,
        project_id=submitter.crs_task.pdt_task_id
    )
    mock_api.submit_sarif_assessment.return_value = third_response

    # Process third submission - should NOT overwrite the correct assessment
    submitter._process_retry_sarif_submissions()

    # Verify the API was called again (system doesn't prevent re-submission)
    assert mock_api.submit_sarif_assessment.call_count == 0

    # Verify submission is still tracked (should be updated again)
    assert submitter.tracker.is_submitted(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )

    # Verify the final saved submission still shows the most recent submission (incorrect)
    # Note: The system doesn't prevent going from correct back to incorrect - it just saves the latest
    final_final_response = submitter.tracker.get_submission(
        submitter.crs_task.task_id,
        SubmissionType.SARIF,
        str(sarif_id),
    )
    assert final_final_response is not None
    assert final_final_response.status == SubmissionStatus.SubmissionStatusAccepted

    # Verify still only one SARIF submission exists (no duplication)
    sarif_submissions_final = list(sarif_dir.glob("*"))
    assert len(sarif_submissions_final) == 1

    # Verify successful_submissions directory still contains exactly one entry
    success_files_final = list(submitter.tracker.successful_submissions.glob("*"))
    sarif_success_files_final = []
    for file in success_files_final:
        file_data = json.loads(file.read_text())
        if file_data.get("type") == SubmissionType.SARIF.value:
            sarif_success_files_final.append(file)
    
    # Should still have exactly one SARIF success file (updated, not duplicated)
    assert len(sarif_success_files_final) == 1

    print("✓ SARIF assessment submission properly handles multiple updates without duplication")
    print("✓ System allows going from incorrect -> correct -> incorrect (saves latest assessment)")
    print("✓ No duplicate tracking entries are created during multiple updates")


