import sys
from shellphish_crs_utils.models import PatchVerificationRequest, PatchVerificationResult, RepresentativeCrashingInputMetadata
import yaml

with open(sys.argv[1], 'r') as f:
    request = yaml.safe_load(f)
    request['crashing_commit_sha'] = request['crashing_commit_sha'].lower()
    fuzz_verification_request = PatchVerificationRequest.model_validate(request)

with open(sys.argv[2], 'r') as f:
    run_pov_result_metadata = yaml.safe_load(f)

all_triggered_sanitizers = set(run_pov_result_metadata['consistent_sanitizers']) | set(run_pov_result_metadata['inconsistent_sanitizers'])

result = PatchVerificationResult(
    patch_id=fuzz_verification_request.patch_id,
    still_crashing=fuzz_verification_request.sanitizer_id in all_triggered_sanitizers,
)

with open(sys.argv[3], 'w') as f:
    f.write(result.model_dump_json())

