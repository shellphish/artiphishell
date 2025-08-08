import unittest
from aixcc_test_utils import *

from pathlib import Path

from time import sleep
import yaml
import os

# from Wil's find first crash commit
class FuzzTests(unittest.TestCase):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        docker_path = Path(__file__).parent.parent.resolve()
        os.system("cd ../../ && ./local_run/rebuild_local.sh build-all aixcc-test_harness_jenkins")
        build_docker(docker_path, "aixcc-test_harness_jenkins", pull_component_base=False)

        os.system("docker pull gcr.io/oss-fuzz-base/base-runner")
        os.system("docker pull ghcr.io/aixcc-finals/base-runner:v1.3.0")

        with open(docker_path / "pipeline.yaml", "r") as f:
            pipeline = yaml.safe_load(f)

        pipeline['tasks']['jazzer_build']['job_quota']['mem'] = '16'
        pipeline['tasks']['jazzer_build']['job_quota']['mem'] = '4Gi'
        pipeline['tasks']['jazzer_build']['timeout'] = dict()
        pipeline['tasks']['jazzer_build']['timeout']['minutes'] = 30

        pipeline['tasks']['jazzer_fuzz']['job_quota']['mem'] = '4Gi'
        pipeline['tasks']['jazzer_fuzz']['max_replicas'] = 1
        pipeline['tasks']['jazzer_fuzz']['timeout'] = dict()
        pipeline['tasks']['jazzer_fuzz']['timeout']['minutes'] = 6

        pipeline['tasks']['jazzer_fuzz_merge']['timeout']['minutes'] = 6
        pipeline['tasks']['jazzer_fuzz_same_node_sync']['timeout']['minutes'] = 6

        with open(docker_path / "pipeline.yaml", "w") as f:
           f.write(yaml.safe_dump(pipeline, default_flow_style=False, sort_keys=False))


    def _run_build_test(self, target):
        prep_target(target)
        lock_pipeline()
        pipeline_inject(
            "jazzer_build.project_oss_fuzz_repo",
            pd_id="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
            file=COMPRESSED_TARGET_DIR / (target + ".tar.gz")
        )
        pipeline_inject("jazzer_build.project_id", data=b"""\
deadline: 1741062917000
focus: shellphish-mock-java-easy
metadata:
  round_id: local-dev
  task_id: 5abf0d0f-bc27-4dd8-a3a7-94433e9da0ae
pdt_task_id: 4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865
project_name: mock-cp-java-easy
source:
- sha256: ''
  type: repo
  url: /home/jmill/aixcc/artiphishell/local_run/generate-challenge-task/repo-tars/shellphish-mock-java-easy.tar.gz
- sha256: ''
  type: fuzz-tooling
  url: /home/jmill/aixcc/artiphishell/local_run/generate-challenge-task/repo-tars/oss-fuzz.tar.gz
task_id: 5abf0d0f-bc27-4dd8-a3a7-94433e9da0ae
task_sanitizer: address
task_uuid: 5abf0d0f-bc27-4dd8-a3a7-94433e9da0ae
type: full""",
            pd_id="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"
        )
        pipeline_inject("jazzer_build.build_configuration", data=b"""\
architecture: x86_64
project_id: 4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865
project_name: mock-cp-java-easy
sanitizer: address""",
            pd_id="f94d1847754a7f78ea9a1745c3493d97"
        )

        pipeline_run(before_args=[
            "--global-script-env", "CI_TEST=1",
            "--verbose",
            "--debug-trace"
        ])

        logs = pipeline_list_ids("jazzer_build.logs")
        output = pipeline_get_data("jazzer_build.logs", logs[0]).decode('latin-1')
        print("BUILD LOG", output)
        os.system("docker images")
        sleep(5)
        status = pipeline_status("json")
        return output, status

    def _run_fuzz_test(self, target):
        os.system("pd status")

        pipeline_inject(
            "jazzer_fuzz.harness_info",
            pd_id="de0eaf297e8e2e60d0cb182eac62de33",
            data=b"""\
architecture: x86_64
build_configuration_id: f94d1847754a7f78ea9a1745c3493d97
cp_harness_binary_path: out/Harness
cp_harness_name: Harness
entrypoint_function: null
project_id: 4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865
project_name: mock-cp-java-easy
sanitizer: address
source_entrypoint: null"""
        )

        pipeline_inject(
            "jazzer_fuzz.full_function_index",
            pd_id="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
            data=b"""{}"""
        )
        pipeline_inject(
            "jazzer_fuzz.project_metadata",
            pd_id="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
            data=b"""\
fuzzing_engines:
- libfuzzer
language: jvm
main_repo: https://github.com/shellphish-support-syndicate/shellphish-mock-cp-java-easy
sanitizers:
- address
shellphish:
  files_by_language:
    java: 1
    markdown: 1
    xml: 1
  fuzzing_engine: libfuzzer
  harnesses:
  - HarnessEasyReflect
  - Harness
  known_sources: {}
  project_name: mock-cp-java-easy
  sanitizer: address
  source_repo_path: /src/mock-java-easy
shellphish_docker_image: gcr.io/oss-fuzz/mock-cp-java-easy
shellphish_project_name: mock-cp-java-easy
vendor_ccs:
- srikanth.mailbox@gmail.com
- all.u.ever.know@gmail.com"""
        )
        pipeline_inject(
            "jazzer_fuzz.project_sources",
            pd_id="4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
            file=COMPRESSED_PROJECT_DIR / (target + ".tar.gz")
        )

        #with open("/shared/fuzzer_sync/mock-cp-java-easy-Harness-de0eaf297e8e2e60d0cb182eac62de33/jazzer-minimized/queue/1", "w+b") as fp:
        #    fp.write(b"\x00\x00\x00\x04\x00\x00\x00\x00/Set-Cookie\x00\x00jazze\x00\x00")

#         pipeline_inject("jazzer_fuzz_merge.benign_harness_inputs.meta", pd_id="1", data=b"""
# architecture: x86_64
# build_configuration_id: f94d1847754a7f78ea9a1745c3493d97
# cp_harness_binary_path: out/Harness
# cp_harness_name: Harness
# fuzzer: jazzer
# harness_info_id: de0eaf297e8e2e60d0cb182eac62de33
# project_id: 4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865
# project_name: mock-cp-java
# sanitizer: address""")

        pipeline_run(before_args=[
             "--global-script-env", "NODE_IP=localhost",
             "--verbose",
             "--debug-trace"
        ])

        os.system("pd status")

        fuzzer_logs = pipeline_list_ids("jazzer_fuzz.logs")
        fuzzer_output = pipeline_get_data("jazzer_fuzz.logs", fuzzer_logs[0]).decode('latin-1')
        print("FUZZER OUTPUT", fuzzer_output)

        status = pipeline_status("json")

        return status, fuzzer_output#, no_codeql_fuzzer_output

    def run_all_tests(self):

        target = "mock-cp-java-easy"

        output, build_status = self._run_build_test(target)
        if '[INFO] BUILD SUCCESS' in output:
            print("Build successful")
        assert build_status['jazzer_build']['success'][0] == ['f94d1847754a7f78ea9a1745c3493d97'], "Build failed"

        fuzz_status, fuzzer_output = fuzztest._run_fuzz_test(target)
        assert 'pulse  cov:' in fuzzer_output, "Fuzzing did not start!"

        # fuzz w/o CodeQL
        # assert fuzz_status['jenkins_jazzer_no_codeql_fuzz']['full_function_index'][0] == ['1'],  "No function indices received!"
        # assert 'pulse  cov:' in no_codeql_fuzzer_output, "Fuzzing did not start for no CodeQL mode!"

        os.system("pd status")

        # fuzz merge
        benign_seeds = fuzz_status['jazzer_fuzz_merge']['benign_harness_inputs'][0]
        crashing_seeds = fuzz_status['jazzer_fuzz_merge']['crashing_harness_inputs'][0]
        assert len(benign_seeds) > 0, "No benign seeds found!"
        if len(crashing_seeds) > 0:
            print("Found a crash!")

        kill_docker_containers('None___jazzer_fuzz')


if __name__ == '__main__':
    fuzztest = FuzzTests()
    fuzztest.run_all_tests()
