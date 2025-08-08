import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from common import TEST_DIR, not_run_on_ci, setup_aicc_backup_target
from patchery.ranker import PatchRanker
from patchery.aicc_patcher import AICCPatcher
import logging
logging.getLogger("patchery").setLevel(logging.DEBUG)



class TestPatcheryAICC(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.container = None
        super().__init__(*args, **kwargs)

    def setUp(self):
        if self.container is not None:
            self.container.kill()
            self.container = None

    def tearDown(self):
        if self.container is not None:
            self.container.kill()
            self.container = None
    @not_run_on_ci
    def test_patch_ranking(self):
        # Example run:
        # patchery --rank-patches ./tests/aicc_testing/patch_ranking/mock_cp_patches/ \
        #   --rank-patch-metadatas ./tests/aicc_testing/patch_ranking/patch_metadata/  \
        #   --rank-patch-verifications ./tests/aicc_testing/patch_ranking/crashes/ \
        #   --rank-output-dir ./ranks/
        #
        # this uses the mock_cp verified patches
        verified_patches = TEST_DIR / "aicc_testing/patch_ranking/mock_cp_patches"
        patch_metadata = TEST_DIR / "aicc_testing/patch_ranking/patch_metadata"
        crashes = TEST_DIR / "aicc_testing/patch_ranking/crashes"

        # we create two vds records inside the files:
        # - vds: 0
        # - vds: 1
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            PatchRanker.rank_many_aicc_patch_dirs(
                verified_patches,
                crashes,
                patch_metadata,
                rank_output_dir=output_dir,
            )

            # load up all the rankings from the output dir
            ranks = {}
            for rank_file in output_dir.glob("*.yaml"):
                rank_data = yaml.safe_load(rank_file.read_text())
                ranks[rank_data["vds_id"]] = rank_data

            # only patch 0 should be invalid
            for bad_patch in ranks[0]['invalidated_patches']:
                assert Path(bad_patch).name == "patch_0"

            # patch ranks vds0
            vds_0_ranks = [
                Path(path).name for path in ranks[0]["ranks"]
            ]
            assert vds_0_ranks == ["patch_1", "patch_2", "patch_0"]

            # patch ranks vds1
            vds_1_ranks = [
                Path(path).name for path in ranks[1]["ranks"]
            ]
            assert vds_1_ranks == ["patch_3", "patch_4"]

    # def test_mock_cp_ossfuzz(self):
    #     # for ossfuzz
    #     local_backup = TEST_DIR / "aicc_testing/mock_cp/backup_4f92b4182d24c140a3a00bebc71fa8d5_0/"
    #     self.container, resource_dir, tmp_dir, src_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets.git",
    #         root_dir_in_target_repo="projects/mock-cp",
    #     )
    #     # run with the default settings, which uses a POI report
    #     print("[+] OSS-Fuzz Mock CP with default settings...")
    #     run_and_validate_patcher(self.container, resource_dir, tmp_dir, src_dir, local_backup)

    def test_mock_cp_backup_13883965678(self):

        target_root, source_root, data_locations = setup_aicc_backup_target(
            target_url='https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets',
            target_repo_name='mock-cp',
            backup_data_dir=TEST_DIR / "aicc_testing/mock_cp/backup-mock-cp-13883965678/",
            poi_report_id='c8cf1ac86995d2cb142aa9da3dfe3156')
        # FILES_NEEDED = ['commit_functions_index', 'crashing_input_path', 'full_functions_index',
        #                 'full_functions_jsons_dir', 'commit_functions_jsons_dir',
        #                 'kumushi_light_mode_output', 'kumushi_heavy_mode_output', 'poi_report',
        #                 'povguy_pov_report_path', 'project_metadata_path']
        patcher = AICCPatcher.from_files(target_root=target_root, source_root=source_root,
                                         report_yaml_path=data_locations['poi_report'],
                                         project_metadata_path=data_locations['project_metadata_path'],
                                         raw_report_path=data_locations['povguy_pov_report_path'],
                                         function_json_dir=data_locations['full_functions_jsons_dir'],
                                         function_indices=data_locations['full_functions_index'],
                                         alerting_inputs_path=data_locations['crashing_input_path'],
                                         patch_output_dir='/tmp/patch_output_dir',
                                         patch_metadata_output_dir='/tmp/patch_metadata_output_dir',
                                         indices_by_commit=data_locations['commit_functions_index'],
                                         changed_func_by_commit=data_locations['commit_functions_jsons_dir'],
                                         patch_planning=True, local_run=True,
                                         kumushi_report_path=data_locations['kumushi_light_mode_output']
                                         if data_locations['kumushi_light_mode_output'] is not None
                                         else data_locations['kumushi_heavy_mode_output'], max_attempts=10, max_pois=8)
        patches = patcher.generate_verified_patches()
        assert len(patches) > 0


    # def test_mock_cp(self):
    #     # to optimize for speed, we include multiple runs of mock_cp to tests a few
    #     # features in the same docker container without having to set it up all over again
    #     local_backup = TEST_DIR / "aicc_testing/mock_cp/backup_fa8d9b910ae411340e42a8610bc62630_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     print("[+] Mock CP with default settings...")
    #     run_and_validate_patcher(self.container, resource_dir, tmp_dir, local_backup)

    #     # # run with default + invariance report
    #     # print("[+] Mock CP with Invariance Report...")
    #     # run_and_validate_patcher(
    #     #     self.container,
    #     #     resource_dir,
    #     #     tmp_dir,
    #     #     local_backup,
    #     #     extra_patch_args=f"--invariance-report {str(resource_dir / 'invariant_report.yaml')} ",
    #     # )
    #     #
    #     # # run with default + debug report
    #     # print("[+] Mock CP with Debug Report...")
    #     # run_and_validate_patcher(
    #     #     self.container,
    #     #     resource_dir,
    #     #     tmp_dir,
    #     #     local_backup,
    #     #     extra_patch_args=f"--debug-report {str(resource_dir / 'debug_report.yaml')} ",
    #     # )

    #     # run with planning
    #     print("[+] Mock CP with Patch Planning...")
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         extra_patch_args=f"--patch-planning",
    #     )

    # @not_run_on_ci
    # def test_nginx_exemplar(self):
    #     # This testcase is from the pre-semifinals of the AIxCC competition, so if this is the future, the data
    #     # format may be outdated. In that case just disable it and replace it.
    #     # In the semi-finals it became CPV15:
    #     # https://github.com/aixcc-public/challenge-004-nginx-cp/blob/bd4490502e9e8f42b45e536cbc05d78ebc41aa0e/.internal_only/cpv15/CPVINFO.md?plain=1#L1
    #     #
    #     # This tests that we parse the commit of the target, give it to the patcher, and see it patch just based
    #     # on the diff information.
    #     #
    #     # Old introducing bug:
    #     # https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-004-nginx-source/commit/8e2a8e613fe5b6f03cb8e0c27180a468671f03a8#diff-ffedae57fb1948576e0b943ff314531cd34117e92cc64c9cf88f6b0d43b71eee
    #     local_backup = TEST_DIR / "aicc_testing/nginx_exemplar/backup_4657771bd193f7185e973c773a547161_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp.git",
    #     )
        
    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
    #     )

    # @not_run_on_ci
    # def test_nginx_cpv17(self):
    #     # bug introducing commit:
    #     # https://github.com/aixcc-public/challenge-004-nginx-source/commit/b6c0a37554e300aa230ea2b8d7fe53dd8604f602#diff-bee42bcf38808b4a893dc34dd99d388088c4cf572923800aa14f0cda9973c563R831
    #     #
    #     # This bug is special because the bug is introduced by introducing a completely new function which already
    #     # has the bug in it. This causes some special failures from our commit-tracking system.
    #     # Ground truth patch:
    #     # https://github.com/aixcc-public/challenge-004-nginx-cp/blob/main/.internal_only/cpv17/patches/nginx/good_patch.diff
    #     local_backup = TEST_DIR / "aicc_testing/nginx_semi_final/backup_27f4b677e87f28941781d8aeabc90dc7_5"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
    #     )

    # @not_run_on_ci
    # def test_nginx_cpv15(self):
    #     # bug introducing commit:
    #     # https://github.com/aixcc-public/challenge-004-nginx-source/commit/b6c0a37554e300aa230ea2b8d7fe53dd8604f602#diff-bee42bcf38808b4a893dc34dd99d388088c4cf572923800aa14f0cda9973c563R831
    #     #
    #     # This bug is special because the bug is introduced by introducing a completely new function which already
    #     # has the bug in it. This causes some special failures from our commit-tracking system.
    #     # Ground truth patch:
    #     # https://github.com/aixcc-public/challenge-004-nginx-cp/blob/main/.internal_only/cpv17/patches/nginx/good_patch.diff
    #     local_backup = TEST_DIR / "aicc_testing/nginx/backup_fe9423a9486c79774d0e4393a3631ce6_1"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         extra_patch_args=f"--patch-planning",
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
    #     )


    # @not_run_on_ci
    # def test_nginx_cpv13_bad(self):
    #     # backup_c0bbf2364f1f523b510b31488838a6e7_1
    #     local_backup = TEST_DIR / "aicc_testing/nginx_semi_final/backup_c0bbf2364f1f523b510b31488838a6e7_1"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )


    # @not_run_on_ci
    # def test_nginx_cpv11(self):
    #     # TODO: this test is still broken
    #     local_backup = TEST_DIR / "aicc_testing/nginx_semi_final/backup_d10658907931dddaf33bc7a1c4b5b6b6_3"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # @not_run_on_ci
    # def test_nginx_cpv13(self):
    #     # bug introducing commit:
    #     # https://github.com/shellphish-support-syndicate/challenge-004-full-nginx-source/commit/316d57f895c4c915c5ce3af8b09972d47dd9984e#diff-f2fa0c604b3eec568bf77394733618361e7ad69d89836b129ff05cfea2d12244
    #     #
    #     # This bug is special because the bug requires patching two functions to fix it. 
    #     # Ground truth patch:
    #     # https://github.com/aixcc-public/challenge-004-nginx-cp/blob/main/.internal_only/cpv13/patches/nginx/good_patch.diff
    #     local_backup = TEST_DIR / "aicc_testing/nginx_semi_final/backup_94f6f8f8f04d44391b39c0311ca40b13_2"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         extra_patch_args=f"--debug-report {str(resource_dir / 'debug_report.yaml')} ",
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
    #     )

    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         extra_patch_args=f"--patch-planning",
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
    #     )

    # @not_run_on_ci
    # def test_nginx_code_parser(self):
    #     local_backup = TEST_DIR / "aicc_testing/nginx_semi_final/backup_e71d566654548a205180f7961f9d4ce3_2"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/aixcc-public/challenge-004-nginx-cp.git",
    #     )

    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # @not_run_on_ci
    # def test_jenkins_backdoor(self):
    #     local_backup = TEST_DIR / "aicc_testing/jenkins_backdoor/backup_c4b34df868ae238c39206b1e566257f4_0/"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git"
    #     )
        
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #         #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariant_report.yaml')}"
    #     )

    # @not_run_on_ci
    # def test_linux_tipc(self):
    #     local_backup = TEST_DIR / "aicc_testing/linux_tipc/backup_fcc67a885262d8bcd6ab356bb0edf8ea_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-001-linux-cp.git",
    #     )

    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # @not_run_on_ci
    # def test_linux_harden_3(self):
    #     local_backup = TEST_DIR / "aicc_testing/harden_demo_3/backup_8dee1f8ee3bd387bde97d0558021daab_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-harden-demo3.git",
    #     )

    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
