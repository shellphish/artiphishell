import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from common import TEST_DIR, setup_aicc_target, run_and_validate_patcher, not_run_on_ci
from patchery.ranker.patch_ranker import PatchRanker


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
            rankers = PatchRanker.rank_many_aicc_patch_dirs(
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

    def test_mock_cp(self):
        # to optimize for speed, we include multiple runs of mock_cp to tests a few
        # features in the same docker container without having to set it up all over again
        local_backup = TEST_DIR / "aicc_testing/mock_cp/backup_53450816d9c930d285d19638ee340871_1"
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            backup_data_dir=local_backup,
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-mock-cp.git",
        )

        # run with the default settings, which uses a POI report
        run_and_validate_patcher(self.container, resource_dir, tmp_dir, local_backup)

        # run with default + invariance report
        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
            extra_patch_args=f"--invariance-report {str(resource_dir / 'invariant_report.yaml')} ",
        )

        # run with default + debug report
        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
            extra_patch_args=f"--debug-report {str(resource_dir / 'debug_report.yaml')} ",
        )

    @not_run_on_ci
    def test_nginx(self):
        # Introduced bug:
        # https://github.com/shellphish-support-syndicate/aixcc-sc-challenge-004-nginx-source/commit/8e2a8e613fe5b6f03cb8e0c27180a468671f03a8#diff-ffedae57fb1948576e0b943ff314531cd34117e92cc64c9cf88f6b0d43b71eee
        local_backup = TEST_DIR / "aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0"
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            backup_data_dir=local_backup,
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp.git",
        )
        
        # run with the default settings, which uses a POI report
        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
            #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariance_report.yaml')} "
        )

    @not_run_on_ci
    def test_jenkins_backdoor(self):
        local_backup = TEST_DIR / "aicc_testing/jenkins_backdoor/backup_b4636e7716b051dde14178f6e1a606ef_0/"
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            backup_data_dir=local_backup,
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git"
        )
        
        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
            #extra_patch_args=f"--invariance-report {str(resource_dir / 'invariant_report.yaml')}"
        )

    @not_run_on_ci
    def test_linux_tipc(self):
        local_backup = TEST_DIR / "aicc_testing/linux_tipc/backup_fcc67a885262d8bcd6ab356bb0edf8ea_0"
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            backup_data_dir=local_backup,
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-001-linux-cp.git",
        )

        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
        )

    @not_run_on_ci
    def test_linux_harden_3(self):
        local_backup = TEST_DIR / "aicc_testing/harden_demo_3/backup_8dee1f8ee3bd387bde97d0558021daab_0"
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            backup_data_dir=local_backup,
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-harden-demo3.git",
        )

        run_and_validate_patcher(
            self.container,
            resource_dir,
            tmp_dir,
            local_backup,
        )

    """
    @unittest.skip("TODO: FIXME")
    def test_linux_tipc(self):
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            local_target_testing_dir=TEST_DIR / "aicc_testing/linux_tipc",
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-001-linux-cp.git",
        )
        extra_patch_args = (
            f"--c-reproducer {str(resource_dir / 'c_reproducer')} "
            f"--kernel-image {str(tmp_dir / 'src/linux_kernel/arch/x86_64/boot/bzImage')}"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir, extra_patch_args=extra_patch_args)

    @unittest.skip("TODO: FIXME")
    def test_java_jenkins(self):
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            local_target_testing_dir=TEST_DIR / "aicc_testing/jenkins_backdoor",
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)

    @unittest.skip("TODO: FIXME")
    def test_nginx(self):
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            local_target_testing_dir=TEST_DIR / "aicc_testing/nginx",
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-004-nginx-cp.git"
        )

        extra_patch_args = (
            f"--raw-report {str(resource_dir / 'asan_report_perfect.txt')} "
            f"--crashing-commit 8e2a8e6"
        )
        self._run_and_validate_patcher(
            resource_dir, 
            tmp_dir, 
            use_func_indices=False, 
            use_poi_report=False,
            extra_patch_args=extra_patch_args
        )

    #
    # Manually ported AIxCC challenges
    #

    @unittest.skip("TODO: FIXME")
    def test_nilo(self):
        # This is the Nilo challenge which was developed by Fabio. This challenge has a simple 
        # overflow in the harness 
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            local_target_testing_dir=TEST_DIR / "aicc_testing/nilo",
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-nilo-the-force-awakens.git"
        )
        extra_patch_args = (
            f"--invariance-report {str(resource_dir / 'invariant_report.json')} "
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir, extra_patch_args=extra_patch_args)

    @unittest.skip("It's too slow and there are no run_tests yet!") 
    def test_linux_harden(self):
        self.container, resource_dir, tmp_dir = setup_aicc_target(
            local_target_testing_dir=TEST_DIR / "aicc_testing/linux_harden",
            target_url="https://github.com/shellphish-support-syndicate/targets-semis-harden-demo2.git",
        )
        extra_patch_args = (
            f"--kernel-image {str(tmp_dir / 'src/linux-kernel/arch/x86_64/boot/bzImage')} "
            f"--invariance-report {str(resource_dir / 'invariant_report.json')} "
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir, extra_patch_args=extra_patch_args, use_func_indices=False)
    """


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
