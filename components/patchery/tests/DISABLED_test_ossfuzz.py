import sys
import unittest

from common import TEST_DIR, setup_aicc_target, run_and_validate_patcher


class TestPatcheryOssFuzz(unittest.TestCase):
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

    # def test_wasm3_33318(self):
    #     # This attempts to patch a stack-overflow that can be caught with a simple if-stmt.
    #     # Correct patch:
    #     # https://github.com/wasm3/wasm3/commit/b48695bb940e55c0baa0a3d5740cf48e03643b58#diff-2e831c160545a729ed85a9e0ce1f02dc63d0ad8bd7ed907278f249483439fc97
    #     #
    #     local_backup = TEST_DIR / "ossfuzz_testing/wasm3_33318/backup_d1d9388483a2d16b14513068e345eb36_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-wasm3-33318.git",
    #     )
    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # def test_libdwarf_57766(self):
    #     # Correct patch:
    #     # https://github.com/davea42/libdwarf-code/commit/761da806fc950c6b26c1763e8989a814e9b16a59#diff-211762d556b28c318a3829b9ce0612e17bb39386f840ce5616377705b7ffc7ffR1770
    #     local_backup = TEST_DIR / "ossfuzz_testing/libdwarf_57766/backup_a4915156e128a78c608589aa54ab40c4_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-libdwarf-57766.git",
    #     )
    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # @unittest.skip("Invalid CWE type of bug: its a versioning issue.")
    # def test_p11kit_57202(self):
    #     # Attempts to patch a lib version mismatch:
    #     # https://github.com/p11-glue/p11-kit/commit/d7c318845405fa7ea33154082b437e4a87ee3699
    #     local_backup = TEST_DIR / "ossfuzz_testing/p11_kit_57202/backup_70bc7d4e1c85f61bcfa3c508a770219c_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-p11-kit-57202.git",
    #     )
    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(
    #         self.container,
    #         resource_dir,
    #         tmp_dir,
    #         local_backup,
    #     )

    # @unittest.skip("This project cannot pass functionality test")
    # def test_lua_29610(self):
    #     local_backup = TEST_DIR / "ossfuzz_testing/lua_29610/backup_1d10596de6289bd40fa366961935d1b9_0"
    #     self.container, resource_dir, tmp_dir = setup_aicc_target(
    #         backup_data_dir=local_backup,
    #         target_url="https://github.com/shellphish-support-syndicate/targets-semis-lua-29610.git",
    #     )
    #     # run with the default settings, which uses a POI report
    #     run_and_validate_patcher(self.container, resource_dir, tmp_dir, local_backup)

    """
    def test_ossfuzz_xs_47443(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-xs-47443"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)

    def test_ossfuzz_libredwg_32275(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-libredwg-32275"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)

    def test_ossfuzz_libredwg_44481(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-libredwg-44481"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_wolfmqtt_37866(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-wolfmqtt-37866"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_wolfmqtt_34207(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-wolfmqtt-34207"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_wasm3_33240(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-wasm3-33240"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_wasm3_33318(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-wasm3-33318"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_selinux_31065(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-selinux-31065"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
    
    def test_ossfuzz_selinux_35492(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-selinux-35492"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)

    def test_ossfuzz_lua_44597(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-lua-44597"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_lua_37621(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-lua-37621"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
        
    def test_ossfuzz_oniguruma_25893(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-oniguruma-25893"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)

    def test_ossfuzz_oniguruma_53036(self):
        resource_dir, tmp_dir = setup_ossfuzz_target(
            local_target_testing_dir=TEST_DIR / "ossfuzz_testing",
            target_url="git@github.com:shellphish-support-syndicate/targets-semis-templates.git",
            ossfuzz_target_name="arvo-c-oniguruma-53036"
        )
        self._run_and_validate_patcher(resource_dir, tmp_dir)
    """


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
