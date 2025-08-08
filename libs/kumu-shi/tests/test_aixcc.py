import subprocess
import sys
import unittest
from pathlib import Path
from common import setup_coverage_guy_container, build_aurora_nginx_image, ensure_image_exists, validate_in_aurora_container
import asyncio
import pytest
import logging
import os
import tarfile
import tempfile
import shutil
import json

import kumushi
from kumushi.code_parsing import CodeFunction
from kumushi.data import PoI
from kumushi.static_tools import StaticAnalyzer, QueryType

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)
TESTS_DIR = Path(__file__).absolute().parent
TARGETS_DIR = TESTS_DIR / "targets"

CODEQL_EXECUTABLE_DIR = TARGETS_DIR / "codeql"


def prepare_test_resource(tared_file: Path):
    subprocess.run(["tar", "-xzf", tared_file], cwd=tared_file.parent)
    codeql_bundle_url = "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.18.4/codeql-bundle-linux64.tar.gz"
    if not CODEQL_EXECUTABLE_DIR.exists():
        subprocess.run(["wget", codeql_bundle_url], cwd=TARGETS_DIR)
        subprocess.run(["tar", "xf", "codeql-bundle-linux64.tar.gz"], cwd=TARGETS_DIR) 


def prepare_aurora_test_resources(backup_dir):
    # extract covergae build target
    target_built_with_coverage_path = os.path.join(backup_dir, 'coverage_build.target_built_with_coverage')
    tar_file_path = os.path.join(target_built_with_coverage_path, '1.tar.gz')
    extract_to_path = os.path.join(backup_dir, 'coverage_target')
    if os.path.exists(extract_to_path):
        os.system(f"rm -rf {extract_to_path}")
    os.makedirs(extract_to_path, exist_ok=True)
    try:
        with tarfile.open(tar_file_path, 'r') as tar: 
            tar.extractall(path=extract_to_path)
    except Exception as e:
        print(f"Failed to extract tar file: {e}")
    
    # extract aflpp build target
    aflpp_build_target_path = os.path.join(backup_dir, 'aflpp_build.aflpp_built_target')
    tar_file_path = os.path.join(aflpp_build_target_path, '1.tar.gz')
    extract_to_path = os.path.join(backup_dir, 'aflpp_target')
    if os.path.exists(extract_to_path):
        os.system(f"rm -rf {extract_to_path}")
    os.makedirs(extract_to_path, exist_ok=True)
    try:
        with tarfile.open(tar_file_path, 'r') as tar: 
            tar.extractall(path=extract_to_path)
    except Exception as e:
        print(f"Failed to extract tar file: {e}")


@pytest.fixture(autouse=True)
def set_paths(monkeypatch):
    monkeypatch.setenv("PATH", str(CODEQL_EXECUTABLE_DIR) + ":" + os.environ.get("PATH", ""))    


class TestKumuShi(unittest.TestCase):
    def test_cli(self):
        # run the CLI version check
        output = subprocess.run(["kumu-shi", "--version"], capture_output=True)
        version = output.stdout.decode().strip()
        assert version == kumushi.__version__

    def test_simple_end_to_end(self):
        setup_coverage_guy_container('backup-full-nginx-11889160244', 'c')

    def test_async_static_analysis(self):
        asyncio.run(self._test_static_analysis_nginx_cpv15())

    async def _test_static_analysis_nginx_cpv15(self):
        function = CodeFunction(name="ngx_http_userid_set_uid", file_path=Path("whatever"), code="some source code",
                            start_line=0, end_line=0)
        crash_function = function
        crash_poi = PoI(
            function=crash_function,
            crash_line_num=446,
            crash_line="",
        )

        codeql_db = TARGETS_DIR / "nginx" / "nginx-codeql-db"
        if not codeql_db.exists():
            prepare_test_resource(TARGETS_DIR / "nginx" / "nginx-codeql-db.tar.gz")
        static_analysis = StaticAnalyzer(crash_poi, codeql_db, CODEQL_EXECUTABLE_DIR / "codeql")
        query_type = QueryType.FUNCTION_VARIABLE_ACCESSES.value
        res = await static_analysis.run_query(query_type, {"function_name": crash_function.name})
    
    def test_static_analysis_end_to_end(self):
        asyncio.run(self._test_end_to_end_static_analysis_nginx_cpv15())

    async def _test_end_to_end_static_analysis_nginx_cpv15(self):
        crash_function = CodeFunction(
            name="ngx_http_userid_set_uid",
            file = Path("whatever"),
            code = "some source code",
            start_line = 0,
            end_line=0
        )
        crash_poi = PoI(
            function=crash_function,
            crash_line_num=446,
            crash_line="",
        )
        codeql_db = TARGETS_DIR / "nginx" / "nginx-codeql-db"
        static_analysis = StaticAnalyzer(crash_poi, codeql_db, CODEQL_EXECUTABLE_DIR / "codeql")
        functions = await static_analysis.retrieve_pois()
        assert len(functions) > 0
        print(f"Found {len(functions)} functions: {functions}")
    
    def test_end_to_end_aurora_cpv15(self):
        harness_name = 'pov_harness'
        crashing_input_id = '70b3e8ccddb55d0123ce1e9a519c9dfe'
        target_function = 'ngx_http_userid_filter_module.c:ngx_http_userid_set_uid'
        backup_id = 'backup-full-nginx-12759578708'
        if not ensure_image_exists("aurora_nginx_image:latest"):
            build_aurora_nginx_image()
        backup_dir =f'/aixcc-backups/{backup_id}'
        shared_dir = "/shared"
        os.makedirs(shared_dir, exist_ok=True) 
        temp_dir = tempfile.mkdtemp(dir=shared_dir)
        try:
            backup_dir_new = os.path.join(temp_dir, os.path.basename(backup_dir))
            shutil.copytree(backup_dir, backup_dir_new)
            backup_dir = backup_dir_new
            prepare_aurora_test_resources(backup_dir)
            setup_coverage_guy_container(backup_id, 'c')
            poc_path = os.path.join(backup_dir,f'passthrough__get_inputs.pov_report_representative_crashing_input_path/{crashing_input_id}')
            benign_coverage_folder = os.path.join(backup_dir, 'coverage_query.benign_coverages/')
            binary_path = os.path.join(backup_dir, f'aflpp_target/out/{harness_name}')
            fuzzer_path = '/kumu-shi/kumushi/aurora/fuzzer/afl-fuzz'
            coverage_build_target_dir = os.path.join(backup_dir, 'coverage_target')
            coverage_build_target_metadata_path = os.path.join(backup_dir, 'coverage_build.target_metadatum/1.yaml')
            fuzzing_dict_path = os.path.join(backup_dir, 'aflpp_target/work/dictionary.txt')
            if not os.path.exists(fuzzing_dict_path):
                fuzzing_dict_path = None          
            output_dir = os.path.join(temp_dir, 'aurora_output')
            aurora_cmds = ["mkdir -p logs", f"python /kumu-shi/kumushi/aurora/aurora_ranker.py --harness_name {harness_name} --poc_path {poc_path} --benign_coverage_folder {benign_coverage_folder} --binary_path {binary_path} --fuzzer_path {fuzzer_path} --coverage_build_target_dir {coverage_build_target_dir} --coverage_build_target_metadata_path {coverage_build_target_metadata_path} --output_dir {output_dir}"]
            validate_in_aurora_container(aurora_cmds)
            assert os.path.exists(os.path.join(output_dir, 'ranked_functions.json'))
            with open(os.path.join(output_dir, 'ranked_functions.json')) as f:
                sorted_func = json.load(f)
            assert len(sorted_func) > 0
            assert target_function in sorted_func
            keys = list(sorted_func.keys())
            target_index = keys.index(target_function)
            assert target_index < 10, f"Index is {target_index}, expected to be < 10"
        finally:
            os.system(f"rm -rf {temp_dir}")
    
    def test_end_to_end_aurora_cpv14(self):
        harness_name = 'pov_harness'
        crashing_input_id = 'e942a30b712848407355cfa1a1eb2b3f'
        target_function = 'ngx_http_script_regex_end_code'
        backup_id = 'backup-full-nginx-11925899750'
        if not ensure_image_exists("aurora_nginx_image:latest"):
            build_aurora_nginx_image()
        backup_dir =f'/aixcc-backups/{backup_id}'
        shared_dir = "/shared"
        os.makedirs(shared_dir, exist_ok=True) 
        temp_dir = tempfile.mkdtemp(dir=shared_dir)
        try:
            backup_dir_new = os.path.join(temp_dir, os.path.basename(backup_dir))
            shutil.copytree(backup_dir, backup_dir_new)
            backup_dir = backup_dir_new
            prepare_aurora_test_resources(backup_dir)
            setup_coverage_guy_container(backup_id, 'c')
            poc_path = os.path.join(backup_dir,f'passthrough__get_inputs.pov_report_representative_crashing_input_path/{crashing_input_id}')
            benign_coverage_folder = os.path.join(backup_dir, 'coverage_query.benign_coverages/')
            binary_path = os.path.join(backup_dir, f'aflpp_target/out/{harness_name}')
            fuzzer_path = '/kumu-shi/kumushi/aurora/fuzzer/afl-fuzz'
            coverage_build_target_dir = os.path.join(backup_dir, 'coverage_target')
            coverage_build_target_metadata_path = os.path.join(backup_dir, 'coverage_build.target_metadatum/1.yaml')
            fuzzing_dict_path = os.path.join(backup_dir, 'aflpp_target/work/dictionary.txt')
            if not os.path.exists(fuzzing_dict_path):
                fuzzing_dict_path = None          
            output_dir = os.path.join(temp_dir, 'aurora_output')
            aurora_cmds = ["mkdir -p logs", f"python /kumu-shi/kumushi/aurora/aurora_ranker.py --harness_name {harness_name} --poc_path {poc_path} --benign_coverage_folder {benign_coverage_folder} --binary_path {binary_path} --fuzzer_path {fuzzer_path} --coverage_build_target_dir {coverage_build_target_dir} --coverage_build_target_metadata_path {coverage_build_target_metadata_path} --output_dir {output_dir}"]
            validate_in_aurora_container(aurora_cmds)
            assert os.path.exists(os.path.join(output_dir, 'ranked_functions.json'))
            with open(os.path.join(output_dir, 'ranked_functions.json')) as f:
                sorted_func = json.load(f)
            assert len(sorted_func) > 0
            assert target_function in sorted_func
            keys = list(sorted_func.keys())
            target_index = keys.index(target_function)
            assert target_index < 10, f"Index is {target_index}, expected to be < 10"
        finally:
            os.system(f"rm -rf {temp_dir}")
            
    def test_end_to_end_aurora_cpv13(self):
        harness_name = 'mail_request_harness'
        crashing_input_id = '7c6ba457aac9ab75cc0acd2e74dc08c7'
        target_function = 'ngx_mail_pop3_handler.c:ngx_mail_pop3_logs'
        backup_id = 'backup-full-nginx-11925899750'
        if not ensure_image_exists("aurora_nginx_image:latest"):
            build_aurora_nginx_image()
        backup_dir =f'/aixcc-backups/{backup_id}'
        shared_dir = "/shared"
        os.makedirs(shared_dir, exist_ok=True) 
        temp_dir = tempfile.mkdtemp(dir=shared_dir)
        try:
            backup_dir_new = os.path.join(temp_dir, os.path.basename(backup_dir))
            shutil.copytree(backup_dir, backup_dir_new)
            backup_dir = backup_dir_new
            prepare_aurora_test_resources(backup_dir)
            setup_coverage_guy_container(backup_id, 'c')
            poc_path = os.path.join(backup_dir,f'passthrough__get_inputs.pov_report_representative_crashing_input_path/{crashing_input_id}')
            benign_coverage_folder = os.path.join(backup_dir, 'coverage_query.benign_coverages/')
            binary_path = os.path.join(backup_dir, f'aflpp_target/out/{harness_name}')
            fuzzer_path = '/kumu-shi/kumushi/aurora/fuzzer/afl-fuzz'
            coverage_build_target_dir = os.path.join(backup_dir, 'coverage_target')
            coverage_build_target_metadata_path = os.path.join(backup_dir, 'coverage_build.target_metadatum/1.yaml')
            fuzzing_dict_path = os.path.join(backup_dir, 'aflpp_target/work/dictionary.txt')
            if not os.path.exists(fuzzing_dict_path):
                fuzzing_dict_path = None          
            output_dir = os.path.join(temp_dir, 'aurora_output')
            aurora_cmds = ["mkdir -p logs", f"python /kumu-shi/kumushi/aurora/aurora_ranker.py --harness_name {harness_name} --poc_path {poc_path} --benign_coverage_folder {benign_coverage_folder} --binary_path {binary_path} --fuzzer_path {fuzzer_path} --coverage_build_target_dir {coverage_build_target_dir} --coverage_build_target_metadata_path {coverage_build_target_metadata_path} --output_dir {output_dir}"]
            validate_in_aurora_container(aurora_cmds)
            assert os.path.exists(os.path.join(output_dir, 'ranked_functions.json'))
            with open(os.path.join(output_dir, 'ranked_functions.json')) as f:
                sorted_func = json.load(f)
            assert len(sorted_func) > 0
            assert target_function in sorted_func
            keys = list(sorted_func.keys())
            target_index = keys.index(target_function)
            assert target_index < 10, f"Index is {target_index}, expected to be < 10"
        finally:
            os.system(f"rm -rf {temp_dir}")
    
if __name__ == "__main__":
    unittest.main(argv=sys.argv)
