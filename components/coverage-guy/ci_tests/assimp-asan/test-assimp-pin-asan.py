import os
import hashlib
from coveragelib import Tracer, Pintracer, PintracerWithSanitizer
import sys
import time
from pathlib import Path
from shellphish_crs_utils.oss_fuzz.instrumentation.coverage_fast import CoverageFastInstrumentation
from shellphish_crs_utils.oss_fuzz.project import InstrumentedOssFuzzProject, OSSFuzzProject

oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
         os.path.join(seeds, "crash-assimp"),
        ]
harness = [oss_fuzz_repo, "assimp_fuzzer"]

project_name="assimp"

asan_build_path = oss_fuzz_repo + "-asan"
coverage_build_path= oss_fuzz_repo
harness_name = "assimp_fuzzer"

asan_project = OSSFuzzProject(project_id = None,
                                            oss_fuzz_project_path = asan_build_path,
                                            project_source = None,
                                            use_task_service = False)
instrumentation = CoverageFastInstrumentation()
coverage_project = InstrumentedOssFuzzProject(
            instrumentation,
            coverage_build_path)


def test_func_no_inline_names():
    with PintracerWithSanitizer(oss_fuzz_project=asan_project,
                        coverage_oss_fuzz_project=coverage_project,
                        coverage_build_path=coverage_build_path, 
                        sanitizer_build_path=asan_build_path,     
                           harness_name=harness_name,
                           debug_mode=True, 
                           aggregate=False, 
                           trace_inlines=False,
                           full_function_mode=True, 
                           return_func_json=False, 
                           ) as ptracer:
        start = time.time()
        
        res = ptracer.trace(*seeds)
        
        end = time.time()
        print(f"Time taken: {end - start}")
        for v in res.values():
                assert len(v) >0, "Something is off with parsing"
        res_0 = res[set(res.keys()).pop()]

        res_str = str(res_0)
        md5_res_str = hashlib.md5(res_str.encode()).hexdigest()
        if md5_res_str != '0bfb6b4af090f6db862f7fd40a8e98a2':
            print(f"MD5 of result is {md5_res_str}, expected 0bfb6b4af090f6db862f7fd40a8e98a2")

            assert False


def test_func_no_inline_json():
    with PintracerWithSanitizer(oss_fuzz_project=asan_project,
                        coverage_oss_fuzz_project=coverage_project,
                        coverage_build_path=coverage_build_path, 
                        sanitizer_build_path=asan_build_path,     
                           harness_name=harness_name,
                           debug_mode=True, 
                           aggregate=False, 
                           trace_inlines=True,
                           full_function_mode=True, 
                           return_func_json=False, 
                           ) as ptracer:
        start = time.time()
        
        res = ptracer.trace(*seeds)
        
        end = time.time()
        
        print(f"Time taken: {end - start}")
        for v in res.values():
                assert len(v) >0, "Something is off with parsing"
        
        res_0 = res[set(res.keys()).pop()]

        res_str = str(res_0)
        md5_res_str = hashlib.md5(res_str.encode()).hexdigest()
        
        if md5_res_str != '4c77f9c2c1d4f413dfa7538f9a070e69':
            print(f"MD5 of result is {md5_res_str}, expected 4c77f9c2c1d4f413dfa7538f9a070e69")

            assert False



def test_func_inline_names():
    with PintracerWithSanitizer(oss_fuzz_project=asan_project,
                        coverage_oss_fuzz_project=coverage_project,
                        coverage_build_path=coverage_build_path, 
                        sanitizer_build_path=asan_build_path,     
                           harness_name=harness_name,
                           debug_mode=True, 
                           aggregate=False, 
                           trace_inlines=True,
                           full_function_mode=True, 
                           return_func_json=False, 
                           ) as ptracer:
        start = time.time()
        
        res = ptracer.trace(*seeds)
        
        end = time.time()
        
        print(f"Time taken: {end - start}")
        for v in res.values():
                assert len(v) >0, "Something is off with parsing"
        res_0 = res[set(res.keys()).pop()]

        res_str = str(res_0)
        md5_res_str = hashlib.md5(res_str.encode()).hexdigest()
        
        if md5_res_str != '4c77f9c2c1d4f413dfa7538f9a070e69':
            print(f"MD5 of result is {md5_res_str}, expected 4c77f9c2c1d4f413dfa7538f9a070e69")

            assert False


def test_func_inline_json():
    with PintracerWithSanitizer(oss_fuzz_project=asan_project,
                        coverage_oss_fuzz_project=coverage_project,
                        coverage_build_path=coverage_build_path, 
                        sanitizer_build_path=asan_build_path,     
                           harness_name=harness_name,
                           debug_mode=True, 
                           aggregate=False, 
                           trace_inlines=True,
                           full_function_mode=True, 
                           return_func_json=True, 
                           ) as ptracer:
        start = time.time()
        
        res = ptracer.trace(*seeds)
        
        end = time.time()
        
        print(f"Time taken: {end - start}")
        for v in res.values():
                assert len(v) >0, "Something is off with parsing"
        
        res_0 = res[set(res.keys()).pop()]
        res_str = str(res_0)
        md5_res_str = hashlib.md5(res_str.encode()).hexdigest()
        
        if md5_res_str != '4eefc9bf723d87e4b86a5e9239a0bb39':
            print(f"MD5 of result is {md5_res_str}, expected 4eefc9bf723d87e4b86a5e9239a0bb39")

            assert False


print("Test: test_covguy_pintracer_full")
test_func_no_inline_json()
test_func_inline_json()
test_func_inline_names()
test_func_no_inline_names()

# TODO: implement test for indirect branch tracking

print("*******All tests passed!*******")