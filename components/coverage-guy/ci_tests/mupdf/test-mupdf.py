
import os
import hashlib

from coveragelib import Tracer
from coveragelib.parsers.line_coverage import C_LineCoverageParser_LLVMCovHTML


oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
         os.path.join(seeds, "8f7cbbbe0e8f898a6fa93056b3de9c9c"),
         os.path.join(seeds, "92287b5f14a666dc572e95fac6853f6e"),
         os.path.join(seeds, "c0b3435b706cb4f3575a2bbfbc62f09f"),
         os.path.join(seeds, "ced03ca6e18b622bef1b632c53f53b94"),
         os.path.join(seeds, "ddb3535d4bffc91e7f2d4ca98df518b8")
        ]


def test_covguy_not_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "pdf_fuzzer", debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")

        if md5_res != "9fa9cac7d5948a5c6500e216e5ccb003":
            print(f"MD5 of result is {md5_res}, expected 9fa9cac7d5948a5c6500e216e5ccb003")
            print(f"Results from coverage: {res}")
            assert False
        
        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")

        if md5_res != "9fa9cac7d5948a5c6500e216e5ccb003":
            print(f"MD5 of result is {md5_res}, expected 9fa9cac7d5948a5c6500e216e5ccb003")
            print(f"Results from coverage: {res}")
            assert False

def test_covguy_not_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "pdf_fuzzer", debug_mode=True, include_seeds_metadata=True, parser=C_LineCoverageParser_LLVMCovHTML()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")

        if md5_res != "1a92eddf3a521c8d1ea360367866452b":
            print(f"MD5 of result is {md5_res}, expected 1a92eddf3a521c8d1ea360367866452b")
            # print(f"Results from coverage: {res}")
            assert False
        
        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")

        if md5_res != "1a92eddf3a521c8d1ea360367866452b":
            print(f"MD5 of result is {md5_res}, expected 1a92eddf3a521c8d1ea360367866452b")
            # print(f"Results from coverage: {res}")
            assert False
        

def test_covguy_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "pdf_fuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "30d846b4c0c5cbffb5b6a29fa2d32eec":
            print(f"MD5 of result is {md5_res}, expected 30d846b4c0c5cbffb5b6a29fa2d32eec")
            print(f"Results from coverage: {res}")
            assert False
        

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = list(r)
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "30d846b4c0c5cbffb5b6a29fa2d32eec":
            print(f"MD5 of result is {md5_res}, expected 30d846b4c0c5cbffb5b6a29fa2d32eec")
            print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "pdf_fuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True, parser=C_LineCoverageParser_LLVMCovHTML()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)

        md5s = []
        r = list(res)
        r.sort()
        r_md5 = hashlib.md5(str(r).encode()).hexdigest()
        md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "feda393fa4e5c78b1cf1a0d658401eac":
            print(f"MD5 of result is {md5_res}, expected feda393fa4e5c78b1cf1a0d658401eac")
            # print(f"Results from coverage: {res}")
            assert False


        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        md5s = []
        r = list(res)
        r.sort()
        r_md5 = hashlib.md5(str(r).encode()).hexdigest()
        md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()

        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        # Calculate the md5 of the string 
        md5_meta = hashlib.md5(str(meta).encode()).hexdigest()
        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "feda393fa4e5c78b1cf1a0d658401eac":
            print(f"MD5 of result is {md5_res}, expected feda393fa4e5c78b1cf1a0d658401eac")
            # print(f"Results from coverage: {res}")
            assert False

print("Test: test_covguy_not_aggregate_line_parser")
test_covguy_not_aggregate_line_parser()
print("Test: test_covguy_not_aggregate_simple_parser")
test_covguy_not_aggregate_simple_parser()
print("Test: test_covguy_aggregate_simple_parser")
test_covguy_aggregate_simple_parser()
print("Test: test_covguy_aggregate_line_parser")
test_covguy_aggregate_line_parser()


print("*******All tests passed!*******")