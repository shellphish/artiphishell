
import os
import hashlib

from coveragelib import Tracer
from coveragelib.parsers.line_coverage import Java_LineCoverageParser_Jacoco


oss_fuzz_repo=os.environ.get("OSS_FUZZ_TARGET_REPO", None)
target_src=os.environ.get("TARGET_SRC", None)
seeds=os.environ.get("SEEDS", None)

assert(oss_fuzz_repo is not None)
assert(target_src is not None)
assert(seeds is not None)

seeds = [
         os.path.join(seeds, "empty"),
         os.path.join(seeds, "0386db182ae9d8db50dfd285499da2af"),
         os.path.join(seeds, "050764bb7d2fe57ea75ff1a2f09e8a62")
        ]

def test_covguy_not_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)

        
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = [ str(x) for x in list(r) ]
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

        if md5_res != "12aef8e4cb12d344407f1e9b8a4510fe":
            print(f"MD5 of result is {md5_res}, expected ebfc4cb89c16c391cc9a1203acd894a1")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)

        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = [ str(x) for x in list(r) ]
            r.sort()
            r_md5 = hashlib.md5(str(r).encode()).hexdigest()
            md5s.append(r_md5)
        
        # Sort md5s alphabetically
        md5s.sort()
        # Compute the md5 of the md5s
        md5_res = hashlib.md5(str(str(md5s)).encode()).hexdigest()
        #print(f"MD5 of result: {md5_res}")

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "144a3f959efaed0c9206a1289fab7dd2":
            print(f"MD5 of result is {md5_res}, expected 144a3f959efaed0c9206a1289fab7dd2")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_not_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", debug_mode=True, include_seeds_metadata=True, parser=Java_LineCoverageParser_Jacoco()) as tracer:
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


        if md5_res != "b0908923eb120a556f1e9efc2229e4cc":
            print(f"MD5 of result is {md5_res}, expected 29c93b15be1d408bb7976748b87b672d")
            #print(f"Results from coverage: {res}")
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

        if md5_res != "8785e59c68df953c55749e2cf928e894":
            print(f"MD5 of result is {md5_res}, expected 8785e59c68df953c55749e2cf928e894")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_simple_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = [ str(x) for x in list(r) ]
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
        
        print(md5_res)
        print(md5_meta)
        

        #print(f"MD5 of metadata: {md5_meta}")
        if md5_res != "9eda66c156ca5cd025876c800e2d3625":
            print(f"MD5 of result is {md5_res}, expected 9eda66c156ca5cd025876c800e2d3625")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        for r in res:
            r = [ str(x) for x in list(r) ]
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
        if md5_res != "9eda66c156ca5cd025876c800e2d3625":
            print(f"MD5 of result is {md5_res}, expected 9eda66c156ca5cd025876c800e2d3625")
            #print(f"Results from coverage: {res}")
            assert False


def test_covguy_aggregate_line_parser():
    with Tracer(oss_fuzz_repo, "Zip4jFuzzer", aggregate=True, debug_mode=True, include_seeds_metadata=True, parser=Java_LineCoverageParser_Jacoco()) as tracer:
        print(" - Run 1")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        r = str(res)
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
        if md5_res != "6ac1b2abcd6c14e350af3c1d650cb810":
            print(f"MD5 of result is {md5_res}, expected 6ac1b2abcd6c14e350af3c1d650cb810")
            #print(f"Results from coverage: {res}")
            assert False

        ######################################
        # TRACE AGAIN RE-USING THE SAME TRACER
        # ####################################
        print(" - Run 2")
        res, meta = tracer.trace(*seeds)
        
        # For every element in the list, compute the md5
        md5s = []
        r = str(res)
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
        if md5_res != "e13fb7a06857c619a3f61fdd98e84901":
            print(f"MD5 of result is {md5_res}, expected e13fb7a06857c619a3f61fdd98e84901")
            #print(f"Results from coverage: {res}")
            assert False


print("Test: test_covguy_aggregate_line_parser")
test_covguy_aggregate_line_parser()
print("Test: test_covguy_aggregate_simple_parser")
test_covguy_aggregate_simple_parser()

# These are using myroco, if something goes wrong ping @Freakston/@degrigis
print("Test: test_covguy_not_aggregate_simple_parser [myroco]")
test_covguy_not_aggregate_simple_parser()
print("Test: test_covguy_not_aggregate_line_parser [myroco]")
test_covguy_not_aggregate_line_parser()

print("*******All tests passed!*******")