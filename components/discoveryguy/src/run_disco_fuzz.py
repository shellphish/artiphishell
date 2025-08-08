import os
from pathlib import Path
import shutil
import hashlib
import subprocess

def find_all_seeds(benign_seeds, benign_hashes):
    benign_seeds_path = Path(benign_seeds)
    if not benign_seeds_path.exists():
        raise ValueError(f"Benign seeds path {benign_seeds_path} does not exist")

    target_hashes = set(benign_hashes)
    target_path = Path("/tmp/disco_fuzz_seeds")
    for seed_file in benign_seeds_path.rglob("*"):
        with open(seed_file, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        if file_hash in target_hashes:
            # Copy the seed file to a tmp folder
            target_path.joinpath(seed_file.name)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(seed_file, target_path)
            print(f"Copied seed {seed_file} to {target_path}")
    return target_path

def main():
    # lets parse all the environment variables
    disco_fuzz_request = os.environ.get("DISCO_FUZZ_REQUEST", None)
    benign_seeds = os.environ.get("DISCO_GUY_START_SEEDS", None)

    if not disco_fuzz_request or not benign_seeds:
        raise ValueError("Missing required environment variables")

    # lets parse the disco fuzz request
    BENIGN_SEEDS_DIR = os.environ.get("DISCO_GUY_START_SEEDS", None)
    HARNESSES_IN_SCOPE = os.environ.get("HARNESSES_IN_SCOPE", None)

    print("Harnesses in scope:", HARNESSES_IN_SCOPE)

    SEED_HASHES = os.environ.get("SEED_HASHES", None)
    if not BENIGN_SEEDS_DIR or not HARNESSES_IN_SCOPE or not SEED_HASHES:
        raise ValueError("Missing required environment variables for disco fuzz request")

    # Now lets get a tmp folder with just the seeds for that request
    seed_hashes = SEED_HASHES.split(" ")
    harnesses_in_scope = HARNESSES_IN_SCOPE.split(" ")

    fuzz_seeds = find_all_seeds(BENIGN_SEEDS_DIR, seed_hashes)
    # get a random uid for the fuzzer
    fuzzer_uid = os.urandom(8).hex()
    
    work_dir = Path(f"/work")
    harness_meta_payload = open('/tmp/harness','r').read().splitlines()
    for harness in harnesses_in_scope:
        corpus_dir = work_dir.joinpath(f"dg-{fuzzer_uid}", f"{harness}", "corpus")
        corpus_dir.mkdir(parents=True, exist_ok=True)
        # lets copy the seeds to the corpus dir
        shutil.copytree(fuzz_seeds, corpus_dir, dirs_exist_ok=True)

        sync_dir = work_dir.joinpath(f"dg-{fuzzer_uid}", f"{harness}", "sync")
        sync_dir.mkdir(parents=True, exist_ok=True)
        
        crashes_dir = work_dir.joinpath(f"dg-{fuzzer_uid}", f"{harness}", "crashes")
        crashes_dir.mkdir(parents=True, exist_ok=True)
        # change current working directory to the /out

        os.chdir("/out")

        cmd = [
            "run_fuzzer",
            corpus_dir,
            f"--artifact_prefix={crashes_dir}/",
        ]

        timeout = 60
        timeout_command = f"timeout --preserve-status -s KILL {timeout + 3} timeout -sINT {timeout + 2} "
        final_cmd = timeout_command + " ".join(cmd)
        print(f"Running fuzzer for harness {harness} with command: {final_cmd}")
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # now check for the process to finish
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                print(f"Fuzzer {harness} failed with return code {process.returncode}")
                continue  # Skip to the next harness if this one fails
            # If there are no crashes, then we delte and clean the folders
            has_crashes = False
            if crashes_dir.exists() and any(crashes_dir.iterdir()):
                has_crashes = True 
            if has_crashes:
                #TODO
                pass
            else:
                print(f"No crashes found for harness {harness}, deleting folders")
                shutil.rmtree(corpus_dir, ignore_errors=True)
                shutil.rmtree(sync_dir, ignore_errors=True)
                shutil.rmtree(crashes_dir, ignore_errors=True)
        except Exception as e:
                shutil.rmtree(corpus_dir, ignore_errors=True)
                shutil.rmtree(sync_dir, ignore_errors=True)
                shutil.rmtree(crashes_dir, ignore_errors=True)
             