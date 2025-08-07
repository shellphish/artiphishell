from collections import defaultdict
import json
import os
from pathlib import Path
import subprocess
import yaml
import logging
from shellphish_crs_utils.pydatatask import PDTRepo
from shellphish_crs_utils.challenge_project import ChallengeProject
LOG = logging.getLogger("analyze_target")

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def split_harnesses(target_id: str, cp: ChallengeProject, harness_infos_repo: PDTRepo):
    print(f"Splitting harnesses for target {target_id}: {harness_infos_repo}, {cp.harnesses}")
    for harness in cp.harnesses:
        data = {
            'target_id':        str(target_id),
            'cp_harness_id':    str(harness.harness_id),
            'cp_harness_name':  str(harness.name),
            'cp_harness_source_path':   str(harness.source),
            'cp_harness_binary_path':   str(harness.binary),
        }
        
        harness_infos_repo.upload_dedup(json.dumps(data, indent=2))
                    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-id', required=True, type=str)
    parser.add_argument('--target-dir', required=True, type=Path)
    parser.add_argument('--harness-infos-dir', required=True, type=Path)
    parser.add_argument('--harness-infos-lock-dir', required=True, type=Path)
    ARGS = parser.parse_args()

    harness_infos_repo = PDTRepo(ARGS.harness_infos_dir, ARGS.harness_infos_lock_dir)
    cp = ChallengeProject(ARGS.target_dir)
    split_harnesses(ARGS.target_id, cp, harness_infos_repo)
