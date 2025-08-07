import hashlib
import os
from pathlib import Path
import subprocess
import time
from shellphish_crs_utils.challenge_project import ChallengeProject


BUILD_CACHE_BASE_DIR = Path('/shared/target_build_cache')


def build_cache_dir_for_commit(commit_hash, patch=None):
    if patch is None:
        return BUILD_CACHE_BASE_DIR / commit_hash
    else:
        return BUILD_CACHE_BASE_DIR / f"{commit_hash}_{hashlib.sha1(patch.encode()).hexdigest()}"


def build_target_by_commit(target_dir, commit_hash, patch=None):

    target_dir = Path(target_dir)
    assert target_dir.exists(), f"Target directory {target_dir} does not exist"
    assert (target_dir / 'project.yaml').exists(), f"Project file {target_dir / 'project.yaml'} does not exist"
    assert (target_dir / 'run.sh').exists(), f"Run script {target_dir / 'run.sh'} does not exist"
    assert (target_dir / 'Dockerfile').exists(), f"Dockerfile {target_dir / 'Dockerfile'} does not exist"

    cache_dir = build_cache_dir_for_commit(commit_hash, patch)
    if os.path.exists(cache_dir):
        project = ChallengeProject(target_dir)
        project.checkout_commit(commit_hash)
        return project.artifacts

    # now, try to lock the file so we can build it
    lock_file = str(cache_dir).rstrip("/") + '.lock'
    lockfile = '/tmp/{pid}.lock'.format(pid=os.getpid())
    with open(lockfile, 'w') as f:
        f.write(str(os.getpid()))

    # try to move the file to the lock file, fail if it already exists
    try:
        os.rename(lockfile, lock_file)
    except FileExistsError:
        # someone else is already building it
        return wait_until_built(cache_dir)

    # now copy the entire target_dir to the cache_dir
    subprocess.check_call(['rsync', '-ra', '--delete', str(target_dir / "target") + '/', str(cache_dir) + '/'])

    project = ChallengeProject(target_dir)
    project.checkout_commit(commit_hash)
    project.build(patch)
    return project.artifacts
