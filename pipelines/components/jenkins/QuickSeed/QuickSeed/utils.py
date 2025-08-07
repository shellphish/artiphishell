import os
import subprocess
from git import Repo
from pathlib import Path
from typing import Optional

def absolute_path_finder(src_root: Path, relative_file_path: Path) -> Path:
    if os.path.exists(src_root / relative_file_path):
        return src_root / relative_file_path
    poi_src_name = os.path.basename(relative_file_path)
    for dirpath, dirnames, filenames in os.walk(src_root):
        if poi_src_name in filenames:
            poi_src_name_match = os.path.join(dirpath, poi_src_name)
            if type(relative_file_path) != str:
                relative_file_path = str(relative_file_path)
            if poi_src_name_match[-len(relative_file_path) :] == relative_file_path:
                return Path(poi_src_name_match)
    return None

class WorkDirContext:
    def __init__(self, path: Path):
        self.path = path
        self.origin = Path(os.getcwd()).absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.origin)

def setup_aicc_target(target_url: str, resources_dir, target_dir, target_repo_name: Optional[str] = None, target_name: Optional[str] = None):
    # first verify the test dir is setup locally
    if not target_dir.exists():
        target_dir.mkdir(parents=True)
    
        # verify that we have an unpacked functions json output dir
    json_output_dirs = resources_dir / "json_output_dirs"
    if not json_output_dirs.exists():
        json_output_dirs.mkdir() 
        json_tar = json_output_dirs.with_suffix(".tar") 
        if not json_tar.exists():
            raise FileNotFoundError(f"Did not find {json_tar}") 

        subprocess.run(
            ["tar", "xC", str(json_output_dirs), "-f", str(json_output_dirs.with_suffix(".tar"))], 
            check=True
        )

    if target_repo_name is None:
        target_repo_name = target_url.split("/")[-1].split(".git")[0]

    # git clone if we don't already have it
    target_repo_dir = target_dir / target_repo_name
    if not target_repo_dir.exists():
        Repo.clone_from(target_url, str(target_repo_dir))

    # reset the repo and pull to update it
    repo = Repo(str(target_repo_dir))
    repo.git.reset("--hard")
    repo.git.pull()


    original_directory = os.getcwd()
    os.chdir(target_repo_dir)
    subprocess.run(["make", "cpsrc-prepare"], check=True)
    # subprocess.run(["make", "docker-pull"], check=True)
    os.chdir(original_directory)
    

    return target_repo_dir
