import requests
import json
import yaml
import logging
import base64
import argparse
import time
import os
import random
from typing import List, Union, Generator, Dict, Tuple
from pathlib import Path

from rich.logging import RichHandler
from rich.console import Console

from models.vds import VDSResponse, VDSStatusResponse, VDSubmission, POU, POV
from models.gp import GPResponse, GPStatusResponse, GPSubmission
from models.types import FeedbackStatus
from submit_types import Commit, SubmitState, Patch

from shellphish_crs_utils.challenge_project import ChallengeProject
from collections import Counter, defaultdict

# Configure logging
FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)]
)

LOG = logging.getLogger("submitter")
LOG.setLevel(logging.DEBUG)

class BaseSubmitter:
    def __init__(self, in_dir: Path, out_dir: Path, lock_dir: Path, save_dir: Path):
        self.out_dir: Path = out_dir
        self.in_dir: Path = in_dir
        self.save_dir: Path = save_dir
        self.lock_dir: Path = lock_dir
        self.dir_prefix = "BASE"

        self.base_url: str
        self.headers: dict
        self.accepted_count = 0
        self.pending_count = 0
        self.rejected_count = 0
        self.invalid_submissions: Path = self.save_dir / "invalid_submissions"

        self.load_config()
    
    def load_config(self):
        location = os.environ.get("AIXCC_API_HOSTNAME", "http://172.17.0.1:8082")
        user = os.environ.get("CAPI_ID", "00000000-0000-0000-0000-000000000000")
        secret = os.environ.get("CAPI_TOKEN", "secret")
        auth_string = f"{user}:{secret}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode().strip()
        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": 'application/json'
        }
        self.base_url = location
        self.headers = headers
    
    def run_submission(self):
        if not self.is_healthy():
            return

        self.update_old_submissions()
        new_records = self.find_new_records()
        for record in new_records:
            try:
                response = self.submit(state=record)
                record.response = response
                self.save_results(record)
            except Exception as e:
                LOG.error("Failed to submit record: %s due to %s", record, e)
                continue
        LOG.info("%s - Pending %s, Accepted %s, Rejected %s", self.__class__.__name__, self.pending_count, self.accepted_count, self.rejected_count)
            
    def save_results(self, state: SubmitState):
        if isinstance(state.submission, VDSubmission):
            file_name = state.submission.pou.commit_sha1.lower()
            dir_prefix = "vds"
        elif isinstance(state.submission, GPSubmission):
            file_name = str(state.submission.cpv_uuid)
            dir_prefix = "gp"
        else:
            raise ValueError(f"Save Results not implemented for type {type(state.submission)}")

        save_dir: Path = self.save_dir / dir_prefix
        save_dir.mkdir(parents=True, exist_ok=True)
        with (save_dir / file_name).open("w") as f:
            f.write(state.model_dump_json(indent=4))


    def find_new_records(self) -> Generator[SubmitState, None, None]:
        raise NotImplementedError(f"No implementation of find_new_records in {self.__class__.__name__}")
    
    def is_healthy(self):
        LOG.info("Health check")
        healthy = False
        try:
            response = requests.get(f"{self.base_url}/health/", headers=self.headers)
            response.raise_for_status()
            LOG.info("Health Response: %s", response)
            healthy = True
        except requests.exceptions.RequestException as e:
            LOG.error(f"Health check failed: {e}")
            healthy = False
        return healthy
    
    def submit(self, state: SubmitState) -> Union[VDSResponse, GPResponse]:
        if isinstance(state.submission, VDSubmission):
            response_type = VDSResponse
            dir_prefix = "vds"
        elif isinstance(state.submission, GPSubmission):
            response_type = GPResponse
            dir_prefix = "gp"
        else:
            raise ValueError(f"Unexpected type: {type(state.submission)}")
        
        json_data = json.loads(state.submission.model_dump_json())
        if "pou" in json_data:
            json_data["pou"]["commit_sha1"] = json_data["pou"]["commit_sha1"].lower()
            json_data["pov"]["data"] = json_data["pov"]["data"]
        LOG.info("Submitting: %s", json_data)

        response = requests.post(f"{self.base_url}/submission/{dir_prefix}/", headers=self.headers, json=json_data)
        state.response = f"{response} | {response.content}"
        self.save_results(state)
        obj_response = response_type.model_validate_json(response.content, strict=True)
        LOG.info("Submission Response: %s", obj_response)
        return obj_response
    
    def get_status(self, status_submission: Union[VDSResponse, GPResponse, VDSStatusResponse, GPStatusResponse]) -> Union[VDSStatusResponse, GPStatusResponse]:
        if isinstance(status_submission, (VDSResponse, VDSStatusResponse)):
            response_type = VDSStatusResponse
            response_id = status_submission.vd_uuid
            dir_prefix = "vds"
        elif isinstance(status_submission, (GPResponse, GPStatusResponse)):
            response_type = GPStatusResponse
            response_id = status_submission.gp_uuid
            dir_prefix = "gp"
        else:
            raise ValueError(f"Unexpected Type: {type(status_submission)}")

        LOG.debug("Getting status for %s", status_submission)
        response = requests.get(f"{self.base_url}/submission/{dir_prefix}/{response_id}", headers=self.headers)
        obj_response = response_type.model_validate_json(response.content, strict=True)
        LOG.info("Status Update: %s", obj_response)
        return obj_response
     
    def update_old_submissions(self):
        (self.save_dir / self.dir_prefix).mkdir(parents=True, exist_ok=True)
        for file in (self.save_dir / self.dir_prefix).iterdir():
            try:
                data = json.loads(file.read_text())
                if "pou" in data["submission"]:
                    data["submission"]["pou"]["commit_sha1"] = data["submission"]["pou"]["commit_sha1"].lower()
                old_state = SubmitState.model_validate(data)
                if old_state.response.status == FeedbackStatus.PENDING or isinstance(old_state.response, (VDSResponse, GPResponse)):
                    response = self.get_status(old_state.response)
                    old_state.response = response
                    self.pending_count += 1
                    self.save_results(old_state)
                elif old_state.response.status == FeedbackStatus.ACCEPTED:
                    self.accepted_count += 1
                    self.pdt_result_output(old_state)
                    if isinstance(old_state.response, GPStatusResponse):
                        (self.invalid_submissions / old_state.crashing_commit_id).touch(exist_ok=True)
                elif old_state.response.status == FeedbackStatus.NOT_ACCEPTED:
                    self.rejected_count += 1
                    (self.invalid_submissions / old_state.crashing_commit_id).touch(exist_ok=True)
                    if isinstance(self, VDSubmitter):
                        self.remove_sanitizer(old_state.submission.pou.sanitizer, old_state.submission.pou.commit_sha1.lower())

            except Exception as e:
                LOG.error("Failed to check status on old submission: %s because of %s (Contents: %s)", file, e, file.read_bytes())
                continue
    
    def pdt_result_output(self, state: SubmitState):
        if isinstance(state.response, (VDSResponse, VDSStatusResponse)):
            file_name = state.submission.pou.commit_sha1
        elif isinstance(state.response, (GPResponse, GPStatusResponse)):
            file_name = str(state.submission.cpv_uuid)
        else:
            raise ValueError("Can't save result of type: %s", type(state.response))
        lock_file: Path = self.lock_dir / file_name
        lock_file.touch(exist_ok=True)
        with (self.out_dir / file_name).open("w") as f:
            data = json.loads(state.model_dump_json())
            if isinstance(state.response, (VDSResponse, VDSStatusResponse)):
                data["submission"]["pou"]["commit_sha1"] = data["submission"]["pou"]["commit_sha1"].lower()
            yaml.safe_dump(data, f)
        lock_file.unlink()

        

class VDSubmitter(BaseSubmitter):

    BACKOFF_TIME = 10
    INVALID_BACKOFF = 10

    def __init__(self, in_dir: Path, out_dir: Path, lock_dir: Path, save_dir: Path, project: Path, crash_dir: Path, crunch_time: int):
        super().__init__(in_dir, out_dir, lock_dir, save_dir)
        self.project = ChallengeProject(project)
        self.crash_dir = crash_dir
        self.dir_prefix = "vds"
        self._vds_backoff = self.save_dir / "vds_backoff"
        self._vds_sanitizers = self.save_dir / "vds_sanitizers.yaml"

        self._vds_backoff.mkdir(parents=True, exist_ok=True)
        self.crunch_time = crunch_time

    
    def has_vds_backoff(self, commit_hash: str) -> bool:
        """
        Checks if the vds file is older than the BACKOFF_TIME in minutes.
        """
        backoff_file = self._vds_backoff / commit_hash
        if self.crunch_time < 0 or os.environ.get("DISABLE_VDS_TIMEOUT") == "1":
            LOG.debug("CRUNCH, DISABLE_VDS_TIMEOUT=%s", os.environ.get("DISABLE_VDS_TIMEOUT"))
            return False

        if backoff_file.exists():
            time_left = self.BACKOFF_TIME*60 - (time.time() - backoff_file.stat().st_ctime )
            if time_left < 0:
                LOG.debug("Ending backoff for %s", commit_hash)
                return False
            LOG.debug("Backing off of %s for %sm%ss", commit_hash, int(time_left/60), int(time_left%60))
        else:
            LOG.debug("Starting backoff for %s", commit_hash)
            backoff_file.touch()
        return True
    
    def submit(self, state: SubmitState) -> VDSResponse:
        response = super().submit(state)
        self.add_sanitizer(state.submission.pou.sanitizer, state.submission.pou.commit_sha1.lower())
        return response
    
    @property
    def submitted_sanitizers(self) -> List[str]:
        if not self._vds_sanitizers.exists():
            self._vds_sanitizers.write_text("{}")
        sanitizers = json.loads(self._vds_sanitizers.read_text())
        LOG.debug("GETTING SANITIZERS: %s", sanitizers)
        all_sanitizers = []
        for sanitizer in sanitizers:
            all_sanitizers.extend([sanitizer]*len(sanitizers[sanitizer]))
        return all_sanitizers
    
    def add_sanitizer(self, sanitizer_id: str, commit_hash: str):
        sanitizers = json.loads(self._vds_sanitizers.read_text())
        LOG.info("ADDING SANITIZER: %s to %s", sanitizer_id, sanitizers)
        if sanitizer_id not in sanitizers:
            sanitizers[sanitizer_id] = [commit_hash]
        else:
            sanitizers[sanitizer_id].append(commit_hash)
        self._vds_sanitizers.write_text(json.dumps(sanitizers))
    
    def remove_sanitizer(self, sanitizer_id: str, commit_hash: str):
        sanitizers: Dict[str, List[str]] = json.loads(self._vds_sanitizers.read_text())
        if sanitizer_id in sanitizers and commit_hash in sanitizers[sanitizer_id]:
            LOG.info("REMOVING SANITIZER: %s from %s", sanitizer_id, sanitizers)
            sanitizers[sanitizer_id].remove(commit_hash)
            self._vds_sanitizers.write_text(json.dumps(sanitizers))
        else:
            LOG.info("SANITIZER %s or COMMIT %s not in %s", sanitizer_id, commit_hash, sanitizers)

    def get_new_commit(self) -> Union[Commit, None]:
        """
        Only submits one commit per cycle
        """
        commits: List[Commit] = []
        commit_list = list(self.in_dir.iterdir())
        random.shuffle(commit_list)
        for file in commit_list:
            with file.open("r") as f:
                commit_data = yaml.safe_load(f)
            commit_data["crashing_commit_id"] = file.name
            commit_data["crashing_commit"] = commit_data["crashing_commit"].lower()
            commit = Commit.model_validate(commit_data, strict=True)
            if (self.save_dir / self.dir_prefix / commit.crashing_commit).exists():
                LOG.debug("COMMIT ALREADY EXISTS, CONTINUING %s", (self.save_dir / self.dir_prefix / commit.crashing_commit))
                continue
            LOG.debug("ADDING COMMIT: %s", commit)
            commits.append(commit)
        
        LOG.debug("COMMITS: %s", commits)
        if len(commits) == 0:
            return None, None

        cp_sanitizers = set(self.project.sanitizers.keys())

        remaining_sanitizers = cp_sanitizers - set(self.submitted_sanitizers)
        current_sanitizers = Counter([y for x in commits for y in x.sanitizer_ids])
        LOG.debug("Curret Sanitizers: %s", current_sanitizers)
        LOG.debug("Remaining Sanitizers: %s", remaining_sanitizers)
        current_sanitizers += Counter(self.submitted_sanitizers) + Counter(cp_sanitizers)
        
        scores: Dict[int, List[Tuple[Commit, str]]] = {}
        LOG.debug("CURRENT SANITIZERS: %s", current_sanitizers)
        for commit in commits:
            min_id = min(commit.sanitizer_ids, key=lambda s: current_sanitizers[s])
            if current_sanitizers[min_id] not in scores:
                scores[current_sanitizers[min_id]] = []
            scores[current_sanitizers[min_id]].append((commit, min_id))

        LOG.debug("SCORES: %s", scores)
        for score in sorted(scores.keys()):
            for commit, san_id in scores[score]:
                if not self.has_vds_backoff(commit.crashing_commit):
                    return commit, san_id
        LOG.critical("Found no submittable commits out of %s", commits)
        return None, None
    
    def get_any_crashing_seed(self, commit: Commit) -> Path:
        LOG.info("Finding Crash ID: %s in %s", commit.crash_id, self.crash_dir)
        for crash in self.crash_dir.iterdir():
            if crash.name == commit.crash_id:
                LOG.info("Found Crash: %s", crash)
                return crash
        raise FileNotFoundError(f"Could not find ID matching crashing seed {commit.crash_id}")

    def find_new_records(self) -> Generator[VDSubmission, None, None]:
        commit = None
        try:
            commit, sanitizer_id = self.get_new_commit()
            LOG.debug("GOT %s %s", commit, sanitizer_id)
            if commit is None:
                return None
            crash = self.get_any_crashing_seed(commit)
            assert sanitizer_id is not None

            vd_submission = VDSubmission(cp_name=self.project.meta["cp_name"],
                                      pou=POU(commit_sha1=commit.crashing_commit.lower(), sanitizer=sanitizer_id),
                                      pov=POV(harness=commit.harness_id, data=base64.b64encode(crash.read_bytes())),
                                      )
            submission = SubmitState(submission=vd_submission, response=None, crashing_commit_id=commit.crashing_commit_id)
            yield submission
        except Exception as e:
            LOG.error("Failed to create submission for commit %s. %s", commit, e)

class GPSubmitter(BaseSubmitter):

    def __init__(self, in_dir: Path, out_dir: Path, lock_dir: Path, save_dir: Path, patch_meta_dir: Path, patch_ranking_dir: Path, vds_dir: Path):
        super().__init__(in_dir, out_dir, lock_dir, save_dir)

        self.vds_dir = vds_dir
        self.patch_meta_dir = patch_meta_dir
        self.patch_ranking_dir = patch_ranking_dir
        self.dir_prefix = "gp"

    def find_new_records(self) -> Generator[GPSubmission, None, None]:
        patches_by_vds_id: Dict[str, Dict] = {}
        known_vds_times: Dict[str, int] = {}
        for ranking in self.patch_ranking_dir.iterdir():
            try:
                with ranking.open("r") as f:
                    ranking_metadata = yaml.safe_load(f)
                if ranking_metadata["vds_id"] not in known_vds_times:
                    known_vds_times[ranking_metadata["vds_id"]] = ranking_metadata["timestamp"]
                if known_vds_times[ranking_metadata["vds_id"]] > ranking_metadata["timestamp"]:
                    continue
                valid_patches = [self.in_dir / Path(x).name for x in ranking_metadata["ranks"] if (self.in_dir / Path(x).name).exists() ]
                patches_by_vds_id[ranking_metadata["vds_id"]] = valid_patches
            except Exception as e:
                LOG.error("Failed to find ranking %s due to %s", ranking, e)
        LOG.debug("Found Ranked Patches %s", patches_by_vds_id)
            
        for patch_file in self.in_dir.iterdir():
            try:
                if not (self.patch_meta_dir / patch_file.name).exists():
                    LOG.debug("No metadata for patch %s", patch_file)
                    continue

                with (self.patch_meta_dir / patch_file.name).open("r") as f:
                    patch_meta = yaml.safe_load(f)
                vds_id = patch_meta["pdt_vds_id"]
                has_cpv_uuid = (self.save_dir / self.dir_prefix / patch_meta["cpv_uuid"]).exists()
                if has_cpv_uuid:
                    if patch_meta["pdt_vds_id"] in patches_by_vds_id and patch_file in patches_by_vds_id[vds_id]:
                        patches_by_vds_id[patch_meta["pdt_vds_id"]].remove(patch_file)
                    LOG.debug("Already submitted %s for patch %s", patch_meta["cpv_uuid"], patch_file)
                    continue

                if vds_id not in patches_by_vds_id:
                    patches_by_vds_id[vds_id] = []
                patches_by_vds_id[vds_id].append(patch_file)
            except Exception as e:
                LOG.error("Failed to find valid patch %s due to %s", patch_file, e)

        submission_list = []
        for vds_id, patch_list in patches_by_vds_id.items():
            try:
                if len(patch_list) == 0:
                    LOG.debug("No patches associated with vds %s", vds_id)
                    continue

                patch = None
                for selected_patch in patch_list:
                    LOG.debug("Selected Patch: %s", selected_patch)

                    patch_meta_file = self.patch_meta_dir / selected_patch.name
                    with patch_meta_file.open("r") as f:
                        patch_meta = yaml.safe_load(f)
                
                    cpv_uuid = patch_meta["cpv_uuid"]
                    if (self.save_dir / self.dir_prefix / cpv_uuid).exists():
                        LOG.debug("CPV_UUID (%s) already exists for patch: %s", cpv_uuid, selected_patch)
                        break

                    patch = Patch(data=base64.b64encode(selected_patch.read_bytes()), cpv_uuid=cpv_uuid)
                    break

                if patch is None:
                    continue

                LOG.debug("PATCH: %s", patch)
                assert len(patch.data) > 0
                vds_data = None
                for vds in (self.save_dir / "vds").iterdir():
                    with vds.open("r") as f:
                        vds_data = yaml.safe_load(f)
                    try:
                        cpv_uuid = vds_data["response"]["cpv_uuid"]
                        if cpv_uuid is not None and str(patch.cpv_uuid) == str(cpv_uuid):
                            LOG.critical("Found CPV_UUID: %s", patch.cpv_uuid)
                            break
                    except Exception as e:
                        LOG.debug("Failing with %s", e)
                        pass
                else:
                    LOG.critical("Could not find VDS with cpv_uuid: %s", patch.cpv_uuid)
                    continue
               
                vds_data["submission"]["pou"]["commit_sha1"] = vds_data["submission"]["pou"]["commit_sha1"].lower()
                prev_submission = SubmitState.model_validate(vds_data)
                if not isinstance(prev_submission.response, VDSStatusResponse):
                    LOG.critical("SKIPPING!! Unexpected Response: %s %s", type(prev_submission.response), prev_submission.response)
                    continue
                response = self.get_status(prev_submission.response)
                if response.status != FeedbackStatus.ACCEPTED:
                    LOG.critical("SKIPPING!! Unknown VDS %s", response)
                    continue
                LOG.info("Found VDS %s", prev_submission)
                gp_submission = GPSubmission(cpv_uuid=prev_submission.response.cpv_uuid, data=patch.data)
                submission = SubmitState(submission=gp_submission, response=None, crashing_commit_id=prev_submission.crashing_commit_id)
                submission_list.append((submission, prev_submission))
            except Exception as e:
                LOG.error("Failed to find new Patch: %s", e)
                continue

        patches_per_sanitizer = defaultdict(list)
        for submission, prev_submission in submission_list:
            try:
                patches_per_sanitizer[prev_submission.submission.pou.sanitizer].append((submission, prev_submission))
            except Exception as e:
                LOG.debug("Failed to add to sanitizer dict for %s:%s", submission, prev_submission)

        while any([len(v) > 0 for v in patches_per_sanitizer.values()]):
            for sanitizer in list(patches_per_sanitizer.keys()):
                if not patches_per_sanitizer[sanitizer]:
                    continue
                submission, prev_submission = patches_per_sanitizer[sanitizer].pop(0)
                if len(list(self.invalid_submissions.iterdir())) >= INVALID_SUBMISSION_OR_PATCH_BACKOFF:
                    LOG.critical("RECEIVED %s INVALID SUBMISSIONS: ", len(self.invalid_submissions.iterdir()))
                    return
                yield submission


def get_args() -> argparse.Namespace:
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Process VDS and GP submissions.')
    parser.add_argument('--saved-results', type=Path, required=True, help='Path to saved results')

    vds_group = parser.add_argument_group("VDS Record")
    vds_group.add_argument('--project', type=Path, required=True, help='Challenge Problem project path')
    vds_group.add_argument('--crashing-commit', type=Path, required=True, help='All verified Crashing Commits')
    vds_group.add_argument('--crashing-seed', type=Path, required=True, help='All Crashing Seeds')
    vds_group.add_argument('--vds-output', type=Path, required=True, help="Path where the result should be stored")
    vds_group.add_argument('--vds-output-lock', type=Path, required=True, help="Path where the result can first lock to prevent premature reading")

    gp_group = parser.add_argument_group("GP Record")
    gp_group.add_argument('--patch', type=Path, required=True, help='Path to the Patch dir')
    gp_group.add_argument('--patch-meta', type=Path, required=True, help='Path to the Patch Meta dir')
    gp_group.add_argument('--patch-ranking', type=Path, required=True, help='Path to the Patch Ranking dir')
    gp_group.add_argument('--gp-output', type=Path, required=True, help="Path where the result should be stored")
    gp_group.add_argument('--gp-output-lock', type=Path, required=True, help="Path where the result can first lock to prevent premature reading")
    gp_group.add_argument('--start-time', type=int, required=True, help="Epoch time of the target ingest time")
    args = parser.parse_args()
    return args

INVALID_SUBMISSION_OR_PATCH_BACKOFF = 10

def main():
    args = get_args()
    ROUND_TIME_SECONDS = int(os.environ.get("ROUND_TIME_SECONDS", str(4*60*60)) or str(4*60*60))
    PATCH_WAIT_TIME = int(ROUND_TIME_SECONDS*0.875)
    VDS_WAIT_TIME = int(ROUND_TIME_SECONDS*0.75)
    LOG.info("ROUND TIME %02d:%02d:%02d", int(ROUND_TIME_SECONDS/60/60), int(ROUND_TIME_SECONDS/60) % 60, int(ROUND_TIME_SECONDS %60))
    LOG.info("VDS WAIT %02d:%02d:%02d", int(VDS_WAIT_TIME/60/60), int(VDS_WAIT_TIME/60) % 60, int(VDS_WAIT_TIME %60))
    LOG.info("PATCH WAIT %02d:%02d:%02d", int(PATCH_WAIT_TIME/60/60), int(PATCH_WAIT_TIME/60) % 60, int(PATCH_WAIT_TIME %60))

    patch_time_diff = args.start_time + PATCH_WAIT_TIME - int(time.time())
    vds_time_diff = args.start_time + VDS_WAIT_TIME - int(time.time())
    invalid_submissions: Path = args.saved_results / "invalid_submissions"
    invalid_submissions.mkdir(parents=True, exist_ok=True)

    num_invalid = len(list(invalid_submissions.iterdir()))  
    if num_invalid >= INVALID_SUBMISSION_OR_PATCH_BACKOFF:
        LOG.critical("RECEIVED %s INVALID OR PATCH SUBMISSIONS", len(invalid_submissions))
        return
    
    if num_invalid > 0:
        LOG.critical("%s INVALID SUBMISSIONS BE CAREFUL", num_invalid)

    LOG.info("Running VD Submitter")
    vds_submitter = VDSubmitter(args.crashing_commit, 
                                args.vds_output,
                                args.vds_output_lock,
                                args.saved_results,
                                args.project,
                                args.crashing_seed,
                                vds_time_diff
                                )
    vds_submitter.run_submission()
    
    if patch_time_diff > 0 and os.environ.get("DISABLE_GP_TIMEOUT") != "1":
        hours = int(patch_time_diff / 60 / 60)
        mins = int((patch_time_diff / 60) % 60)
        seconds = int(patch_time_diff % 60)
        LOG.info("Waiting to submit Patches in .... %s:%s:%s", hours, mins, seconds)
        return

    LOG.info("Running GP Submitter")
    gp_submitter = GPSubmitter(args.patch,
                               args.gp_output,
                               args.gp_output_lock,
                               args.saved_results,
                               args.patch_meta,
                               args.patch_ranking,
                               args.vds_output)
    gp_submitter.run_submission()

if __name__ == "__main__":
    main()