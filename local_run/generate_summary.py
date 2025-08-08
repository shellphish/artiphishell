#!/usr/bin/env python3
import argparse
import glob
import os
import subprocess
import time
import base64
import json
import hashlib

import yaml

# Dirty script to output markdown of the status of the CRS right now

OUTPUT_DATA = {
    "end_time": int(time.time()),
    "ci": {
        "action_run_id": "",
    },
    "configuration": {
        "target": "",
        "pipeline_run_timeout_minutes": "",
        "ref": "",
        "sha": "",
        "inject_seeds": False,
        "inject_sarif": False,
        "llm_budget": "",
        "diff_mode": False,
    },
    "game": {
        "VDS": [
            # {
            #    "submission_num": 0,
            #    "status": "",
            #    "commit_sha": "",
            # },
            # ...
        ],
        "GP": [
            # {
            #    "submission_num": 0,
            #    "status": "",
            #    "patch_content": "",
            # },
            # ...
        ],
    },
    "pipeline": {
        "backup_url": "",
        "execution_timeline_url": "",
        "tasks": [],
    },
    # Add summary metrics at the top level
    "summary": {
        "VDS_count": 0,
        "VDS_success": 0,
        "VDS_pending": 0,
        "GP_count": 0,
        "GP_success": 0,
        "GP_pending": 0
    }
}


parser = argparse.ArgumentParser()
parser.add_argument("--target", type=str, help="The target to test")
args = parser.parse_args()

# Fill out configuration part of OUTPUT_DATA based on GitHub Actions environment variables
OUTPUT_DATA["configuration"]["target"] = args.target
OUTPUT_DATA["configuration"]["pipeline_run_timeout_minutes"] = os.environ.get(
    "PIPELINE_RUN_TIMEOUT_MINUTES", ""
)
OUTPUT_DATA["configuration"]["ref"] = os.environ.get("GITHUB_REF", "")
OUTPUT_DATA["configuration"]["sha"] = os.environ.get("GITHUB_SHA", "")
OUTPUT_DATA["configuration"]["inject_seeds"] = os.environ.get("ARTIPHISHELL_GLOBAL_ENV_INJECT_SEEDS", "").lower() == "true"
OUTPUT_DATA["configuration"]["inject_sarif"] = os.environ.get("ARTIPHISHELL_GLOBAL_ENV_INJECT_SARIF", "").lower() == "true"
OUTPUT_DATA["configuration"]["llm_budget"] = os.environ.get("ARTIPHISHELL_GLOBAL_ENV_LLM_BUDGET", "")
OUTPUT_DATA["configuration"]["diff_mode"] = os.environ.get("ARTIPHISHELL_GLOBAL_ENV_CI_DIFF_MODE", "").lower() == "true"
OUTPUT_DATA["ci"]["action_run_id"] = os.environ.get("GITHUB_RUN_ID", "")

# Set gettting the info directly from the backup rather than going through pdt
BACKUP_DIR = os.environ.get("BACKUP_DIR", None)
STORAGE_URL = os.environ.get("STORAGE_URL", "your-backup-dir")

OUTPUT_DATA["pipeline"]["backup_url"] = (
    f"{STORAGE_URL}/backup-{args.target}-{OUTPUT_DATA['ci']['action_run_id']}.tar.gz"
)
OUTPUT_DATA["pipeline"]["crs_scratch_url"] = (
    f"{STORAGE_URL}/crs_scratch-{args.target}-{OUTPUT_DATA['ci']['action_run_id']}.tar.gz"
)
OUTPUT_DATA["pipeline"]["execution_timeline_url"] = (
    f"{STORAGE_URL}/container_plots/index.html"
)


IN_CI = False
GITHUB_ENV = os.environ.get("GITHUB_ENV", None)
if GITHUB_ENV:
    IN_CI = True
    ENV_OUTPUT_FILE = open(GITHUB_ENV, "a")


def store_github_env(name, value):
    assert IN_CI
    assert "EOF" not in value
    ENV_OUTPUT_FILE.write(f"""{name}<<EOF
{value}
EOF
""")


def pd(*args):
    if BACKUP_DIR:
        cmd = args[0]
        if cmd == "ls":
            task_job = args[1]
            to_return = ""

            backup_task_job_dir = f"{BACKUP_DIR}/{task_job}"
            if os.path.exists(backup_task_job_dir):
                for job in os.listdir(backup_task_job_dir):
                    to_return += f"{job.split('.')[0]}\n"
                return to_return.strip()
        elif cmd == "cat":
            task_job = args[1]
            job_id = args[2]

            files = glob.glob(f"{BACKUP_DIR}/{task_job}/{job_id}*")
            if len(files) == 1:
                assert len(files) == 1
                the_file = files[0]
                return open(the_file, "r").read()

    proc = subprocess.run(
        ["pd"] + list(args), capture_output=True, check=True, text=True
    )
    return proc.stdout.strip()


status = json.loads(pd("status", "-j"))

tasks = list(status.keys())
tasks.sort()


def add_pseudo_task(name):
    tasks.append(name)
    status[name] = {
        "done": [[], {}],
        "live": [[], {}],
    }


# SEARCH: Service List

add_pseudo_task("docker_builder")
add_pseudo_task("host_config")
add_pseudo_task("pydatatask_agent")
add_pseudo_task("crs_api")

add_pseudo_task("analysis_graph")
add_pseudo_task("codeql_server")
add_pseudo_task("lang_server")
add_pseudo_task("functionresolver_server")
add_pseudo_task("permanence")

add_pseudo_task('telemetry_db')
add_pseudo_task('telegraf')
add_pseudo_task("opensearch")
add_pseudo_task("otel-collector")
add_pseudo_task("data-prepper")
add_pseudo_task("jaeger")
add_pseudo_task("opensearch-dashboards")



def warn(message):
    print(f"> [!WARNING]  ")
    print(f"> {message}")


if IN_CI:
    # output tasks as an environment variable
    store_github_env("tasks", " ".join(tasks))

print("## VDS and GP status")
print("")
print("| Name | Total | Success | Pending | Success Rate |")
print("|------|-------|---------|---------|--------------|")

if not os.path.exists("/crs_scratch") or True:
    vds = []

    num_submission = 0
    for submission in os.listdir(f"{BACKUP_DIR}/submitter.vulnerability_submission/"):
        num_submission += 1
        submission_info = {}
        try:
            submission_info["submission_num"] = num_submission
            submission_info["status"] = ""
            submission_info["commit_sha"] = ""
            submission_info["sha"] = ""

            submission_id = submission.split(".")[0]
            submission_info["submission_id"] = submission_id

            try:
                with open(f"{BACKUP_DIR}/submitter.vulnerability_submission/{submission}", 'r') as f:
                    text = f.read()
                    submission_info['text'] = text
                    submission_metadata = yaml.safe_load(text)
            except (FileNotFoundError, yaml.YAMLError, IOError) as e:
                warn(f"Error reading or parsing VDS submission file {submission}: {e}")
                submission_metadata = {}
                submission_info['text'] = ""
            
            crash_id = submission_metadata.get('representative_crash_id', submission_metadata.get('identifier', None))
            vuln_id = submission_metadata.get('vuln_id', submission_metadata.get('pov_id', None))
            sub_status = submission_metadata.get('status', None)

            crash_metadata = {}
            crash_bytes = b'POV File Not Found'
            crash_base64 = base64.b64encode(crash_bytes).decode('utf-8')

            if not crash_id:
                warn(f"No representative_crash_id found for VDS submission {submission_id} in the submission metadata")

            else:
                pov_report_path = f"{BACKUP_DIR}/poiguy.pov_report_path/{crash_id}"
                if os.path.exists(pov_report_path):
                    try:
                        with open(pov_report_path, 'r') as f:
                            pov_report = yaml.safe_load(f)
                    except (FileNotFoundError, yaml.YAMLError, IOError) as e:
                        warn(f"Error reading or parsing crash metadata file for {crash_id}: {e}")
                        pov_report = {}
                else:
                    warn(f"File not found: {pov_report_path} for pov_report_path of VDS submission {submission_id} in the submission metadata")

                crash_path = f"{BACKUP_DIR}/submitter.crashing_input_path/{crash_id}"
                if os.path.exists(crash_path):
                    try:
                        with open(crash_path, 'rb') as f:
                            crash_bytes = f.read()
                            crash_base64 = base64.b64encode(crash_bytes).decode('utf-8')
                    except (FileNotFoundError, IOError) as e:
                        warn(f"Error reading crash file for {crash_id}: {e}")
                else:
                    warn(f"File not found: {crash_path} for crashing_input_path of VDS submission {submission_id} in the submission metadata")

            harness_name = pov_report.get('cp_harness_name', 'no-harness-name')

            dedup_tokens = pov_report.get('dedup_crash_report', {}).get('dedup_tokens', {})
            dedup_tokens_shellphish = pov_report.get('dedup_crash_report', {}).get('dedup_tokens_shellphish', {})
            dedup_tokens_full = pov_report.get('dedup_crash_report', {}).get('dedup_tokens_full', {})

            consistent_sanitizers = pov_report.get('consistent_sanitizers', [])

            data = dict(
                submission=dict(
                    cp_name=args.target,
                    pou={},
                    pov=dict(
                        harness=harness_name,
                    ),
                    crash_id=crash_id,
                ),response=dict(
                    status=sub_status,
                    vd_uuid=vuln_id,
                    cpv_uuid=vuln_id,
                ),
                crashing_commit_id=None,
                dedup_tokens=dedup_tokens,
                dedup_tokens_shellphish=dedup_tokens_shellphish,
                dedup_tokens_full=dedup_tokens_full,
                consistent_sanitizers=consistent_sanitizers,
            )

            submission_info["data"] = data

        except Exception as e:
            warn(f"Error processing VDS submission {submission}: {e}")
            submission_info["data"] = dict(
                submission=dict(),
                response=dict(
                    status="error",
                    error=str(e),
                ),
                crashing_commit_id=None,
            )

        vds.append(submission_info)

    OUTPUT_DATA["game"]["VDS"] = vds

    gps = []
    num_submission = 0
    for submission in os.listdir(f"{BACKUP_DIR}/submitter.patch_diff_meta"):
        num_submission += 1
        submission_info = {}
        try:
            submission_info["submission_num"] = num_submission
            submission_info["status"] = ""
            submission_info["commit_sha"] = ""
            submission_info["sha"] = ""

            submission_id = submission.split(".")[0]
            submission_info["submission_id"] = submission_id

            if not submission_id:
                warn(f"No submission_id found for GP submission {submission}")

            patch_text = b'Patch File Not Found'
            patch_base64 = base64.b64encode(patch_text).decode('utf-8')
            submission_metadata = {}

            diff_meta_path = f"{BACKUP_DIR}/submitter.patch_diff_meta/{submission}"
            if os.path.exists(diff_meta_path):
                try:
                    with open(diff_meta_path, 'r') as f:
                        text = f.read()
                        submission_info['text'] = text
                        submission_metadata = yaml.safe_load(text)
                except (FileNotFoundError, yaml.YAMLError, IOError, Exception) as e:
                    warn(f"Error reading or parsing diff meta file for {submission}: {e}")
                    submission_info['text'] = ""
            else:
                warn(f"File not found: {diff_meta_path} for patch_diff_meta of GP submission {submission_id}")
            
            patch_path = f"{BACKUP_DIR}/patcherq.out_patch/{submission_id}"
            if os.path.exists(patch_path):
                try:
                    with open(patch_path, 'rb') as f:
                        patch_text = f.read()
                        patch_base64 = base64.b64encode(patch_text).decode('utf-8')
                except (FileNotFoundError, IOError, Exception) as e:
                    warn(f"Error reading patch file for {submission_id}: {e}")
            else:
                warn(f"File not found: {patch_path} for patch_diff of GP submission {submission_id}")

            cpv_uuid = submission_metadata.get('cpv_uuid', submission_id)
            crash_id = submission_metadata.get('poi_report_id', None)
            patcher_name = submission_metadata.get('patcher_name', None)
            data_status = submission_metadata.get('status', "passed")  # Default to accepted if not specified
            data = dict(
                submission=dict(
                    cpv_uuid=cpv_uuid or submission_id,
                    crash_id=crash_id,
                    data=patch_base64,
                ),
                response=dict(
                    status=data_status,  # Use the status from the metadata
                    gp_uuid=submission_id,
                ),
                crashing_commit_id=None,
            )

            submission_info["data"] = data
        except Exception as e:
            warn(f"Error processing GP submission {submission}: {e}")
            submission_info["data"] = dict(
                submission=dict(),
                response=dict(
                    status="error",
                    error=str(e),
                ),
                crashing_commit_id=None,
            )

        gps.append(submission_info)

    OUTPUT_DATA["game"]["GP"] = gps



# Process submissions from backup directory for VDS and GP that weren't processed in the loop above
for target_name in ["VDS", "GP"]:
    if target_name in OUTPUT_DATA["game"]:
        submissions = OUTPUT_DATA["game"][target_name]
        num_submission = len(submissions)
        num_success = 0
        num_pending = 0
        
        # Count success and pending based on status
        for sub in submissions:
            if "data" in sub and "response" in sub["data"]:
                data_status = sub["data"]["response"].get("status", "")
                if data_status == "accepted" or data_status == "passed":
                    num_success += 1
                elif data_status == "pending":
                    num_pending += 1
        
        # Calculate success rate
        rate = "N/A"
        if num_submission != 0:
            rate = f"{num_success / num_submission:.0%}"
            
        if IN_CI:
            try:
                store_github_env(f"{target_name}_SUBMISSION_NUM", f"{num_submission}")
                store_github_env(f"{target_name}_SUCCESS_NUM", f"{num_success}")
                store_github_env(f"{target_name}_PENDING_NUM", f"{num_pending}")
            except Exception as e:
                warn(f"Error storing GitHub environment variables for {target_name}: {e}")
        
        # Update the top-level summary metrics
        OUTPUT_DATA["summary"][f"{target_name}_count"] = num_submission
        OUTPUT_DATA["summary"][f"{target_name}_success"] = num_success
        OUTPUT_DATA["summary"][f"{target_name}_pending"] = num_pending
                
        print(f"| {target_name} | {num_submission} | {num_success} | {num_pending} | {rate} |")

print("## Component Status")
print("")
print("| Component Name | Status | Num Ran | Num Running | Num Success | Rate | Logs |")
print("|----------------|--------|---------|-------------|-------------|------|------|")
outputs = []
for task in tasks:
    try:
        task_status = status.get(task, {'done': [[], {}], 'live': [[], {}]})

        job_ids = task_status["done"][0]
        # we also need to look for jobs in the logs in case they are in backoff
        try:
            extra_jobs = [
                x
                for x in os.listdir(f'{BACKUP_DIR}/{task}.logs/')
                if not '.' in x
            ]
            #print(extra_jobs)
            #input()
            job_ids = list(set(job_ids) | set(extra_jobs))
        except:
            pass
        num_ran = len(job_ids)
        num_running = len(task_status["live"][0])

        logs = ""
        jobs_success = 0

        output_task_info = {
            "task": task,
            "status": "",
            "num_ran": num_ran,
            "num_running": num_running,
            "jobs_success": jobs_success,
            "rate_str": "N/A",
            "rate": 1000,
            "logs": "",
        }
        output_jobs = []

        should_limit_jobs = True
        if 'patch' in output_task_info["task"].lower():
            should_limit_jobs = False

        did_skip = False

        for job in job_ids:
            try:
                job_result = None
                if os.path.exists(f"{BACKUP_DIR}/{task}.done/{job}.yaml"):
                    with open(f"{BACKUP_DIR}/{task}.done/{job}.yaml") as f:
                        job_result = yaml.safe_load(f.read())

                if not job_result:
                    lp = f"{BACKUP_DIR}/{task}.logs/{job}"
                    if not os.path.exists(lp):
                        lp = f"{BACKUP_DIR}/{task}.logs/0-{job}"
                    if os.path.exists(lp) and not os.path.exists(f"/tmp/ci/long-running/{task}"):
                        # Failed Backoff
                        job_result = dict(reason="Failed", success=False, timeout=False)

                if not job_result:
                    continue
                should_skip = False
                if job_result.get('success', False):
                    jobs_success += 1
                    if jobs_success >= 30:
                        should_skip = True
                    if not should_skip:
                        logs += f"[🟩{job[:5]}]({STORAGE_URL}/{task}.logs/{job}) "
                else:
                    logs += f"[🟥{job[:5]}]({STORAGE_URL}/{task}.logs/{job}) "

                if should_skip:
                    did_skip = True
                    if jobs_success == 30:
                        output_jobs.append({
                            "job": "view all",
                            "status": "success",
                            "logs": f"{STORAGE_URL}/{task}.logs/",
                            "result": None,
                        })
                    continue
                
                output_jobs.append({
                    "job": job,
                    "status": "success" if job_result.get('success', False) else "failed",
                    "logs": f"{STORAGE_URL}/{task}.logs/{job}",
                    "result": yaml.safe_dump(job_result),
                })
            except Exception as e:
                warn(f"Error parsing {task}.done/{job}: {e}")
                logs += f"[⚠️{job[:5]}]({STORAGE_URL}/{task}.logs/{job}) "
                output_jobs.append({
                    "job": job,
                    "status": "error",
                    "logs": f"{STORAGE_URL}/{task}.logs/{job}",
                    "result": None,
                })

        if did_skip:
            logs += f"[⚠️ truncated]({STORAGE_URL}/{task}.logs/)"

        if IN_CI and os.path.exists(f"/tmp/ci/long-running/{task}"):
            try:
                with open(f"/tmp/ci/long-running/{task}", "r") as f:
                    for long_job in f.readlines():
                        long_job = long_job.strip()
                        num_running += 1
                        output_task_info["num_running"] = num_running
                        if num_running < 30:
                            logs += f"[🏃{long_job[:5]}]({STORAGE_URL}/{task}.logs/{long_job}) "
                            output_jobs.append({
                                "job": long_job,
                                "status": "running",
                                "logs": f"{STORAGE_URL}/{task}.logs/{long_job}",
                                "result": None,
                            })
                        elif num_running == 30:
                            output_jobs.append({
                                "job": "view all",
                                "status": "running",
                                "logs": f"{STORAGE_URL}/{task}.logs/",
                                "result": None,
                            })
            except (FileNotFoundError, IOError) as e:
                warn(f"Error reading long-running jobs for {task}: {e}")



        output_task_info["jobs"] = output_jobs
        OUTPUT_DATA["pipeline"]["tasks"].append(output_task_info)

        if (num_ran + num_running) == 0:
            output_status = "⬜"
        elif num_ran == (jobs_success + num_running):
            output_status = "🟩"
        elif jobs_success == 0 and num_running != 0:
            output_status = "🏃"
        elif jobs_success == 0:
            output_status = "🟥"
        else:
            output_status = "🟧"

        rate_str = "N/A"
        rate = 1000  # just to make sure it's farther down the sort list
        if num_ran != 0:
            rate = (jobs_success + num_running) / num_ran
            rate_str = f"{rate:.0%}"

        if IN_CI:
            try:
                ran_status = "no"
                if num_ran != 0:
                    ran_status = "yes"
                store_github_env(f"{task}_RAN", ran_status)
            except Exception as e:
                warn(f"Error storing GitHub environment variable for {task}: {e}")

        outputs.append((task, output_status, num_ran, num_running, jobs_success, rate_str, rate, logs))
    except Exception as e:
        warn(f"Error processing task {task}: {e}")
        outputs.append((task, "⚠️", 0, 0, 0, "N/A", 1000, ""))

for (
    task,
    output_status,
    num_ran,
    num_running,
    jobs_success,
    rate_str,
    rate,
    logs,
) in sorted(outputs, key=lambda x: (x[-2], -x[3], x[0])):
    print(
        f"| {task} | {output_status} | {num_ran} | {num_running} | {jobs_success} | {rate_str} | {logs} |"
    )

try:
    os.system('sudo rm -rf /tmp/results.json')
except Exception as e:
    warn(f"Error removing old results file: {e}")

try:
    with open("/tmp/results.json","w") as f:
        f.write(json.dumps(OUTPUT_DATA))
except Exception as e:
    warn(f"Error writing results to /tmp/results.json: {e}")
