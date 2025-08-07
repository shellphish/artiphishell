#!/usr/bin/env python3
import glob
import os
import subprocess
import sys

import json

import yaml

# Dirty script to output markdown of the status of the CRS right now

# Set gettting the info directly from the backup rather than going through pdt
BACKUP_DIR = os.environ.get("BACKUP_DIR", None)
STORAGE_URL = os.environ.get("STORAGE_URL", "your-backup-dir")

IN_CI=False
GITHUB_ENV = os.environ.get("GITHUB_ENV", None)
if GITHUB_ENV:
    IN_CI = True
    ENV_OUTPUT_FILE = open(GITHUB_ENV, 'a')

def store_github_env(name, value):
    assert(IN_CI)
    assert(not "EOF" in value)
    ENV_OUTPUT_FILE.write(f"""{name}<<EOF
{value}
EOF
""")

def pd(*args):
    if BACKUP_DIR:
        cmd = args[0]
        if cmd == 'ls':
            task_job = args[1]
            to_return = ""
            
            backup_task_job_dir = f"{BACKUP_DIR}/{task_job}"
            if os.path.exists(backup_task_job_dir):
                for job in os.listdir(backup_task_job_dir):
                    to_return += f"{job.split('.')[0]}\n"
                return to_return.strip()
        elif cmd == 'cat':
            task_job = args[1]
            job_id = args[2]

            files = glob.glob(f"{BACKUP_DIR}/{task_job}/{job_id}*")
            if len(files) == 1:
                assert(len(files) == 1)
                the_file = files[0]
                return open(the_file, 'r').read()
        
    proc = subprocess.run(["pd"] + list(args), capture_output=True, check=True, text=True)
    return proc.stdout.strip()


status = json.loads(pd("status", "-j"))

tasks = list(status.keys())
tasks.sort()

if IN_CI:
    # output tasks as an environment variable
    store_github_env("tasks", " ".join(tasks))

print("## VDS and GP status")
print("")
print("| Name | Total | Success | Pending | Success Rate |")
print("|------|-------|---------|---------|--------------|")

target_dirs = [("VDS", "/crs_scratch/submission/vds/"), ("GP", "/crs_scratch/submission/gp/")]

for target_name, target_dir in target_dirs:
    num_submission = 0
    num_success = 0
    num_pending = 0
    if os.path.exists(target_dir):
        for submission in os.listdir(target_dir):
            num_submission += 1

            with open(f"{target_dir}/{submission}", 'r') as f:
                result = yaml.safe_load(f.read())

                if 'response' in result:
                    response = result['response'].get('status', 'failed')
                    if response == 'pending':
                        num_pending += 1
                    elif response == 'accepted':
                        num_success += 1

    rate = "N/A"
    if num_submission != 0:
        rate = f"{num_success / num_submission:.0%}"

    if IN_CI:
        store_github_env(f"{target_name}_SUBMISSION_NUM", f"{num_submission}")
        store_github_env(f"{target_name}_SUCCESS_NUM", f"{num_success}")
        store_github_env(f"{target_name}_PENDING_NUM", f"{num_pending}")

    print(f"| {target_name} | {num_submission} | {num_success} | {num_pending} | {rate} |")
    


print("## Component Status")
print("")
print("| Component Name | Status | Num Ran | Num Running | Num Success | Rate | Logs |")
print("|----------------|--------|---------|-------------|-------------|------|------|")
outputs = []
for task in tasks:
    task_status = status[task]

    job_ids = task_status['done'][0]
    num_ran = len(job_ids)
    num_running = len(task_status['live'][0])

    logs = ""
    jobs_success = 0

    for job in job_ids:
        job_result = yaml.safe_load(pd('cat', f"{task}.done", job))
        if job_result['success']:
            jobs_success += 1
            logs += f"[🟩{job[:5]}]({STORAGE_URL}/{task}.logs/{job}) "
        else:
            logs += f"[🟥{job[:5]}]({STORAGE_URL}/{task}.logs/{job}) "

    if IN_CI and os.path.exists(f"/tmp/ci/long-running/{task}"):
        with open(f"/tmp/ci/long-running/{task}", "r") as f:
            for long_job in f.readlines():
                long_job = long_job.strip()
                logs += f"[🏃{long_job[:5]}]({STORAGE_URL}/{task}.logs/{long_job}) "

    if (num_ran+num_running) == 0:
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
    rate = 1000 # just to make sure it's farther down the sort list
    if num_ran != 0:
        rate = (jobs_success + num_running) / num_ran
        rate_str = f"{rate:.0%}"

    if IN_CI:
        ran_status = "no"
        if num_ran != 0:
            ran_status = "yes"
        store_github_env(f"{task}_RAN", ran_status)

    outputs.append((task, output_status, num_ran, num_running, jobs_success, rate_str, rate, logs))

for task, output_status, num_ran, num_running, jobs_success, rate_str, rate, logs in sorted(outputs, key=lambda x: (x[-2], -x[3], x[0])):
    print(f"| {task} | {output_status} | {num_ran} | {num_running} | {jobs_success} | {rate_str} | {logs} |")
