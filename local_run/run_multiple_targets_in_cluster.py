#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import time
import requests
import base64
import random

if len(sys.argv) != 2:
    print("Usage: python3 run_multiple_targets_in_cluster.py json_config")
    sys.exit(1)

json_config = sys.argv[1]
with open(json_config, "r") as f:
    config = json.load(f)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

with open(os.path.join(ROOT_DIR, ".github/workflows/targets.json"), "r") as f:
    targets = json.load(f)["targets"]

print(targets)

def should_stop_run():
    RUN_ID = os.environ.get("GITHUB_RUN_ID")
    res = requests.get(f"https://shellphish-support-syndicate-workers.cf-a92.workers.dev/api/v1/k8s/deployment/status/stopped?job_id={RUN_ID}")
    return res.text.strip() == "true"

def start_task(target, diff_mode=True, run_time=180, run_num=1):
    rand = random.randint(0, 9999)
    task_id = f"CAFE0000-0000-0000-{rand:04d}-0000000000{run_num:02d}"
    #return task_id, time.time() + run_time * 60

    env = os.environ.copy()
    basis = target.get("basis", None)
    diff = target.get("diff", 'main')

    env['TARGET_STS_TOKEN'] = base64.b64decode("c2U9MjAyNS0wNi0xMFQxMCUzQTUzWiZzcD1yYWN3ZGwmc3Y9MjAyMi0xMS0wMiZzcj1jJnNrb2lkPTBhMmZjZjQwLTZlMWMtNDliNi05ZjFmLTcyODA3OGY5MTVhYyZza3RpZD1jNjdkNDliZC1mM2VjLTRjN2YtYjllYy02NTM0ODAzNjU2OTkmc2t0PTIwMjUtMDYtMDNUMTAlM0E1MyUzQTM2WiZza2U9MjAyNS0wNi0xMFQxMCUzQTUzJTNBMDBaJnNrcz1iJnNrdj0yMDIyLTExLTAyJnNpZz1yanAwUmdlWUFNdWVCNnQ5VVdNQWFHUHFaaVBHdmI5ZFBoRjVRSS9GZVI0JTNECgo=").decode("utf-8")
    env['STORAGE_CONNECTION_STRING'] = base64.b64decode("RGVmYXVsdEVuZHBvaW50c1Byb3RvY29sPWh0dHBzO0VuZHBvaW50U3VmZml4PWNvcmUud2luZG93cy5uZXQ7QWNjb3VudE5hbWU9YXJ0aXBoaXNoZWxsY2k7QWNjb3VudEtleT0rL1FvOTJzZ1Q0c0xCbGpPZHgwSWJVeCtzejFoYmlGQUxEWTBGM3h1Rjd1NVhtQjRuNmRuMFppVDRlVktyQ3lIQ2NrRDV6NStRamxaK0FTdDZFYk9BUT09O0Jsb2JFbmRwb2ludD1odHRwczovL2FydGlwaGlzaGVsbGNpLmJsb2IuY29yZS53aW5kb3dzLm5ldC87RmlsZUVuZHBvaW50PWh0dHBzOi8vYXJ0aXBoaXNoZWxsY2kuZmlsZS5jb3JlLndpbmRvd3MubmV0LztRdWV1ZUVuZHBvaW50PWh0dHBzOi8vYXJ0aXBoaXNoZWxsY2kucXVldWUuY29yZS53aW5kb3dzLm5ldC87VGFibGVFbmRwb2ludD1odHRwczovL2FydGlwaGlzaGVsbGNpLnRhYmxlLmNvcmUud2luZG93cy5uZXQvCgo=")

    cmd = [
        os.path.join(ROOT_DIR, "local_run/run_in_cluster.sh"),
        target["repo"],
        target["short-name"],
    ]

    RUN_DUR_MS = run_time * 60 * 1000
    env["RUN_DUR_MS"] = str(RUN_DUR_MS)
    env["RUNTIME"] = str(run_time * 60)


    env["CRS_TASK_ID"] = task_id

    env["CUSTOM_OSS_FUZZ_TARGETS_REPO"] = target['targets-repo']

    if diff_mode and basis and diff:
        cmd += [basis, diff]
    else:
        cmd += [diff]

    print("=== Running run_in_cluster.sh")

    print('+' + ' '.join(cmd))
    sys.stdout.flush()
    subprocess.check_call(cmd, env=env)

    # now we wait until that time is up

    print(f"=== Task has now started, waiting {run_time} minutes for it to finish...")
    sys.stdout.flush()

    end_time = time.time() + run_time * 60 + 120

    return task_id, end_time

    while time.time() < end_time:
        time.sleep(10)
        if should_stop_run():
            print("Run has been stopped, exiting...")
            sys.stdout.flush()
            with open('/tmp/.stop_run','w') as f:
                f.write('true')
            sys.exit(0)

tasks_ran = []
active_tasks = {}

def start_parallel_tasks(parallel_tasks):
    for task in parallel_tasks:
        target_info = next((t for t in targets if t["name"] == task['name']), None)
        if target_info is None:
            print(f"⚠️⚠️⚠️ Target {task['name']} not found!!!")
            sys.stdout.flush()
            time.sleep(30)
            continue

        print(f"🚀 Starting task {task['name']} for {task['time']} minutes in {'diff' if task['diff'] else 'full'} mode")
        sys.stdout.flush()
        task_id, end_time = start_task(
            target_info,
            diff_mode=task['diff'],
            run_time=task['time'],
            run_num=len(tasks_ran)+1
        )
        task['end_time'] = end_time
        active_tasks[task_id] = task
        tasks_ran.append(task_id)
        time.sleep(60)

    wait_for_tasks()

def wait_for_tasks():
    while active_tasks:
        if should_stop_run():
            print("Run has been stopped, exiting...")
            sys.stdout.flush()
            with open('/tmp/.stop_run','w') as f:
                f.write('true')
            sys.exit(0)
            return

        for task_id, task in list(active_tasks.items()):
            if time.time() > task['end_time']:
                del active_tasks[task_id]
                print(f"🔴 Task {task['name']} has finished")
                sys.stdout.flush()
                if len(active_tasks) == 0:
                    return
        time.sleep(30)
        num_active_tasks = len(active_tasks)
        print(f"🐟 {num_active_tasks} tasks are still running")
        sys.stdout.flush()


for i, target_info in enumerate(config["multi"]):
    def_run_time = 180
    def_diff_mode = True
    parallel_tasks = []

    target_infos = []

    if type(target_info) == str:
        target_name = target_info
        target_infos = [dict(
            name=target_name,
            time=def_run_time,
            diff=def_diff_mode,
        )]

    elif type(target_info) == list:
        if type(target_info[0]) == str:
            target_infos = []

            ind = 0
            while ind < len(target_info):
                target_name = target_info[ind]
                run_time = def_run_time
                diff_mode = def_diff_mode
                to_add = 1
                if len(target_info) > ind+1 and type(target_info[ind+1]) == int:
                    run_time = target_info[ind+1]
                    to_add = 2
                if len(target_info) > ind+2 and target_info[ind+2] in { True, False }:
                    diff_mode = target_info[ind+2]
                    to_add = 3

                ind += to_add

                target_infos.append(dict(
                    name=target_name,
                    time=run_time,
                    diff=diff_mode,
                ))
        else:
            target_infos = target_info
    else:
        target_infos = [target_info]

    for target_info in target_infos:
        target_name = target_info["name"]
        run_time = target_info.get("time", def_run_time)
        diff_mode = target_info.get("diff", def_diff_mode)
        parallel_tasks.append(dict(
            name=target_name,
            time=run_time,
            diff=diff_mode,
        ))

    if len(parallel_tasks) > 0:
        print("Parallel tasks:")
        print(parallel_tasks)
        sys.stdout.flush()
        start_parallel_tasks(parallel_tasks)

time.sleep(300)

with open('/tmp/.stop_run','w') as f:
    f.write('true')
sys.exit(0)