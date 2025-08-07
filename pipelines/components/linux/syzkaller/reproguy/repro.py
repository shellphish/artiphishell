from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import shutil
import subprocess
from pathlib import Path

DEBUG = False
crashes = {}
C_REPRODUCER_OUT_PATH = None
SYZLANG_REPRODUCER_OUT_PATH = None
CRASHDIR = ""
def addrepro():
    pass    

def write_file():
    global DEBUG, crashes
    if DEBUG:
        print("Unpacking crashes")
        os.system('tar -xf /crashes.tar.gz -C /crashes')
        DEBUG = False
    if not DEBUG:
        for crash_id in crashes.copy().keys():
            if crashes[crash_id]["reproduced"] == True or crashes[crash_id]["being_repro"] == True:
                if crashes[crash_id]["reproduced"] == True:
                    print(f"[*] Done reproducing {crash_id}")
                continue
            if crashes[crash_id]["description"] and crashes[crash_id]["log"] and crashes[crash_id]["report"]:
                if "SYZFATAL" in open(crashes[crash_id]["description"],'r').read():
                    continue
                print(f"ready to repro crash_id {crash_id}")
                print(crashes[crash_id])
                run_repro(crash_id)

def call_syzrepro(log_file,crash_id):
    global CRASHDIR
    repro_cmd = ['/shellphish/syzkaller/bin/syz-repro','-config','/shellphish/syzkaller/syzconfig-repro.cfg','-crepro',f'{CRASHDIR}/{crash_id}.c','-output',f'{CRASHDIR}/{crash_id}.repro',log_file]
    subprocess.run(repro_cmd)
    #print("----------------------Finished Running------------------------")

def run_repro(crash_id):
    global crashes
    idx = 0
    if crashes[crash_id]['last_tried'] == None:
        crashes[crash_id]['last_tried'] = 0
    else:
        idx = crashes[crash_id]['last_tried']
        if not len(crashes[crash_id]['log']) > (crashes[crash_id]['last_tried']):
            return
    crashes[crash_id]['being_repro'] = True
    for log_file in crashes[crash_id]['log'][idx:]:
        print(f"Reproducing crash {crash_id} with log_file as {log_file}")
        call_syzrepro(log_file,crash_id)
        crashes[crash_id]['last_tried'] += 1
        if crashes[crash_id]['reproduced']:
            return
    crashes[crash_id]['being_repro'] = False

class MyHandler(FileSystemEventHandler):
    global crashes, out_file
    def on_any_event(self, event):
        print(f"Event type: {event.event_type}  path : {event.src_path}")
        if event.event_type == 'created' and event.is_directory == True:
            #print(f"New directory was created: {event.src_path}")
            crashid = event.src_path.split("/")[-1]
            crashes[crashid] = {
                'description' : None,
                'log': [],
                'report': None,
                'last_tried': None,
                'being_repro': False,
                'reproduced': False,
                'repro_syz': None,
                'repro_c': None
            }
        elif event.event_type == 'created' and event.is_directory == False:
            crashid = event.src_path.split("/")[-2]
            if "report" in event.src_path:
                crashes[crashid]["report"] = event.src_path
                #print(f"New report was created inside the directory: {event.src_path}")
            elif "log" in event.src_path:
                crashes[crashid]["log"].append(event.src_path)
                crashes[crashid]["log"] = list(set(crashes[crashid]["log"]))
                #print(f"New log file was created inside the directory: {event.src_path}")
            elif "description" in event.src_path:
                crashes[crashid]["description"] = event.src_path
            elif ".repro" in event.src_path:
                repro_file = event.src_path.split('/')[-1]
                crashid = repro_file.split('.repro')[0]
                crashes[crashid]['repro_syz'] = event.src_path
                crashes[crashid]['reproduced'] = True
                # copy the repro file to the outdir in crash_id/crash_id.repro
                print(f'Copying {event.src_path} to {SYZLANG_REPRODUCER_OUT_PATH}')
                shutil.copy(event.src_path, SYZLANG_REPRODUCER_OUT_PATH)
            elif ".c" in event.src_path:
                repro_file = event.src_path.split('/')[-1]
                crashid = repro_file.split('.c')[0]
                crashes[crashid]['repro_c'] = event.src_path
                crashes[crashid]['reproduced'] = True
                # copy the repro file to the outdir in crash_id/crash_id.c
                print(f'Copying {event.src_path} to {C_REPRODUCER_OUT_PATH}')
                shutil.copy(event.src_path, C_REPRODUCER_OUT_PATH)

            print(f"{crashes[crashid]=}")

def monitor(crashpath):
    global CRASHDIR
    CRASHDIR = crashpath
    observer = Observer()
    observer.schedule(MyHandler(), path=crashpath, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(10)
            write_file()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    #crashpath = os.environ.get('CRASH_DIR')
    debug = os.environ.get('DEBUG')
    crashpath = os.environ.get('CRASH_DIR')
    C_REPRODUCER_OUT_PATH = os.environ.get('C_REPRODUCER_OUT_PATH')
    SYZLANG_REPRODUCER_OUT_PATH = os.environ.get('SYZLANG_REPRODUCER_OUT_PATH')
    if crashpath == None:
        exit("Failed to get CRASH_DIR environment variable")
    if debug:
        DEBUG = True
        crashpath = '/crashes'
        if os.path.exists(crashpath):
            shutil.rmtree(crashpath)
        os.mkdir(crashpath)
    monitor(crashpath)