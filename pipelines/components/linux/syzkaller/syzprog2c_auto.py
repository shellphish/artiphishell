
import argparse
import os
import time
import sys
import subprocess
import multiprocessing
import functools
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


########################################################################################################
# CONFIG 📝
########################################################################################################

SYZKALLER_HOME  = "/shellphish/syzkaller/"

# This folder is populated by syzkaller whenever there is a new benign syzprog
NEW_BENIGN_SYZPROGS_DIR  = f"{SYZKALLER_HOME}benign_syzprogs_new/"

SYZ_PROG2C_TOOL = f"{SYZKALLER_HOME}tools/syz-prog2c/prog2c.go"
SYZPROG_TO_C  = f"cd {SYZKALLER_HOME} && go run {SYZ_PROG2C_TOOL} -prog <SYZPROGNAME> --build" # e.g.,: go run tools/syz-prog2c/prog2c.go --prog a10ea19597d19717a01199f573198be27f9004ad

# How many benign syzprogs to pop at once
POP_N_PER_WORKER = 5

# How often we should check the folder size of the new syzprogs (seconds)
WAIT_FOR        = 30

########################################################################################################

# Convert a syzprog to a C program using syzkaller utility.
def syzprog2c(output_syzprogs, output_cprogs, syzprog_path):

    #print(f" 🔄 Converting {syzprog_path} to C")

    syzprog_name = os.path.basename(syzprog_path)
    
    # Move the syzprog to the all_benign_syzprogs folder
    os.system(f"mv {syzprog_path} {output_syzprogs}")

    # The new path of the syzprog is the output_syzprogs folder
    syzprog_path = f'{output_syzprogs}/{syzprog_name}'

    # Customize the command
    cmd = SYZPROG_TO_C.replace("<SYZPROGNAME>", syzprog_path)

    comm = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = comm.stdout
    logs = comm.stderr

    try:
        if "binary build OK" in logs:
            with open(f"{output_cprogs}/{syzprog_name}.c", "w") as f:
                f.write(result)
            print(f' ✅ {syzprog_name} converted to C')

    except Exception as e:
        print(f" ❌ Error converting {syzprog_name} to C: {e}")


class NewFileHandler(FileSystemEventHandler):
    def __init__(self, file_list, max_active):
        self.file_list = file_list
        self.max_active = max_active

    def on_created(self, event):
        if not event.is_directory:
            #print("🐣 New file %s detected" % event.src_path)
            # Add the new file path to the beginning of the list
            if len(self.file_list) < self.max_active:
                self.file_list.insert(0, event.src_path)
            else:
                # remove the last element
                self.file_list.pop()
                # insert the new element at the beginning
                self.file_list.insert(0, event.src_path)

def monitor_folder(directory, file_list, max_active):
    print(f"👀 Monitoring {directory} for new files (max_active: {max_active})")
    event_handler = NewFileHandler(file_list, max_active)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

'''
  _________                                               _________________                          __          
 /   _____/__.__._____________________  ____   ____  _____\_____  \_   ___ \          _____   __ ___/  |_  ____  
 \_____  <   |  |\___   /\____ \_  __ \/  _ \ / ___\/  ___//  ____/    \  \/   ______ \__  \ |  |  \   __\/  _ \ 
 /        \___  | /    / |  |_> >  | \(  <_> ) /_/  >___ \/       \     \____ /_____/  / __ \|  |  /|  | (  <_> )
/_______  / ____|/_____ \|   __/|__|   \____/\___  /____  >_______ \______  /         (____  /____/ |__|  \____/ 
        \/\/           \/|__|               /_____/     \/        \/      \/               \/                    

        [1] This script will monitor the folder where syzkaller stores the new benign syzprogs (thanks to our patch).
            Once at least MIN_NEW_BENIGNS are found, the script will move them to the all_benign_syzprogs folder and 
            start to convert them to C programs using the syz-prog2c utility.
            NOTE: The conversion is done in parallel using `num_workers` workers.
            NOTE: This script requires the patch fetch_benign_syzprogs.diff to be applied to syzkaller.
'''
def main():

    argparser = argparse.ArgumentParser(description='Convert new benign syzprogs to C programs')
    argparser.add_argument('--output-syzprogs', type=str, help='Folder where we store all the new benign syzprogs')
    argparser.add_argument('--output-cprogs', type=str, help='Folder where the C programs will be stored')
    argparser.add_argument('--max-active', type=int, help='Max number of active syzprogs to convert to C', default=float('inf'))
    argparser.add_argument('--num-workers', type=int, help='How many workers to employ to convert syzprogs to c', default=5)

    args = argparser.parse_args()

    output_syzprogs = args.output_syzprogs
    output_cprogs = args.output_cprogs
    max_active = args.max_active
    num_workers = args.num_workers

    NEW_SYZPROGS = []
    # Monitor the folder and insert the new syzprogs in the list
    # the new syzprogs are appended in front (so we have latest first)
    monitor_thread = threading.Thread(target=monitor_folder, args=(NEW_BENIGN_SYZPROGS_DIR, NEW_SYZPROGS, max_active))
    monitor_thread.daemon = True  # Daemonize thread to ensure it exits when the main thread does
    monitor_thread.start()

    try:
        while True:
            if len(NEW_SYZPROGS) > 0:
                # Get an element from the list
                print(f"👀 Current new syzprogs: {len(NEW_SYZPROGS)}")

                # always pop the N first elements of the list
                # i.e., the N most recents syzprogs syzkaller put in the NEW_BENIGN_SYZPROGS_DIR folder
                syzprogs_to_process = []
                for _ in range(0, min(POP_N_PER_WORKER * num_workers , len(NEW_SYZPROGS))):
                    syzprogs_to_process.append(NEW_SYZPROGS.pop(0))
                
                # Start the conversion!
                with multiprocessing.Pool(num_workers) as pool:
                    pool.map(functools.partial(syzprog2c, output_syzprogs, output_cprogs), syzprogs_to_process)

            else:
                # If there are any leftover syzprogs in the folder, add them to the list!
                # This can happen if we reacheed the max_active limit earlier and now we are waiting for new syzprogs
                syzprogs_leftover = os.listdir(NEW_BENIGN_SYZPROGS_DIR)
                
                if len(syzprogs_leftover) > 0:
                    syzprogs_leftover_paths = [f"{NEW_BENIGN_SYZPROGS_DIR}/{syzprog}" for syzprog in syzprogs_leftover]
                    if max_active != float('inf'):
                        syzprogs_leftover_paths = syzprogs_leftover_paths[:max_active]
                    NEW_SYZPROGS.extend(syzprogs_leftover_paths)
                else:
                    print(f'😴 No new syzprogs found. Waiting for {WAIT_FOR} seconds...')
                    time.sleep(WAIT_FOR)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
