import subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

IDS = ['35704eccb16acae568d71f11b8b35b5c', '5f57bb2a1c6184e4871fd736c346bde5', 'e54a500652c546b2526a5b0c7dc08d51']
NUM_WORKERS = 3

def run_experiment(id):
    print(f"Running experiment for ID: {id}")
    command = ['./run-patcherq-from-patchery-backup.sh', '/aixcc-backups/backup-nginx-15661266298/', id]
    log_file = f"{sys.argv[1]}/{id}.log"

    try:
        with open(log_file, 'w') as f:
            _ = subprocess.run(command, check=True, stdout=f, stderr=subprocess.STDOUT)
        print(f"Experiment for ID {id} completed successfully. Output saved to {log_file}")
    except subprocess.CalledProcessError:
        print(f"An error occurred while running the experiment for ID {id}. Check {log_file} for details.")
    except Exception as e:
        print(f"An unexpected error occurred for ID {id}: {e}")

# Run experiments in parallel
with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
    futures = [executor.submit(run_experiment, id) for id in IDS]

    # Optionally wait for them to complete and catch exceptions
    for future in as_completed(futures):
        future.result()  # Will raise exception if any occurred inside `run_experiment`
