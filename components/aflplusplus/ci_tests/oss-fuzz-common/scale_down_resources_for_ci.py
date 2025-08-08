import yaml
import os

with open('../../pipeline.yaml', 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

# Retrieve number of available CPUs
NUM_CPUS_AVAILABLE = os.cpu_count()
data['tasks']['aflpp_fuzz']['job_quota']['mem'] = '1Gi'
data['tasks']['aflpp_fuzz']['job_quota']['cpu'] = str(NUM_CPUS_AVAILABLE / 12)
data['tasks']['aflpp_fuzz_merge']['job_quota']['mem'] = '1Gi'
data['tasks']['aflpp_fuzz_merge']['job_quota']['cpu'] = str(NUM_CPUS_AVAILABLE / 12)
data['tasks']['aflpp_fuzz_main_replicant']['job_quota']['mem'] = '1Gi'
data['tasks']['aflpp_fuzz_main_replicant']['job_quota']['cpu'] = str(NUM_CPUS_AVAILABLE / 12)

with open('../../pipeline.yaml', 'w', encoding='utf-8') as f:
    yaml.dump(data, f)