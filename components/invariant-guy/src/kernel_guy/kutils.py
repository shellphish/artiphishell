import os

################################################################
# Container configuration for invariant-guy
################################################################

NPROC_VAL = int(os.getenv('NPROC_VAL', 1))

# Environment for kernel tracing 🏠
CRASH_SEED_DIR    =  "/crashing_inputs"
BENIGN_SEED_DIR   =  "/benign_inputs"
CRASH_TRACES_DIR  =  "/crash_traces_dir"
BENIGN_TRACES_DIR =  "/benign_traces_dir"

# Wether we want to test the benign inputs or not before tracing
# i.e., do they panick the kernel?
TEST_BENIGN_SEEDS = False

# We want to make sure the crashing seed triggers a KASAN and does not
# just hang the kernel.
TEST_CRASHING_SEED = True

# Limit the amount of benign inputs we want to trace
MAX_NUM_BENIGN_INPUTS = 50

# The amount of RAM we want to give to the VM spawned with virtme
# to execute the target kernel
VIRTME_MEM = "4G"
# The amount of CPUs we want to give to the VM spawned with virtme
# to execute the target kernel
VIRTME_CPUS = "1"

MAX_ATTEMPTS_CRASHING_POC_RUNS = 2

# These tracepoints will be filtered out (we are matching with startswith)
FILTERED_TRACEPOINTS_PREFIX = [
                               "_",
                               "get_stack_info",
                               "orc_find",
                               "kasan",
                               "probe:handle_mm_fault",
                               "switch_fpu_return",
                               "dump_stack",
                               "report"
                               ]

# This controls how many benign inputs we want to trace with perf
# before rebooting the qemu VM.
# -1 = inf.
# 👀 NOTE: the probes persist a reboot.

REBOOTS_VM_AFTER_TRACING_N_INPUTS = -1

################################################################

################################################################
# Everything else
################################################################

def random_string(length=10):
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # Background colors:
    GREYBG = '\033[100m'
    REDBG = '\033[101m'
    GREENBG = '\033[102m'
    YELLOWBG = '\033[103m'
    BLUEBG = '\033[104m'
    PINKBG = '\033[105m'
    CYANBG = '\033[106m'

# define the custom exception
class KamikazeException(Exception):
    pass