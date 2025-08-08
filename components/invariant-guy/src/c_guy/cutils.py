import os

################################################################
# Container configuration for invariant-guy
################################################################

NPROC_VAL = int(os.getenv('NPROC_VAL', 1))

MAX_NUM_BENIGN_INPUTS = 50


CRASH_SEED_DIR    =  "/crashing_inputs"
BENIGN_SEED_DIR   =  "/benign_inputs"
CRASH_TRACES_DIR  =  "/crash_traces_dir"
BENIGN_TRACES_DIR =  "/benign_traces_dir"

perf = "/shellphish/linux/tools/perf/perf"

################################################################
# Everything else
################################################################

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