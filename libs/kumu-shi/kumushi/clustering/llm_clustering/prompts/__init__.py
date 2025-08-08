from pathlib import Path

PROMPTS_DIR = Path(__file__).parent

# prompts
CLUSTER_SYS_PROMPT = PROMPTS_DIR / "cluster.system.j2"
CLUSTER_USR_PROMPT = PROMPTS_DIR / "cluster.j2"
ROOT_CAUSE_OUTPUT = str(PROMPTS_DIR / "cluster.output.txt")
