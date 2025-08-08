
import logging
import argparse
import yaml

from discoveryguy.config import Config


logger = logging.getLogger("discoveryguy.split_func_ranking")
logger.setLevel(logging.INFO)

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="DiscoveryGuy Split Function Ranking Script")
    argparser.add_argument("--func_ranking", required=True, help="The code swipe report")
    argparser.add_argument("--proc_id", type=int, default=1, help="the process id")
    argparser.add_argument("--num_proc", type=int, default=1, help="Number of processes to use for discoveryguy")
    argparser.add_argument("--output", required=True, help="The output file to write the split function ranking")

    args = argparser.parse_args()

    with open(args.func_ranking, "r") as file:
        func_ranking = yaml.safe_load(file)

    num_proc = args.num_proc
    output_file = args.output
    proc_id = args.proc_id

    func_ranking = func_ranking["ranking"]
    # Reduce to the max POIs to check
    funcs_to_check = func_ranking[:Config.max_pois_to_check]

    proc_id_to_chunk = {}
    for i in range(1, num_proc+1):
        start_index = (i-1)
        proc_id_to_chunk[i]  = funcs_to_check[start_index::num_proc]

    f = 0
    for k,v in proc_id_to_chunk.items():
        print(f"Process {k} will handle {len(v)} functions")
        f += len(v)

    print(f"Total functions to check: {f}")
    assert f == len(funcs_to_check), "The total number of functions to check does not match the original list"

    print(f"Writing the split function ranking to the output file at {output_file} for process {proc_id}")
    with open(output_file, "w") as file:
        yaml.dump({"ranking": proc_id_to_chunk[proc_id]}, file)
