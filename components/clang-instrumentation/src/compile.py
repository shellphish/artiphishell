import argparse
import pathlib

from griller.config import initialize_client_config
from griller.config.job import JobConfig
from griller.passes import DriverGeneratorPass
from griller.runtime import GrillerRuntime
from griller.common import logger
from griller.utils import file_utils

log = logger.get_logger("client")

def generate_harness(job: JobConfig):
    """
    Generate the harness using the DriverGeneratorPass.
    """
    log.info(f"Generating harness for function: {job.function}")
    # Create the pass
    driver_pass = DriverGeneratorPass(job)

    # Run the pass
    harnessed_bitcode = job.CWD / f"{job.function}_harness.bc"
    driver_pass.run(
        targetfunc=job.function,
        input_file=job.bitcode,
        output_file=harnessed_bitcode,
        options="--debug-mode",
    )

    log.info(f"Harness generated at {harnessed_bitcode}.. Now linking with runtime")
    # Link the harness with the runtime

    runtime = GrillerRuntime(job)
    # Check if the runtime is built
    final_bitcode = job.output / f"harnessed.bc"
    runtime.link(
        input_file=harnessed_bitcode,
        output_file=final_bitcode,
        runtime="normal_runtime.bc",
    )
    log.info(f"Final harnessed bitcode generated at {final_bitcode}")
    
    grammar_file = job.output / f"type.log"
    # Copy the grammar file to the output directory
    file_utils.copy_file(job.CWD / "type.log", grammar_file)
    

def get_args():
    parser = argparse.ArgumentParser(description="Griller Function Harness")
    parser.add_argument(
        "--function", type=str, required=True, help="Function to harness"
    )
    parser.add_argument(
        "--bitcode", type=pathlib.Path, required=True, help="Bitcode file to harness"
    )
    parser.add_argument("--json", type=pathlib.Path, help="3C JSON file")
    parser.add_argument(
        "--output", type=pathlib.Path, required=True, help="Output file"
    )
    return parser.parse_args()


def startup():
    args = get_args()
    return JobConfig(args)


if __name__ == "__main__":
    logger.set_global_log_level("DEBUG")
    initialize_client_config(pathlib.Path(__file__).parent / "griller.config")
    # Start the client
    job = startup()
    # Generate the harness
    generate_harness(job)
