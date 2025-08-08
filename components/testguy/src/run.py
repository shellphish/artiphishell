import argparse
import os
import yaml
import logging

from pathlib import Path
from rich import print

from testguy.main import TestGuy
from shellphish_crs_utils.models.testguy import TestGuyMetaData

def main():
    argparser = argparse.ArgumentParser(description='TestGuy')

    argparser.add_argument('--project_id', type=str, required=True)
    argparser.add_argument('--project_path', type=Path, help='Path to the project', required=True)
    argparser.add_argument('--project_metadata_path', type=Path, help='Path to the project metadata file', required=True)
    argparser.add_argument('--compile_cmd_path', type=Path, help='Path to the compile command file', required=True, default=None)
    argparser.add_argument('--output_path', type=Path, help='Path to the output directory', required=True)
    argparser.add_argument('--local_run', required=False, type=int, default=False)
    
    args = argparser.parse_args()
    args = {
        'project_id': args.project_id,
        'project_path': args.project_path,
        'project_metadata_path': args.project_metadata_path,
        'compile_cmd_path': args.compile_cmd_path,
        'output_path': args.output_path,
        'local_run': args.local_run,
    }

    result = TestGuyMetaData()
    try:
        assert(args['local_run'] == 0 or args['local_run'] == 1)

        if args['local_run'] == 1:
            # export TASK_SERVICE=1 and LOCAL_RUN=1
            os.environ['TASK_SERVICE'] = 'False'
            os.environ['LOCAL_RUN'] = 'True'
        else:
            os.environ['TASK_SERVICE'] = 'True'
            os.environ['LOCAL_RUN'] = 'False'

        print(f"🏁 Starting TestGuy with the following arguments: {args}")
        
        testguy = TestGuy(**args)
        result = testguy.start()
        if result.test_available:
            print(f"🎉 {result.num_tests_passed} tests passed!")
        else:
            print("❌ TestGuy could not find any tests to run.")
    # Catch all possible exceptions
    except Exception as e:
        logging.error(f"🤡 Error: {e}")
    # Save the test result to a output file
    finally:
        with open(args['output_path'], 'w') as f:
            yaml.safe_dump(result.model_dump(), f)
        logging.info(f"🔖 TestGuy report saved at {args['output_path']}")

if __name__ == "__main__":
    main()
