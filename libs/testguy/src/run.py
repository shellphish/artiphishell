import argparse
from rich import print

from shellphish_crs_utils.models.testguy import TestGuyLibMetaData
from testguy.lib import TestGuy

def main():
    parser = argparse.ArgumentParser(description="TestGuy")
    parser.add_argument("--project_path", type=str, required=True, help="The target root directory.")
    parser.add_argument("--testguy_report_path", type=str, required=True, help="The testguy report.")
    parser.add_argument("--use_task_service", type=bool, default=False, help="Use the task service.")
    args = parser.parse_args()

    args = {
        "project_path": args.project_path,
        "testguy_report_path": args.testguy_report_path,
        "use_task_service": args.use_task_service
    }
    print(f"🏁 Starting TestGuy Lib with args = {args}")

    testguy = TestGuy(**args)
    result: TestGuyLibMetaData = testguy.test()

    if result.is_valid_patch:
        print("🎉 Patch is valid!")
    else:
        print("🤡 Patch is invalid!")

if __name__ == "__main__":
    main()