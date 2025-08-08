# Generated data sample
# {
#     "CWE_ID": [
#       "CWE-121"
#     ],
#     "code": "\n\n\n#include \"std_testcase.h\"\n\n\nstatic const int STATIC_CONST_TRUE = 1; \nstatic const int STATIC_CONST_FALSE = 0; \n\n\n\n\nstatic void f_qvdcopbb()\n{\n    int data;\n    \n    data = -1;\n    if(STATIC_CONST_TRUE)\n    {\n        \n        data = 10;\n    }\n    if(STATIC_CONST_FALSE)\n    {\n        \n        printLine(\"Benign, fixed string\");\n    }\n    else\n    {\n        {\n            int i;\n            int buffer[10] = { 0 };\n            \n            if (data >= 0 && data < (10))\n            {\n                buffer[data] = 1;\n                \n                for(i = 0; i < 10; i++)\n                {\n                    printIntLine(buffer[i]);\n                }\n            }\n            else\n            {\n                printLine(\"ERROR: Array index is out-of-bounds\");\n            }\n        }\n    }\n}\n\n\nstatic void f_oyihqlxn()\n{\n    int data;\n    \n    data = -1;\n    if(STATIC_CONST_TRUE)\n    {\n        \n        data = 10;\n    }\n    if(STATIC_CONST_TRUE)\n    {\n        {\n            int i;\n            int buffer[10] = { 0 };\n            \n            if (data >= 0 && data < (10))\n            {\n                buffer[data] = 1;\n                \n                for(i = 0; i < 10; i++)\n                {\n                    printIntLine(buffer[i]);\n                }\n            }\n            else\n            {\n                printLine(\"ERROR: Array index is out-of-bounds\");\n            }\n        }\n    }\n}\n\n\nstatic void f_bvmbnvmw()\n{\n    int data;\n    \n    data = -1;\n    if(STATIC_CONST_FALSE)\n    {\n        \n        printLine(\"Benign, fixed string\");\n    }\n    else\n    {\n        \n        data = 7;\n    }\n    if(STATIC_CONST_TRUE)\n    {\n        {\n            int i;\n            int buffer[10] = { 0 };\n            \n            if (data >= 0)\n            {\n                buffer[data] = 1;\n                \n                for(i = 0; i < 10; i++)\n                {\n                    printIntLine(buffer[i]);\n                }\n            }\n            else\n            {\n                printLine(\"ERROR: Array index is negative.\");\n            }\n        }\n    }\n}\n\n\nstatic void f_hzoxoqnj()\n{\n    int data;\n    \n    data = -1;\n    if(STATIC_CONST_TRUE)\n    {\n        \n        data = 7;\n    }\n    if(STATIC_CONST_TRUE)\n    {\n        {\n            int i;\n            int buffer[10] = { 0 };\n            \n            if (data >= 0)\n            {\n                buffer[data] = 1;\n                \n                for(i = 0; i < 10; i++)\n                {\n                    printIntLine(buffer[i]);\n                }\n            }\n            else\n            {\n                printLine(\"ERROR: Array index is negative.\");\n            }\n        }\n    }\n}\n\nvoid f_zrtbzday()\n{\n    f_qvdcopbb();\n    f_oyihqlxn();\n    f_bvmbnvmw();\n    f_hzoxoqnj();\n}\n\n\n\n\n\nint main(int argc, char * argv[])\n{\n    \n    srand( (unsigned)time(NULL) );\n\n    f_zrtbzday();\n\n    return 0;\n}\n\n",
#     "target": 0,
#     "language": "c",
#     "dataset": "juliet 1.3",
#     "idx": 400460,
#     "original_file": "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_large_04.c",
#     "RELATED_CWE": [
#       "CWE-122",
#       "CWE-415",
#       "CWE-416"
#     ]
#   }

# ground truth vulnerabilities info sample
# {
#     "CWE_ID": ["CWE-125"],
#     "function_name": "zlibVersion",
#     "file_name": "/src/assimp/contrib/zlib/zutil.c",
# }
import os
import json
import argparse
from collections import defaultdict

CWE_IN_SCOPE_SEMI = {"c": ["CWE-125", "CWE-787", "CWE-119", "CWE-416", "CWE-415", "CWE-476", "CWE-190"],
                    "java": ["CWE-22", "CWE-77", "CWE-78", "CWE-94", "CWE-190", "CWE-434", "CWE-502", "CWE-918"]}
seen_hashes = set()

def construct_data(args):
    """
    Constructs the dataset by reading from the specified clang indices folder.
    
    Args:
        args: Command line arguments containing the path to the clang indices folder.
    """
    # Assuming construct_data is a function that processes the clang indices
    # and constructs the dataset. The implementation details are not provided.
    all_data = []
    idx = 0
    if args.vulns_json:
        with open(args.vulns_json, 'r') as f:
            vulns = json.load(f)
    elif args.vuln_func_list:
        with open(args.vuln_func_list, 'r') as f:
            vulns = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) == 3:
                    vuln = {
                        "CWE_ID": [parts[0]],
                        "function_name": parts[1],
                        "file_name": parts[2]
                    }
                elif len(parts) == 2:
                    vuln = {
                        "CWE_ID": ["CWE-125"],
                        "function_name": parts[0],
                        "file_name": parts[1]
                    }
                elif len(parts) == 1:
                    vuln = {
                        "CWE_ID": ["CWE-125"],
                        "function_name": parts[0],
                        "file_name": ""
                    }
                vulns.append(vuln)
    else:
        print("No vulnerabilities information provided.")
        return
    for folder in ["FUNCTION", "MACRO", "METHOD"]:
        folder_path = os.path.join(args.clang_indices, folder)
        if os.path.exists(folder_path):
            print(f"Processing folder: {folder_path}")
            for file_name in os.listdir(folder_path):
                if not file_name.endswith(".json"):
                    continue
                file_path = os.path.join(folder_path, file_name)
                if os.path.isfile(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if data.get("hash") in seen_hashes:
                            continue
                        seen_hashes.add(data.get("hash"))
                        # if len(data["code"]) > 20000:
                        #     print(f"Code snippet too long: {file_name}")
                        #     continue
                single_sample = {}
                single_sample["CWE_ID"] = ["CWE-125"]
                single_sample["target"] = 0
                for vuln in vulns:
                    if ( (os.path.basename(vuln["file_name"]) == data["filename"]) and (data["funcname"].endswith(vuln["function_name"])) ) or (not vuln["file_name"] and vuln["function_name"] == data["funcname"]):
                        single_sample["CWE_ID"] = vuln["CWE_ID"]
                        single_sample["target"] = 1
                        break
                single_sample["RELATED_CWE"] = [i for i in CWE_IN_SCOPE_SEMI[args.language] if i not in single_sample["CWE_ID"]]
                single_sample["language"] = args.language
                single_sample["dataset"] = "aixcc"
                single_sample["idx"] = idx
                idx += 1
                single_sample["original_file"] = file_name
                single_sample["code"] = data["code"]
                all_data.append(single_sample)
        else:
            print(f"Folder not found: {folder_path}")
    with open("aixcc_dataset.json", "w") as f:
        json.dump(all_data, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument(
        "--clang_indices",
        type=str,
        required=True,
        help="The path to the clang indices folder, which contains three folders: FUNCTION, MACRO, and METHOD."
    )
    parser.add_argument(
        "--vulns_json",
        type=str,
        required=False,
        help="The path to the JSON file containing ground truth vulnerabilities info"
    )
    parser.add_argument(
        "--language",
        type=str,
        choices=["c", "java"],
        default="c",
        help="The programming language of the code snippets."
    )
    parser.add_argument(
        "--vuln_func_list",
        type=str,
        required=False,
        help="The path to the file containing the list of vulnerable functions."
    )
    args = parser.parse_args()
    assert not (args.vuln_func_list and args.vulns_json), "Please provide either a list of vulnerable functions or a JSON file with ground truth vulnerabilities info."
    construct_data(args)
#python construct_dataset.py --vuln_func_list data/nginx_vuln_functions --clang_indices /aixcc-backups/backup-nginx-14763518498/clang_index.output_dir/bddc024547da41c889933f396a9c05d3