import argparse
import os
import asyncio
import json
import yaml
from pprint import pprint
from libcodeql.client import CodeQLClient, ServerException
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver, FunctionResolver
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
import random


def write_to_txt_file(file_path, data):
    # Dump the list of packages in scope to the output file
    with open(file_path, 'w') as f:
        for d in data:
            f.write(f'{d}\n')

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run multiple CodeQL queries dynamically with full configuration from args."
    )
    parser.add_argument("--cp-name", required=True, help="The CodeQL project name.")
    parser.add_argument("--project-id", required=True, help="The project identifier.")
    parser.add_argument("--run-codeql",  action='store_true', help="Run CodeQL")
    parser.add_argument("--project-metadata", required=True, help="Path to the project metadata YAML file.")

    # Allow --query to be repeated; each should be in the format "template:custom_key"
    parser.add_argument(
        "--query",
        action="append",
        help=(
            "Query definition in the format 'template:custom_key'.\n"
            "For example: 'info-extraction-java/java-string-literals.ql.j2:strings'\n"
            "If no custom_key is provided (i.e. no colon), the template name is used as the key."
        )
    )

    parser.add_argument(
        "--output",
        default="in_scope_classes_path.json",
        help="Path to the output JSON file where results will be saved."
    )

    return parser.parse_args()

def parse_query_arg(query_arg):
    """
    Parse the query argument which is expected in the format:
    "query_template:custom_key"
    If no colon is found, the custom_key defaults to the query_template.
    """
    parts = query_arg.split(":", 1)
    template = parts[0].strip()
    key = parts[1].strip() if len(parts) > 1 else template
    return template, key

def call_function_resolver(cp_name, project_id, project_metadata):

    with open(project_metadata) as f:
        augmented_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
    focus_repo_path = augmented_metadata.source_repo_path
    target_functions, source_func_keys,  all_packages = [], [], []
    # function_resolver = LocalFunctionResolver("full_function_index", "json_dir")
    function_resolver = RemoteFunctionResolver(cp_name=cp_name, project_id=project_id)
    source_func_keys = function_resolver.get_focus_repo_keys(focus_repo_path)
    values_for_all_functions = function_resolver.get_many(source_func_keys)
    print(f"Total source repo functions: {len(source_func_keys)}")

    for key, func_value in values_for_all_functions.items():
        package_name = func_value.package
        if package_name:
            if '<' in package_name:
                continue
            all_packages.append(package_name)
        funcname = func_value.funcname
        if funcname:
            target_functions.append(funcname)
    print(f"Total target functions: {len(target_functions)}")
    return target_functions, list(set(all_packages))

async def run_codeql_queries(query_args, target_functions, cp_name, project_id):
    try:
        results, tasks = {}, {}
        #client = CodeQLClient()
        client = CodeQLClient()
        # Process each provided --query argument.

        for query_arg in query_args:
            # we dont want reachable classes query to be run in full mode

            template, key = parse_query_arg(query_arg)
            print(f"{template} with {len(target_functions)} functions")
            TASK_TYPE_FOR_CODEQL_QUERY = os.environ.get("TASK_TYPE_FOR_CODEQL_QUERY")
            if TASK_TYPE_FOR_CODEQL_QUERY == 'full' and key.startswith("java_reaching_classes"):
                print(f"Skipping {template} for full mode")
                continue
            if key == "java_reaching_classes":
                if len(target_functions) > 50:
                    if len(target_functions) > 500:
                        target_functions = random.sample(target_functions, 500)
                    remaining_functions = target_functions.copy()
                    batch_count = 0
                    while remaining_functions:
                        # Take the next batch of 50 functions
                        current_batch = remaining_functions[:50]
                        remaining_functions = remaining_functions[50:]
                        batch_count += 1

                        # Create task with numbered key
                        batch_key = f"{key}_{batch_count}"
                        print(f"Sending batch {batch_count} with {len(current_batch)} functions, {len(remaining_functions)} remaining")

                        tasks[batch_key] = asyncio.create_task(
                            client.query({
                                "cp_name": cp_name,
                                "project_id": project_id,
                                "query_tmpl": template,
                                "query_params": {"target_functions": current_batch}
                            })
                        )
            else:
                tasks[key] = asyncio.create_task(
                client.query({
                    "cp_name": cp_name,
                    "project_id": project_id,
                    "query_tmpl": template,
                    "query_params": {"target_functions": target_functions}
                })
                )

        # Await all tasks and collect their results.
        results = { key: await task for key, task in tasks.items() }
        pprint(results)

    except ServerException as e:
        print(f"CodeQL Server error: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")
    return results

def main():
    args = parse_args()
    cp_name = args.cp_name
    project_id = args.project_id
    project_metadata = args.project_metadata
    run_codeql = args.run_codeql
    output = args.output
    

    # always dump some strings
    final_dict_strings = ["jaz.Zer", "jaz.Ter", "jazze", "jazzer", "jazzer-traversal", "JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME", "jazzer.example.com", 
                     "JAZZER_SSR", "JAZZER_FILE_READ_WRITE", "JAZZER_COMMAND_INJECTION", "fuzz"]
    all_classes_from_reachability_report, in_scope_packages_from_antlr = '', ''
    # function resolver
    try:
        target_functions, packages = call_function_resolver(cp_name, project_id, project_metadata)
        print(f"Total target functions: {len(target_functions)} packages: {len(packages)}")
        # codeql
        if run_codeql:
            query_args = args.query
            if not query_args:
                print("No query provided. Please provide a query using --query.")
                return
            print("Running CodeQL queries...")
            results = asyncio.run(run_codeql_queries(query_args, target_functions, cp_name, project_id))
            if not results:
                print("No results returned from CodeQL queries.")
                return

            dict_strings, class_names = set(), set()
            for key, value in results.items():
                if key == "interesting_strings":
                    for item in value:
                        if item['col0'].strip() and item['col0'].strip() not in ["\\", "'", ":", ".", "_"]:
                            # dict_strings.add(item['col0'])
                            string_value = item['col0'].strip()
                            hex_content = "".join(f"\\x{byte:02x}" for byte in string_value.encode("utf-8"))
                            final_dict_strings.append(f'"{hex_content}"')
                    final_dict_strings = list(set(final_dict_strings))

                elif key.startswith("java_reaching_classes"):
                    for item in value:
                        if item['col0']:
                            class_name = item['col0'].strip().split('.')[:-1]
                            # April 1st hack. TODO: see if this is really needed or not
                            class_name = '.'.join(class_name)
                            if class_name.startswith("<"):
                                continue
                            class_names.add(class_name)

                    all_classes_from_reachability_report = chr(34) + ':'.join([f"{item}.**" for item in class_names]) + chr(34)

        # write_to_txt_file('/shellphish/dict.txt', final_dict_strings)
        write_to_txt_file('dict.txt', final_dict_strings)
        in_scope_packages_from_antlr = chr(34) + ':'.join([f"{item}.**" for item in packages]) + chr(34)
        absolutely_final_dict = {
            "in_scope_packages_from_antlr": in_scope_packages_from_antlr,
            "all_classes_from_reachability_report": all_classes_from_reachability_report,
        }

        # Save results to the specified JSON file.
        with open(output, "w") as f:
            json.dump(absolutely_final_dict, f, indent=4)
        print(f"Results saved to {output}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()


