import logging
import os
import shutil
import subprocess
import tempfile
import yaml

from libcodeql.client import CodeQLClient
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata, LanguageEnum

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("coverageguy")

# Load environment variables
ARTIPHISHELL_PROJECT_NAME = os.environ.get("ARTIPHISHELL_PROJECT_NAME")
ARTIPHISHELL_PROJECT_ID = os.environ.get("ARTIPHISHELL_PROJECT_ID")
PROJECT_METADATA_PATH = os.environ.get("PROJECT_METADATA_PATH")
OUTPUT_DICTIONARIES_PATH = os.environ.get("OUTPUT_DICTIONARIES_PATH")
ARTIPHISHELL_FUZZER_SYNC_DICTS = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_DICTS")
CORPUSGUY_SYNC_TO_FUZZER = os.environ.get("CORPUSGUY_SYNC_TO_FUZZER")

log.info(f"ARTIPHISHELL_PROJECT_NAME: {ARTIPHISHELL_PROJECT_NAME}")
log.info(f"ARTIPHISHELL_PROJECT_ID: {ARTIPHISHELL_PROJECT_ID}")
log.info(f"PROJECT_METADATA_PATH: {PROJECT_METADATA_PATH}")
log.info(f"OUTPUT_DICTIONARIES_PATH: {OUTPUT_DICTIONARIES_PATH}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_DICTS: {ARTIPHISHELL_FUZZER_SYNC_DICTS}")
log.info(f"CORPUSGUY_SYNC_TO_FUZZER: {CORPUSGUY_SYNC_TO_FUZZER}")


def run_codeql_query(project_name, project_id, query_path) -> list[dict]:
    client = CodeQLClient()
    with open(query_path, "r") as f:
        query = f.read()
    result = client.query({
        "cp_name": project_name,
        "project_id": project_id,
        "query": query
    })
    log.info(f"CodeQL query result length : {len(result)}")
    return result


def main():
    # Load project metadata
    with open(PROJECT_METADATA_PATH, "r") as f:
        project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

    if project_metadata.language == LanguageEnum.jvm:
        CODEQL_QUERY_PATH = "/shellphish/corpusguy/generic_java_strings_for_dict.ql"
    else:
        CODEQL_QUERY_PATH = "/shellphish/corpusguy/generic_c_strings_for_dict.ql"

    dictionary_entries = set()
    result = run_codeql_query(
        project_name=ARTIPHISHELL_PROJECT_NAME,
        project_id=ARTIPHISHELL_PROJECT_ID,
        query_path=CODEQL_QUERY_PATH
    )
    if result and len(result) > 0:
        log.info(f"Result keys: {list(result[0].keys())}. Extracting values for \"col0\"...")
        for row in result:
            if row["col0"]:
                dictionary_entries.add(row["col0"])
    else:
        log.warning("Empty CodeQL query result.")
        return

    # Write the keys as double quoted representations to a file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        quoted_entries = set()
        for entry in dictionary_entries:
            if " " in entry:
                continue
            hex_content = "".join(f"\\x{byte:02x}" for byte in entry.encode("utf-8"))
            quoted_entries.add(f'"{hex_content}"\n')
        tmp_file.write("".join(quoted_entries).encode("utf-8"))
        tmp_file_path = tmp_file.name

    sha256sum = subprocess.check_output(
        ["sha256sum", tmp_file_path], 
        text=True
    ).split()[0]
    output_path = os.path.join(OUTPUT_DICTIONARIES_PATH, sha256sum)
    shutil.copy(tmp_file_path, output_path)
    log.info(f"Copied normalized dictionary to {output_path}")

    os.remove(tmp_file_path)

    log.warning(f"Ignoring CORPUSGUY_SYNC_TO_FUZZER flag ({CORPUSGUY_SYNC_TO_FUZZER}). Syncing anyway.")
    shutil.copy(output_path, ARTIPHISHELL_FUZZER_SYNC_DICTS)
    log.info(f"Copied normalized dictionary to fuzzer sync directory.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error(f"Failed to extract codeql dicts: {e}", exc_info=True)
