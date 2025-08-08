#!/usr/bin/env python3

import logging
import os
import random
import time
import yaml

from agentlib import AgentWithHistory, tools
from agentlib.lib.common import LLMApiBudgetExceededError

from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.target import HarnessInfo
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from crs_telemetry.utils import init_otel, get_otel_tracer

init_otel("corpus-guy-inference-llm", "input_generation", "corpus_selection")
TRACER = get_otel_tracer()

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("corpusguy")


# Load environment variables
IS_LOCAL_RUN = os.environ.get("IS_LOCAL_RUN", "0")
PROJECT_METADATA_PATH = os.environ.get("PROJECT_METADATA_PATH")
HARNESS_INFO_PATH = os.environ.get("HARNESS_INFO_PATH")
PROJECT_DIR = os.environ.get("PROJECT_DIR")
FUNCTIONS_INDEX_PATH = os.environ.get("FUNCTIONS_INDEX_PATH")
FUNCTIONS_JSONS_DIR_PATH = os.environ.get("FUNCTIONS_JSONS_DIR_PATH")
INPUT_CORPUS_FILTERED_PATH = os.environ.get("INPUT_CORPUS_FILTERED_PATH")
INPUT_CORPUS_UNFILTERED_PATH = os.environ.get("INPUT_CORPUS_UNFILTERED_PATH")
INPUT_CORPUS_GRAMMARS_PATH = os.environ.get("INPUT_CORPUS_GRAMMARS_PATH")
INPUT_DICTIONARIES_PATH = os.environ.get("INPUT_DICTIONARIES_PATH")
OUTPUT_CORPUS_PATH = os.environ.get("OUTPUT_CORPUS_PATH")
OUTPUT_GRAMMARS_PATH = os.environ.get("OUTPUT_GRAMMARS_PATH")
OUTPUT_DICTIONARIES_PATH = os.environ.get("OUTPUT_DICTIONARIES_PATH")
OUTPUT_METADATA_PATH = os.environ.get("OUTPUT_METADATA_PATH")
ARTIPHISHELL_FUZZER_SYNC_QUEUE = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_QUEUE")
ARTIPHISHELL_FUZZER_SYNC_GRAMMARS = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_GRAMMARS")
ARTIPHISHELL_FUZZER_SYNC_DICTS = os.environ.get("ARTIPHISHELL_FUZZER_SYNC_DICTS")
CORPUSGUY_SYNC_TO_FUZZER = os.environ.get("CORPUSGUY_SYNC_TO_FUZZER")
ARTIPHISHELL_MAX_SEEDS_TOTAL = int(os.environ.get("ARTIPHISHELL_MAX_SEEDS_TOTAL"))

log.info(f"IS_LOCAL_RUN: {IS_LOCAL_RUN}")
log.info(f"PROJECT_METADATA_PATH: {PROJECT_METADATA_PATH}")
log.info(f"HARNESS_INFO_PATH: {HARNESS_INFO_PATH}")
log.info(f"PROJECT_DIR: {PROJECT_DIR}")
log.info(f"FUNCTIONS_INDEX_PATH: {FUNCTIONS_INDEX_PATH}")
log.info(f"FUNCTIONS_JSONS_DIR_PATH: {FUNCTIONS_JSONS_DIR_PATH}")
log.info(f"INPUT_CORPUS_FILTERED_PATH: {INPUT_CORPUS_FILTERED_PATH}")
log.info(f"INPUT_CORPUS_UNFILTERED_PATH: {INPUT_CORPUS_UNFILTERED_PATH}")
log.info(f"INPUT_CORPUS_GRAMMARS_PATH: {INPUT_CORPUS_GRAMMARS_PATH}")
log.info(f"INPUT_DICTIONARIES_PATH: {INPUT_DICTIONARIES_PATH}")
log.info(f"OUTPUT_CORPUS_PATH: {OUTPUT_CORPUS_PATH}")
log.info(f"OUTPUT_GRAMMARS_PATH: {OUTPUT_GRAMMARS_PATH}")
log.info(f"OUTPUT_DICTIONARIES_PATH: {OUTPUT_DICTIONARIES_PATH}")
log.info(f"OUTPUT_METADATA_PATH: {OUTPUT_METADATA_PATH}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_QUEUE: {ARTIPHISHELL_FUZZER_SYNC_QUEUE}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_GRAMMARS: {ARTIPHISHELL_FUZZER_SYNC_GRAMMARS}")
log.info(f"ARTIPHISHELL_FUZZER_SYNC_DICTS: {ARTIPHISHELL_FUZZER_SYNC_DICTS}")
log.info(f"CORPUSGUY_SYNC_TO_FUZZER: {CORPUSGUY_SYNC_TO_FUZZER}")
log.info(f"ARTIPHISHELL_MAX_SEEDS_TOTAL: {ARTIPHISHELL_MAX_SEEDS_TOTAL}")


################################################################################
################################################################################
BEST_INPUT_FILE_FORMATS = set()
ALLOWED_INPUT_FILE_FORMATS = {"3gpp","3gpp2","7z","access","aff","afm","aiff","ar","asm","asn1","asp","ass","atom","av1","avi","avif","basicaudio","bdf","bmp","bpg","bplist","bson","bz","bz2","c","chm","conf","coredump","cpio","cpp","cr3","css","csv","cue","dds","deflate","difxml","djvu","dns","doc","docm","docx","dotm","dotx","dwg","elf","elliptic","envisat","epub","exe","exr","fb2","fits","flac","flv","ftp","geotiff","geotopic","gif","glsl","gob","graphviz","gravity","grib","grib2","groovy","gtar","gz","h264","hdf","heif","hevc","html","http","http2","httpresp","ibooks","icc","icns","ico","ics","iptcanpa","isatab","iso19139","iwork","jar","java","javaclass","jbig2","jpeg","jpeg2000","js","json","keynote","lua","lz","lz4","lzma","m4a","m4v","makefile","markdown","mathml","matlab","mbox","mhtml","midi","mjpeg","mkv","mol","mov","mp3","mp4","mpeg2","msproject","mvg","netcdf","netpbm","nitf","nss","numbers","object","odc","odf","odg","odi","odm","odp","ods","odt","office","ofx","ogg","oleembedded","ooxml","ooxmlprotected","opus","otc","otf","otg","oth","oti","otp","ots","ott","outlook","ozi","pages","pam","pcap","pcx","pdf","php","pkcs7mime","pkcs7signature","pl","png","pop3","potx","ppam","ppsm","ppsx","ppt","pptm","pptx","protobuf","ps","psd","pst","publisher","py","rar","regexp","rss","rst","rtf","ruby","saml","sas","sdp","sfnt","sh","sharedlib","sip","sldworks","smtp","snodas","solidity","speex","spss","sql","stata","svg","swf","tar","tex","tga","tiff","tnef","toml","ttf","type1","type42","unixdump","uri","vcf","vhd","visio","vp8","vp9","wapxhtml","wasm","wast","wav","wbmp","webdav","webm","webp","wgsl","wkt","wps","x509","xcf","xhtml","xlam","xls","xlsm","xlsx","xltm","xltx","xlw","xml","xplist","xslt","xz","yaml","yara","zip","zlib","zmtp","zstd"}
ANALYSIS_COMPLETE = False

@tools.tool
def add_harness_input_file_format(file_format: str):
    '''
    Add a file format to the list of input file formats that the harness accepts as an input.
    '''
    global BEST_INPUT_FILE_FORMATS

    file_format = file_format.lower().strip()

    if file_format in BEST_INPUT_FILE_FORMATS:
        return f"File format {file_format} is already in your proposed list of input file formats. Your proposed list of input file formats is: {BEST_INPUT_FILE_FORMATS}.\n"
    elif file_format in ALLOWED_INPUT_FILE_FORMATS:
        BEST_INPUT_FILE_FORMATS.add(file_format)
        return f"Added file format {file_format} to the list of input file formats."
    else:
        return f"File format {file_format} is not a valid input file format. Valid input file formats are: {ALLOWED_INPUT_FILE_FORMATS}.\n"

@tools.tool
def complete_analysis():
    '''
    Signal that the analysis is complete. Call this when you have finished analyzing the harness
    and have either identified appropriate file formats or determined that no specific formats
    can be identified.
    '''
    global ANALYSIS_COMPLETE
    ANALYSIS_COMPLETE = True
    
    if BEST_INPUT_FILE_FORMATS:
        return f"Analysis completed. Identified {len(BEST_INPUT_FILE_FORMATS)} file format(s): {', '.join(sorted(BEST_INPUT_FILE_FORMATS))}"
    else:
        return "Analysis completed. No specific file formats could be identified from the harness code."

class InferenceAgent(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = '/shellphish/corpusguy/prompts/system.inference.j2'
    __USER_PROMPT_TEMPLATE__ = '/shellphish/corpusguy/prompts/user.inference.j2'
    __LLM_MODEL__ = 'claude-4-sonnet'
    __LLM_ARGS__ = {'max_tokens': 16000}
    __HAS_MEMORY__ = True
    __CONTEXT_WINDOW_EXCEEDED_STRATEGY__ = dict( name='remove_turns', number_to_remove='80%' )
    __RETRIES_ON_TOOL_VALIDATION_ERROR__ = 1

    def __init__(self, *args, project: OSSFuzzProject, harness_info: HarnessInfo, harness_source_code: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.__PROJECT__ = project
        self.__HARNESS_INFO__ = harness_info
        self.__HARNESS_SOURCE_CODE__ = harness_source_code

    def run(self):
        global ANALYSIS_COMPLETE
        
        for attempt in range(5):
            try:
                res = self.invoke(dict(
                    valid_file_formats=" ".join(ALLOWED_INPUT_FILE_FORMATS),
                    project_name=self.__PROJECT__.augmented_metadata.shellphish.project_name,
                    harness_name=self.__HARNESS_INFO__.cp_harness_name,
                    harness_source_code=self.__HARNESS_SOURCE_CODE__,
                ))
                print(res.value)
                
                # Check if analysis was completed
                if ANALYSIS_COMPLETE:
                    log.info("Analysis completed successfully")
                    return
                else:
                    log.warning(f"Agent did not call complete_analysis tool. Attempt {attempt + 1}/5")
                    # Add a message to prompt completion
                    self.chat_history.append({
                        "role": "user",
                        "content": "Please complete your analysis by calling the complete_analysis tool."
                    })
                    
            except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded. Waiting for 1 minute before retrying.")
                time.sleep(60)
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                log.error(f"An error occurred: {e}", exc_info=True)
                self.chat_history.clear()
                if artiphishell_should_fail_on_error():
                    import traceback
                    print(traceback.format_exc())
                    raise
                else:
                    log.exception("Ignoring error and retrying.")
                    time.sleep(60)
                    continue
        
        # If we've exhausted all attempts without completion
        log.warning(f"Analysis did not complete after 5 attempts. Proceeding with {len(BEST_INPUT_FILE_FORMATS)} identified formats.")

    def get_available_tools(self):
        return [
            add_harness_input_file_format,
            complete_analysis
            # find_function,
            # grep_sources,
            # get_functions_in_file,
            # get_files_in_directory,
        ]


################################################################################
################################################################################


@TRACER.start_as_current_span("corpus-guy-inference-llm.main")
def main(project: OSSFuzzProject, harness_info: HarnessInfo):

    if IS_LOCAL_RUN.lower() in ["1", "true", "t", "yes", "y"]:
        function_resolver = LocalFunctionResolver(FUNCTIONS_INDEX_PATH, FUNCTIONS_JSONS_DIR_PATH)
    else:
        function_resolver = RemoteFunctionResolver(cp_name=harness_info.project_name, project_id=harness_info.project_id)

    # then get the harness source code
    harness_function_index_key = project.get_harness_function_index_key(harness_info.cp_harness_name, function_resolver)
    if not harness_function_index_key:
        raise ValueError(f"Could not find harness function {harness_info.cp_harness_name} in the function index")
    harness_function_index = function_resolver.get(harness_function_index_key)
    harness_target_container_path = harness_function_index.target_container_path
    harness_source_code = harness_function_index.code

    log.info(f"Harness source code: \n{harness_source_code}")

    agent = InferenceAgent(
        project=project,
        harness_info=harness_info,
        harness_source_code=harness_source_code
    )
    agent.run()

    # Log the final results
    log.info(f"Final selected file formats: {BEST_INPUT_FILE_FORMATS}")

    # Calculate budget per format
    max_seeds_per_format = ARTIPHISHELL_MAX_SEEDS_TOTAL // len(BEST_INPUT_FILE_FORMATS) if BEST_INPUT_FILE_FORMATS else 0

    for input_format in BEST_INPUT_FILE_FORMATS:
        if os.path.exists(os.path.join(INPUT_CORPUS_UNFILTERED_PATH, input_format)):
            # Copy only up to max_seeds_per_format files (randomly sampled)
            src_dir = os.path.join(INPUT_CORPUS_UNFILTERED_PATH, input_format)
            all_files = [f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))]
            files = random.sample(all_files, min(max_seeds_per_format, len(all_files)))
            for f in files:
                os.system(f"rsync -a {os.path.join(src_dir, f)} {OUTPUT_CORPUS_PATH}/")
        if os.path.exists(os.path.join(INPUT_DICTIONARIES_PATH, input_format)):
            os.system(f"rsync -raz {os.path.join(INPUT_DICTIONARIES_PATH, input_format)}/ {OUTPUT_DICTIONARIES_PATH}")
        # Grammars are single files (not directories) and named {input_format.upper()}.py or {input_format.upper()}@CORPUS.py
        if os.path.exists(os.path.join(INPUT_CORPUS_GRAMMARS_PATH, input_format.upper() + ".py")):
            new_filename = f"CORPUS_INFERENCE_{input_format.upper()}.py"
            os.system(f"rsync -raz {os.path.join(INPUT_CORPUS_GRAMMARS_PATH, input_format.upper() + '.py')} {os.path.join(OUTPUT_GRAMMARS_PATH, new_filename)}")
        if os.path.exists(os.path.join(INPUT_CORPUS_GRAMMARS_PATH, input_format.upper() + "@CORPUS.py")):
            new_filename = f"CORPUS_INFERENCE_{input_format.upper()}@CORPUS.py"
            os.system(f"rsync -raz {os.path.join(INPUT_CORPUS_GRAMMARS_PATH, input_format.upper() + '@CORPUS.py')} {os.path.join(OUTPUT_GRAMMARS_PATH, new_filename)}")

    # output metadata (list of best matches as yaml)
    with open(OUTPUT_METADATA_PATH, "w") as f:
        yaml.dump({"best_input_formats": list(BEST_INPUT_FILE_FORMATS)}, f)

    if CORPUSGUY_SYNC_TO_FUZZER.lower() in ["1", "true", "t", "yes", "y"]:
        with TRACER.start_as_current_span("corpus-guy-inference-llm.sync_to_fuzzer"):
            # sync all seeds with fuzzer
            for i, filename in enumerate(os.listdir(OUTPUT_CORPUS_PATH)):
                new_filename = f"id:{str(i).zfill(6)}_{filename}"
                os.system(f'rsync -a {os.path.join(OUTPUT_CORPUS_PATH, filename)} {os.path.join(ARTIPHISHELL_FUZZER_SYNC_QUEUE, new_filename)}')

            # sync all dictionaries with fuzzer
            for filename in os.listdir(OUTPUT_DICTIONARIES_PATH):
                os.system(f"rsync -a {os.path.join(OUTPUT_DICTIONARIES_PATH, filename)} {os.path.join(ARTIPHISHELL_FUZZER_SYNC_DICTS, filename)}")

            # sync all grammars with fuzzer
            for filename in os.listdir(OUTPUT_GRAMMARS_PATH):
                os.system(f"rsync -a {os.path.join(OUTPUT_GRAMMARS_PATH, filename)} {os.path.join(ARTIPHISHELL_FUZZER_SYNC_GRAMMARS, filename)}")


if __name__ == "__main__":
    # load project metadata and harness info
    with open(HARNESS_INFO_PATH, "r") as f:
        harness_info = HarnessInfo.model_validate(yaml.safe_load(f))
    with open(PROJECT_METADATA_PATH, "r") as f:
        project_metadata = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

    project = OSSFuzzProject(
        PROJECT_DIR,
        project_id=harness_info.project_id,
        augmented_metadata=project_metadata,
    )

    main(project, harness_info)
