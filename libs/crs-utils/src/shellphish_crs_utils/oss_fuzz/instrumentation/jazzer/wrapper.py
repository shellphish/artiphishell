#!/usr/bin/env python3
import os
import sys
import shutil
import random
import yaml
import json
import subprocess
import glob
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any, ClassVar
from abc import ABC, abstractmethod
from pydantic import BaseModel, Field, field_validator, ValidationError
from collections import defaultdict
from rich.logging import RichHandler
from rich.console import Console
from itertools import chain

LOG_FORMAT = (
    "%(asctime)s [%(levelname)-8s] "
    "%(name)s:%(lineno)d | %(message)s"
)

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(console=Console(width=200), rich_tracebacks=True)],
)

log = logging.getLogger("jazzer_wrapper")

# -------------------------------------------
# 🔹 Base Configuration Classes (Pydantic)
# -------------------------------------------


class LibFuzzerConfig(BaseModel):
    """All possible libFuzzer options with their defaults"""

    # LibFuzzer Integer options with defaults
    verbosity: int = 1
    # timeout: int = 60 # FIXME: If timeout not set from aixcc organizers, do something about it
    max_len: int = 0
    # len_control: int = 1000
    # unit_timeout_sec: int = 300
    # timeout_exit_code: int = 70
    # oom_exit_code: int = 71
    # interrupt_exit_code: int = 72
    # error_exit_code: int = 77
    # max_total_time_sec: int = 0
    # rss_limit_mb: int = 0
    # malloc_limit_mb: int = 0
    # mutate_depth: int = 5
    # reload_interval_sec: int = 1
    reload: int = 300 # custom reload interval
    use_value_profile: int = 0
    # max_number_of_runs: int = -1
    # report_slow_units: int = 10
    # print_new_cov_funcs: int = 0
    # purge_allocator_interval_sec: int = 1
    # trace_malloc: int = 0
    # entropic_feature_frequency_threshold: int = 0xFF
    # entropic_number_of_rarest_features: int = 100

    # LibFuzzer Boolean options with defaults
    # keep_seed: bool = False
    ignore_timeouts: int = 0
    ignore_ooms: int = 0
    # ignore_crashes: bool = False
    # do_cross_over: bool = True
    # cross_over_uniform_dist: bool = False
    # reduce_depth: bool = False
    # use_counters: bool = False
    # use_memmem: bool = True
    # use_cmp: bool = False
    
    # shrink: bool = False
    # reduce_inputs: bool = False
    # shuffle_at_startup: bool = True
    # prefer_small: bool = True
    # only_ascii: bool = False
    # entropic: bool = True
    # fork_corpus_groups: bool = False
    # entropic_scale_per_exec_time: bool = False
    # save_artifacts: bool = True
    # print_new: bool = True
    # print_new_cov_pcs: bool = False
    # print_final_stats: bool = False
    # print_corpus_stats: bool = False
    # print_coverage: bool = False
    # print_full_coverage: bool = False
    # dump_coverage: bool = False
    # detect_leaks: bool = True
    # handle_abrt: bool = False
    # handle_alrm: bool = False
    # handle_bus: bool = False
    # handle_fpe: bool = False
    # handle_ill: bool = False
    # handle_int: bool = False
    # handle_segv: bool = False
    # handle_term: bool = False
    # handle_xfsz: bool = False
    # handle_usr1: bool = False
    # handle_usr2: bool = False
    # handle_win_except: bool = False

    # LibFuzzer String options (no defaults unless specified)
    output_corpus: Optional[str] = None
    artifact_prefix: str = "./"
    exact_artifact_path: Optional[str] = None
    # exit_on_src_pos: Optional[str] = None
    # exit_on_item: Optional[str] = None
    # focus_function: Optional[str] = None
    # data_flow_trace: Optional[str] = None
    # collect_data_flow: Optional[str] = None
    # features_dir: Optional[str] = None
    # mutation_graph_file: Optional[str] = None
    # stop_file: Optional[str] = None
    fuzzer_dict: Optional[str] = Field(None, alias="-dict")

    model_config = {
        "alias_generator": lambda field_name: field_name if field_name in {'output_corpus', 'exact_artifact_path'} else f"-{field_name}"
    }


class JazzerConfig(BaseModel):
    """All possible Jazzer options with their defaults, based on com.code_intelligence.jazzer.driver.Opt"""
    
    # Boolean options with defaults
    # fuzz: bool = True  # Run in fuzzing mode (false for regression tests)
    # asan: bool = False  # Allow fuzzing of native libraries with address sanitizer
    # dedup: bool = True  # Compute and print deduplication token for findings
    # mutator_framework: bool = True  # Use internal mutator framework
    # native: bool = False  # Allow fuzzing of native libraries with fuzzer sanitizer
    # hooks: bool = True  # Apply fuzzing instrumentation
    # hwasan: bool = False  # Allow fuzzing of native libraries with hwasan
    # ubsan: bool = False  # Allow fuzzing of native libraries with undefined behavior sanitizer
    # conditional_hooks: bool = False  # Add check for JazzerInternal#hooksEnabled

    # String options
    # agent_path: Optional[str] = None # DO NOT MESS WITH IT
    # autofuzz: Optional[str] = None  # Method to fuzz with auto-generated args TODO
    # coverage_dump: Optional[str] = None   # fabio handle this
    # coverage_report: Optional[str] = None  # fabio handle this
    # dump_classes_dir: Optional[str] = None  # Dir to dump instrumented classes # no need
    # id_sync_file: Optional[str] = None  # File for subprocess coordination
    # reproducer_path: str = "."  # Dir for Java reproducers
    # target_class: Optional[str] = None   # preset from Harness # DO NOT MESS WITH IT
    # target_method: Optional[str] = None  # DO NOT MESS WITH IT

    # Integer options
    # mutator_cross_over_frequency: int = 100  # Frequency of cross-over mutations
    keep_going: int = 1  # Number of findings before stopping

    # List options
    # additional_classes_excludes: List[str] = []  # Exclude patterns for additional classes
    # autofuzz_ignore: List[str] = []  # Exception classes to ignore
    # cp: List[str] = []  # preset from Harness # DO NOT MESS WITH IT
    # custom_hook_excludes: List[str] = []  # Exclude patterns for hook instrumentation
    custom_hooks: str = ""  # Classes for custom hooks
    custom_hook_includes: str = ""  # Include patterns for hook instrumentation
    disabled_hooks: str = ""  # Classes to not load hooks from
    # ignore: List[str] = []  # Deduplication tokens to ignore 
    # instrument: List[str] = []  # Classes to instrument for fuzzing
    instrumentation_excludes: str = ""  # Exclude patterns for instrumentation
    instrumentation_includes: str = ""  # Include patterns for instrumentation
    # target_args: List[str] = []  # Args for fuzzerInitialize
    # trace: List[str] = []  # Types of instrumentation to apply
    # list_fuzz_tests: List[str] = []  # Classes to scan for fuzz tests

    model_config = {
        "alias_generator": lambda field_name: f"--{field_name}"
    }

# ----------------------------------------------
# 🔹 Read Environment Variables from Pipeline
# ----------------------------------------------


class FuzzingEnvironmentConfig(BaseModel):
    """Configuration for fuzzing environment"""
    # Either modified shellphish jazzer or default aixcc-jazzer
    jazzer_binary: Path = Field(..., description="Path to Jazzer binary")
    jazzer_agent: Path = Field(..., description="Path to Jazzer agent")

    # In-scope classes for instrumentation
    in_scope_classes_path: Optional[Path] = Field(..., description="Path to in-scope classes file")
    #FIXME: force paths to end with a slash
    crashing_seeds: Optional[Path] = Field(None, description="Path to crashing seeds directory")
    losan_crashing_seeds: Optional[Path] = Field(None, description="Path to losan crashing seeds directory")
    benign_seeds: Optional[Path] = Field(None, description="Path to benign seeds directory")
    fuzzer_sync_path: Optional[Path] = Field(None, description="Path to fuzzer sync directory for this harness")
    cross_harness_fuzzer_sync_path:Optional[Path] = Field(None, description="Path to fuzzer sync directory for cross-harness fuzzing") #TODO
    crash_reports: Optional[Path] = Field(None, description="Path to crash reports directory")
    fuzzing_log: Optional[Path] = Field(None, description="Path to fuzzing log file")

    # Run POV LOSAN
    losan_jazzer_agent: Optional[Path] = Field(None, description="Path to LOSAN Jazzer agent")
    losan_jazzer_driver: Optional[Path] = Field(None, description="Path to LOSAN Jazzer driver")
    harness_name: Optional[str] = Field(None, description="Name of the harness")
    run_pov_seed: Optional[str] = Field(None, description="Seed for the fuzzing")

    # OSS-FUZZ and mounted paths
    src_dir: Path = Path("/src")
    out_dir: Path = Path("/out")
    work_dir: Path = Path("/work")
    shellphish_path: Path = Path("/shellphish")
    codeql_strings_dict: Optional[Path] = Field("/shellphish/dict.txt", description="Path to codeql strings dict")

    ijon_mode: bool = Field(None, description="Enable IJON mode for Jazzer")

    @classmethod
    def load_from_env(cls):
        """Load environment variables and validate"""
        env_vars = {
            "jazzer_binary": os.environ.get("ARTIPHISHELL_JAZZER_BINARY") or os.environ.get("LOSAN_JAZZER_DRIVER"),
            "jazzer_agent": os.environ.get("ARTIPHISHELL_JAZZER_AGENT") or os.environ.get("LOSAN_JAZZER_AGENT_JAR"),
            "crashing_seeds": os.environ.get("ARTIPHISHELL_JAZZER_CRASHING_SEEDS"),
            "losan_crashing_seeds": os.environ.get("ARTIPHISHELL_JAZZER_LOSAN_CRASHING_SEEDS"),
            "benign_seeds": os.environ.get("ARTIPHISHELL_JAZZER_BENIGN_SEEDS"),
            "fuzzer_sync_path": os.environ.get("ARTIPHISHELL_FUZZER_SYNC_PATH"),
            "cross_harness_fuzzer_sync_path": os.environ.get("ARTIPHISHELL_JAZZER_CROSS_HARNESS_FUZZER_SYNC_PATH"),
            "in_scope_classes_path": os.environ.get("ARTIPHISHELL_IN_SCOPE_CLASSES"),
            "crash_reports": os.environ.get("ARTIPHISHELL_JAZZER_CRASH_REPORTS"),
            "fuzzing_log": os.environ.get("ARTIPHISHELL_JAZZER_FUZZING_LOG"),

            "losan_jazzer_agent": os.environ.get("LOSAN_JAZZER_AGENT_JAR"),
            "losan_jazzer_driver": os.environ.get("LOSAN_JAZZER_DRIVER"),
            "harness_name": os.environ.get("ARTIPHISHELL_HARNESS_NAME"),
            "run_pov_seed": os.environ.get("TESTCASE"),
            "ijon_mode": os.environ.get("ARTIPHISHELL_IJON_MODE", None) is not None,
        }

        log.debug(f"🔎 Environment Variables Loaded: {env_vars}")
        try:
            return cls(**env_vars) 
        except ValidationError as e:
            log.error(f"❌ Environment variable validation failed! {e}")


# -----------------------------------
# 🔹 Abstract Base Runpov Class
# -----------------------------------

class JazzerRunPOV(ABC):
    def __init__(self, cli_args: List[str]):
        log.debug(f"Initializing {self.__class__.__name__} with args: {cli_args}")
        self.cli_args = cli_args

        # Load configurations
        self.fuzzing_environment_config = self.load_fuzzing_environment_config()
    
    def load_fuzzing_environment_config(self) -> FuzzingEnvironmentConfig:
        """Load Jazzer-specific configuration directly from environment variables"""
        try:
            config = FuzzingEnvironmentConfig.load_from_env()
            return config
        except ValidationError as e:
            log.error(f"❌ Fatal error: Missing required environment variables: {e} ::\n{config}")
        return config

# -----------------------------------
# 🔹 Abstract Base Fuzz Class
# -----------------------------------

class JazzerFuzz(ABC):
    def __init__(self, cli_args: List[str]):
        log.debug(f"Initializing {self.__class__.__name__} with args: {cli_args}")
        self.cli_args = cli_args

        # Load configurations
        self.fuzzing_environment_config = self.load_fuzzing_environment_config()
        self.in_scope_classes = self.load_in_scope_classes()
        self.random_instrumentation_classes = self.get_random_instrumentation_classes()
        
        updated_fuzzer_args = self.update_fuzzer_args()
        self.mandatory_args, self.optional_args = updated_fuzzer_args.get("mandatory", {}), updated_fuzzer_args.get("optional", {})
        log.debug(f"Loaded Jazzer and libFuzzer configs! with updated args: {updated_fuzzer_args}")


    def load_fuzzing_environment_config(self) -> FuzzingEnvironmentConfig:
        """Load Jazzer-specific configuration directly from environment variables"""
        try:
            config = FuzzingEnvironmentConfig.load_from_env()
            return config
        except ValidationError as e:
            log.error(f"❌ Fatal error: Missing required environment variables: {e} ::\n{config}")
        return config
    
    def get_random_instrumentation_classes(self):
        if self.in_scope_classes:
            in_scope = self.in_scope_classes
            # Convert keys to a list and randomly choose one key
            random_key = random.choice(list(in_scope.keys()))
            log.debug(f"🔹 Instrumentation classes from {random_key}")
            return in_scope[random_key]
        else:
            return None

    # Load instrumentation classes
    def load_in_scope_classes(self):
        """Loads JSON file with in-scope classes."""
        if self.fuzzing_environment_config.in_scope_classes_path is None:
            return None
        json_path = self.fuzzing_environment_config.in_scope_classes_path
        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                return json.load(f)
        return {
                'in_scope_packages_from_antlr': None,
                'all_packages_from_reachability_report': None,
                }

    def get_mandatory_args(self) -> Dict[str, Any]:
        """Returns mandatory arguments with their values."""
        log.debug(f"🔹 Mandatory args: {self.mandatory_args}")
        return self.mandatory_args

    def get_optional_args(self) -> Dict[str, Any]:
        """Returns optional arguments with their values."""
        log.debug(f"🔹 Optional args: {self.optional_args}")
        return self.optional_args

    def load_libfuzzer_config(self) -> LibFuzzerConfig:
        return LibFuzzerConfig.model_validate(os.environ)
    
    def load_jazzer_config(self) -> JazzerConfig:
        return JazzerConfig.model_validate(os.environ)

    # Update models with new args for each fuzzing mode
    def _update_models_with_new_args(self, fuzzer_name, args):

        # Load and update the model.
        config_loader = getattr(self, f"load_{fuzzer_name}_config")
        config_tmp = config_loader().model_copy(update=args)
        # Retrieve the updated model as a dictionary, with aliasing.
        updated_dict = config_tmp.dict(exclude_unset=True, by_alias=True)
        return updated_dict

    # collect mandatory and optional args for each fuzzing mode
    def update_fuzzer_args(self):
        """Applies updates to both LibFuzzer and Jazzer configurations and returns only updated fields."""

        final_dict = defaultdict(dict)
        updates = self.get_updated_args_for_fuzzer()
        for fuzzer_name, arg_updates in updates.items():
            for update_type, update_dict in arg_updates.items():
                updated_dict = self._update_models_with_new_args(fuzzer_name, update_dict)
                final_dict[update_type].update(updated_dict)
        # log.debug(f"🔹 Final dict: {final_dict}")
        return dict(final_dict)


    def add_or_update_fuzzer_cli_args(self, min_optional_args: int = 1, max_optional_args: int = 1) -> Tuple[Dict[str, Any], List[str]]:
        """Processes CLI args, ensures mandatory args are included, and enables optional args randomly."""

        # Step 1️⃣:  Parse CLI args into a dictionary
        log.debug(f"📌 CLI args: {self.cli_args}")
        cli_args_dict, seeds_dirs = {}, []

        for arg in self.cli_args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                if key == "-timeout":
                    log.debug(f"📌 Timeout arg detected: {arg} with value {value}.")
                    value = int(value) + 5
                    log.debug(f"📌 Updated timeout value: {value}")
                cli_args_dict[key] = value
            else:
                seeds_dirs.append(arg)

        # Step 2️⃣: Ensure all mandatory args are present. at this point all args are aliased
        log.debug(f"Updating mandatory args: {self.get_mandatory_args()}")
        mandatory_args = self.get_mandatory_args()
        for arg_name, arg_value in mandatory_args.items():
            if arg_name not in cli_args_dict:
                cli_args_dict[arg_name] = arg_value 

        # Step 3️⃣: Randomly enable optional args. at this point all args are aliased
        log.debug(f"Updating optional args: {self.get_optional_args()}")
        optional_args = self.get_optional_args()
        if optional_args:
            all_optional_keys = list(self.get_optional_args().keys())
            num_selected = random.randint(min_optional_args, max_optional_args)  # Choose 1 to 3 random args # FIXME: change the number of optional args
            selected_optional_keys = random.sample(all_optional_keys, min(num_selected, len(all_optional_keys)))
            log.debug(f" Selected optional keys: {selected_optional_keys}")
            for key in selected_optional_keys:
                # TODO: find why both instrumentation_includes and custom_hook_includes are needed for now just add them both
                if key == "--instrumentation_includes":
                    cli_args_dict["--custom_hook_includes"] = optional_args[key]
                cli_args_dict[key] = optional_args[key]

        return cli_args_dict, seeds_dirs


    def build_args(self, additional_seeds_args: Optional[List[str]] = None, min_optional_args: int = 1, max_optional_args: int = 1) -> List[str]:
        """Build final fuzzing argument list, ensuring correct updates and handling additional seed directories."""
        # Always copy agent if path is set
        if self.fuzzing_environment_config.jazzer_agent is not None:
            agent_dest = Path(self.fuzzing_environment_config.out_dir, "jazzer_agent_deploy.jar")
            os.system(f'cp {self.fuzzing_environment_config.jazzer_agent} {agent_dest}')

        log.debug("Building fuzzer arguments")
        selected_args, detected_benign_seeds_dir = self.add_or_update_fuzzer_cli_args(min_optional_args, max_optional_args)
        final_args = [f"{key}={value}" if not isinstance(value, bool) else key for key, value in selected_args.items()]
        # if detected_benign_seeds_dir not in final_args: # TODO: make sure we first seeds dir for benign seeds is our seeds dir (setting CORPUS_DIR to the benign seeds dir sets our benign seeds dir to the benign seeds dir else ossfuzz assigns something else)
        #     log.debug(f"📂 Unknown benign seeds dir detected: {detected_benign_seeds_dir}")
        if additional_seeds_args:
            log.debug(f"📂 Adding additional seed directories: {additional_seeds_args}")
            final_args.extend(additional_seeds_args)

        log.debug(f"Final fuzzer args: {final_args}")
        return final_args

    def run_jazzer(self, args: List[str], job_name: str) -> str:
        """Run Jazzer with the given arguments"""
        try:
            log.debug(f"Starting {job_name} Jazzer!")
            fuzzing_args = [str(self.fuzzing_environment_config.jazzer_binary)] + args
            # Prepare script
            # TODO: add auto kill timeout issue
            fuzz_script = f'''#!/bin/bash
            set -x
            
            echo "===== Fuzzer Disk Space Usage ====="
            # space usage
            df -h /tmp /dev/shm
            # inode usage (many small files can exhaust this before bytes do)
            df -i  /tmp /dev/shm
            
            mkdir -p {self.fuzzing_environment_config.out_dir}
            mkdir -p {self.fuzzing_environment_config.crash_reports}

            # snapshot any pre-existing log
            if [[ -f "{self.fuzzing_environment_config.fuzzing_log}" ]]; then
                mv "{self.fuzzing_environment_config.fuzzing_log}" "{self.fuzzing_environment_config.fuzzing_log}.$(date +%d%H%M%S)"
            fi
            
            # nohup bash /work/auto_kill.sh > /work/tmpkill_{job_name}.log & 
            {" ".join(str(x) for x in fuzzing_args)}

            echo "Fuzzing completed. Copying crash reports to {self.fuzzing_environment_config.crash_reports}"
            find . -name "Crash*" -type f -exec cp {{}} {self.fuzzing_environment_config.crash_reports} \;
            '''

            script_path = Path(self.fuzzing_environment_config.out_dir, f"fuzz_{job_name}.sh")
            with open(script_path, "w") as f:
                f.write(fuzz_script)
            log.debug(f"Created fuzzing script at: {script_path} and fuzzing args: {fuzzing_args}")

            # Execute
            os.system(f'chmod +x {script_path}')
            replica_id = os.environ.get("REPLICA_ID")
            log.debug(f"Replica ID: {replica_id}")

            while True:
                if replica_id and 1 <= int(replica_id) <= 8:
                    os.system(f'/bin/bash {script_path} 2>&1 | tee {self.fuzzing_environment_config.fuzzing_log}')
                else:
                    os.system(f'/bin/bash {script_path}')

                # Lets check if we have injected seeds, if so we copy thme into the crashes dir
                if os.path.exists("/shared/injected-seeds"):
                    log.debug(f"We have crashing seeds, copying injected seeds to {self.fuzzing_environment_config.crashing_seeds}")
                    os.system(f'cp -r /shared/injected-seeds/. {self.fuzzing_environment_config.fuzzer_sync_path}/jazzer-minimized/crashes/')



        except Exception as e:
            log.error(f"Error running Jazzer: {e}", exc_info=True)
            raise


    @abstractmethod
    def get_updated_args_for_fuzzer(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        pass

    @abstractmethod
    def run(self):
        """Each fuzzing mode implements its own run method"""
        pass


# -----------------------------------
# 🔹 Fuzzing Modes - Vanilla
# -----------------------------------

class VanillaFuzz(JazzerFuzz):
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)

    def get_updated_args_for_fuzzer(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Returns a nested dictionary with separate mandatory and optional updates for each fuzzer.
        """
        corpus_strings, interesting_strings = [], []
        try:
            with open(self.fuzzing_environment_config.codeql_strings_dict, 'r') as r:
                interesting_strings = r.read().splitlines()

            corpus_guy_dict_path = Path(self.fuzzing_environment_config.fuzzer_sync_path)/"sync-dicts/"
            if corpus_guy_dict_path.is_dir():
                for file_path in corpus_guy_dict_path.iterdir():
                    if file_path.is_file():
                        with open(file_path, 'r') as r:
                            corpus_strings.extend(r.read().splitlines())
            if random.randint(0,1):
                if corpus_strings:
                    # We replace the dictionary with corpus guy strings
                    corpus_strings = list(set(corpus_strings))
                    with open(self.fuzzing_environment_config.codeql_strings_dict, 'w') as w:
                        w.write("\n".join(corpus_strings))
        except Exception as e:
            log.error(f"Error in updating dict {e}")

        # DEBUG REMOVE ME
        os.system("cat /shellphish/dict.txt")

        libfuzzer_updates = {
            "mandatory": {
                "verbosity": 2,
                "reload": 200,
                "artifact_prefix": f'{self.fuzzing_environment_config.crashing_seeds}/',
                "max_len": 2<<20,
            },
            "optional": {
                "fuzzer_dict": self.fuzzing_environment_config.codeql_strings_dict,
                "use_value_profile": 1,
            }
        }
        jazzer_updates = {
            "mandatory": {
                "keep_going": 1000,
            },
            "optional":{

            }
        }
        if self.random_instrumentation_classes:
            jazzer_updates["optional"] = {"instrumentation_includes": self.random_instrumentation_classes}

        return {"libfuzzer": libfuzzer_updates, "jazzer": jazzer_updates}

    def run(self):
        try:
            log.debug("Starting VanillaFuzz run")
            additional_seeds_args = []
            
            # If benign_seeds exists in config, add it as additional arg
            if self.fuzzing_environment_config.benign_seeds:
                log.debug(f" Adding benign seeds path: {self.fuzzing_environment_config.benign_seeds}")
                additional_seeds_args.append(f'{self.fuzzing_environment_config.benign_seeds}/')

            if self.fuzzing_environment_config.fuzzer_sync_path:
                log.debug(f" Adding fuzzer sync path: {self.fuzzing_environment_config.fuzzer_sync_path}")
                additional_seeds_args.append(f'{self.fuzzing_environment_config.fuzzer_sync_path}/jazzer-minimized/queue/')

                # Sync seeds from other components
                quickseed_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-quickseed" / "queue"
                corpusguy_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy" / "queue"
                corpus_guy_kickstart_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-kickstart" / "queue"
                corpus_guy_kickstart_crashes_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-kickstart-crashes" / "queue"
                corpus_guy_permanence_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-permanence" / "queue"
                disco_guy_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-discoguy" / "queue"
                
                # ggs
                sync_grammar_agent_explore_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammar-agent-explore" / "queue"
                sync_grammar_guy_fuzz_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammar-guy-fuzz" / "queue"
                sync_grammarroomba = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammarroomba" / "queue"
                # losan_reproducer_corpus = self.fuzzing_environment_config.fuzzer_sync_path / "sync-grammar-agent-reproduce-losan-dedup-pov" / "queue"
                losan_agent_corpus = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-losan-gg" / "queue"

                corpus_collection = [quickseed_path, corpusguy_path, corpus_guy_kickstart_path, corpus_guy_kickstart_crashes_path, corpus_guy_permanence_path, disco_guy_path, 
                                    sync_grammar_agent_explore_path, sync_grammar_guy_fuzz_path, sync_grammarroomba, losan_agent_corpus]

                if self.fuzzing_environment_config.ijon_mode is None:
                    ijon_sync_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-aijon-java" / "queue"
                    corpus_collection.append(ijon_sync_path)
                    
                for path in corpus_collection:
                    path.mkdir(parents=True, exist_ok=True)
                    additional_seeds_args.append(str(path))

                # # directories matching "sync-grammar-agent-explore-* because we can have N number of replicas"
                # patterns = [
                #     "sync-grammar-agent-explore-*",
                #     "sync-corpusguy*",
                #     "sync-discoguy*"
                # ]

                # for agent_dir in chain.from_iterable(self.fuzzing_environment_config.fuzzer_sync_path.glob(pattern) for pattern in patterns):
                #     log.info(f" Sync dir found: {agent_dir}!")
                #     queue_dir = agent_dir / "queue"
                #     queue_dir.mkdir(parents=True, exist_ok=True)
                #     additional_seeds_args.append(str(queue_dir))

            log.debug(f"seeds dir {additional_seeds_args}")

            final_args = self.build_args(
                additional_seeds_args=additional_seeds_args,
                min_optional_args=1, # TODO: update this after more args
                max_optional_args=3
            )
            log.debug(f"Fuzzing with args: {final_args}")
            if self.fuzzing_environment_config.ijon_mode:
                log.debug("IJON mode is enabled. Compiling..")
                JazzerFactory.compile_aijon()
            self.run_jazzer(final_args, "vanilla_fuzz")

        except Exception as e:
            log.error(f"Error in vanilla fuzzing: {e}", exc_info=True)
            raise


# -----------------------------------
# 🔹 Fuzzing Modes - Losan
# -----------------------------------

class LosanFuzz(VanillaFuzz):
    """VanillaFuzz with SHELL_SAN=LOSAN environment variable set."""
    
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)
        
    def get_updated_args_for_fuzzer(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        
        # TODO: try disabling some hooks for some runs
        vanilla_updates = super().get_updated_args_for_fuzzer()

        # Consolidate extra updates specific to LOSAN.
        extra_updates = {
            "libfuzzer": {
                "mandatory": {"ignore_timeouts": 1,
                            "ignore_ooms": 1,
                            "artifact_prefix": f'{self.fuzzing_environment_config.losan_crashing_seeds}/',
                            },
                "optional": {},
            },
            "jazzer": {
                "mandatory": {},
                "optional": {},
            },
        }

        # Loop over each fuzzer and its update categories, merging the updates.
        for fuzzer, categories in extra_updates.items():
            for category, updates in categories.items():
                vanilla_updates[fuzzer][category].update(updates)

        return vanilla_updates

# TODO: disable some hooks for some runs
    def run(self):
        try:
            log.debug("Starting LosanFuzz run")
            # Set SHELL_SAN environment variable
            os.environ["SHELL_SAN"] = "LOSAN"
            log.debug('🛡️ Fuzzing with LOSAN enabled')
            
            # Call parent's run method to do the actual fuzzing
            super().run()
            
        except Exception as e:
            log.error(f"Error in LOSAN fuzzing: {e}", exc_info=True)
            raise

# -----------------------------------
# 🔹 Fuzzing Modes - Nautilius
# -----------------------------------

class NautilusFuzz(VanillaFuzz):
    """VanillaFuzz with X environment variable set."""

    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)

    def get_updated_args_for_fuzzer(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Returns specific LibFuzzer & Jazzer args for VanillaFuzz."""

        # TODO: try disabling some hooks for some runs
        vanilla_updates = super().get_updated_args_for_fuzzer()

        rons_input_crashes_path = f"{self.fuzzing_environment_config.fuzzer_sync_path}/sync-jazzer-rons/crashes/"

        # Consolidate extra updates specific to Nautilus.
        extra_updates = {
            "libfuzzer": {
                "mandatory": {
                    "artifact_prefix": rons_input_crashes_path,
                },
                "optional": {},
            },
            "jazzer": {
                "mandatory": {"keep_going": 9999},
                "optional": {},
            },
        }

        # Loop over each fuzzer and its update categories, merging the updates.
        for fuzzer, categories in extra_updates.items():
            for category, updates in categories.items():
                vanilla_updates[fuzzer][category].update(updates)

        return vanilla_updates

    def run(self):
        try:
            log.debug("Starting NautilusFuzz run")

            os.environ["NAUTILUS"] = "X"
            os.environ["JAZZER_NAUTILUS_HOOKS"] = "X"
            os.environ["JAZZER_NAUTILUS_HOOKS_PATH"] = f"{self.fuzzing_environment_config.out_dir}/shellphish/nautilus/librevolver_mutator.so"

            additional_seeds_args = []

            if self.fuzzing_environment_config.fuzzer_sync_path:
                grammar_sync_path = f"{self.fuzzing_environment_config.fuzzer_sync_path}/sync-grammars/nautilus-python"
                rons_input_queue_path = f"{self.fuzzing_environment_config.fuzzer_sync_path}/sync-jazzer-rons/queue"
                rons_input_crashes_path = f"{self.fuzzing_environment_config.fuzzer_sync_path}/sync-jazzer-rons/crashes"
                jazzer_queue_sync_dir = f'{self.fuzzing_environment_config.fuzzer_sync_path}/jazzer-all/queue'
                jazzer_crashes_sync_dir = f'{self.fuzzing_environment_config.fuzzer_sync_path}/jazzer-all/crashes'

                os.system(f"mkdir -p {jazzer_queue_sync_dir}")
                os.system(f"mkdir -p {jazzer_crashes_sync_dir}")
                os.system(f"mkdir -p {grammar_sync_path}")
                os.system(f"mkdir -p {rons_input_queue_path}")
                os.system(f"mkdir -p {rons_input_crashes_path}")

                token_env_setting = random.choice(['NEVER', 'ALWAYS', 'BOTH', 'BOTH', 'BOTH'])
                os.environ['NAUTILUS_TOKEN_FUZZ'] = token_env_setting

                print(f"Running with NAUTILUS_TOKEN_FUZZ = {token_env_setting}")

                if os.environ.get("NAUTILUS_TOKEN_FUZZ") == "NEVER":
                    os.system('" > ' + grammar_sync_path + '/bytes_grammar.py')
                    with open(grammar_sync_path + '/bytes_grammar.py', "w+") as fp:
                        fp.write("ctx.rule(\"START\", b\"{BYTES}\")\nctx.bytes(\"BYTES\", 65536)")
                else:
                    with open(grammar_sync_path + '/token_grammar_bytes.py', "w+") as fp:
                        fp.write("ctx.rule(\"START\", b\"{BYTES}\")\nctx.bytes(\"BYTES\", 65536)\n# ARTIPHISHELL TOKEN TOKEN TOKEN ")

                log.debug(f'👀 Starting watchtower monitoring {grammar_sync_path} for grammars')
                subprocess.Popen(
                    [
                        f"{self.fuzzing_environment_config.out_dir}/shellphish/nautilus/watchtower",
                        "sync-grammars",
                        "-i", grammar_sync_path,
                        "-o", rons_input_queue_path,
                        "-n", "10"
                    ]
                )

                log.debug(f'👀 Starting watchtower monitoring {rons_input_queue_path} for inputs')
                subprocess.Popen(
                    [
                        f"{self.fuzzing_environment_config.out_dir}/shellphish/nautilus/watchtower",
                        "sync-outputs",
                        "-i", rons_input_queue_path,
                        "-o", jazzer_queue_sync_dir,
                    ]
                )

                log.debug(f'👀 Starting watchtower monitoring {rons_input_crashes_path} for crashes')
                subprocess.Popen(
                    [
                        f"{self.fuzzing_environment_config.out_dir}/shellphish/nautilus/watchtower",
                        "sync-outputs",
                        "-i", rons_input_crashes_path,
                        "-o", jazzer_crashes_sync_dir,
                    ]
                )

                log.debug(f" Adding cross-harness fuzzer sync path: {rons_input_queue_path}")
                additional_seeds_args.append(f'{self.fuzzing_environment_config.fuzzer_sync_path}/sync-jazzer-rons/queue')

            log.debug('🛡️ Fuzzing with NAUTILUS enabled')

            final_args = self.build_args(additional_seeds_args=additional_seeds_args)
            log.debug(f"Fuzzing with args: {final_args}")

            self.run_jazzer(final_args, "nautilus")
        except Exception as e:
            log.error(f"Error in Nautilus fuzzing: {e}", exc_info=True)
            raise

# -----------------------------------
# 🔹 Fuzzing Modes - Run POV
# -----------------------------------

class RunPovFuzz(JazzerRunPOV):
    """Run POV"""
    
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)
    
    def run(self):
        try:
            log.debug(f"Runing LOSAN POV with self.cli_args: {self.cli_args}")
            losan_jazzer_agent = self.fuzzing_environment_config.losan_jazzer_agent
            losan_jazzer_driver = self.fuzzing_environment_config.losan_jazzer_driver
            
            if losan_jazzer_agent is None or losan_jazzer_driver is None:
                log.error("Missing LOSAN Jazzer agent or driver")
                raise EnvironmentError("Missing LOSAN Jazzer agent or driver")
            os.system(f'cp {losan_jazzer_agent} {Path(self.fuzzing_environment_config.out_dir, "jazzer_agent_deploy.jar")}')
            # os.system(f'cp {losan_jazzer_driver} {Path(self.fuzzing_environment_config.out_dir, "jazzer_driver")}')
            harness_name = self.fuzzing_environment_config.harness_name
            if harness_name is None:
                log.error("Missing harness name")
                raise EnvironmentError("Missing harness name")
            run_pov_seed = self.fuzzing_environment_config.run_pov_seed
            if run_pov_seed is None:
                log.error("Missing pov guy seed")
                raise EnvironmentError("Missing pov guy seed")
            
            #os.system(f'{self.fuzzing_environment_config.jazzer_binary} {" ".join(self.cli_args)} {run_pov_seed}')
            os.system(f'{losan_jazzer_driver} {" ".join(self.cli_args)} {run_pov_seed}')
        except Exception as e:
            log.error(f"Error in Run POV: {e}", exc_info=True)
            raise

# --------------------------------------
# 🔹 Fuzzing Modes - Targeted Fuzzing
# --------------------------------------

class TargetedFuzz(VanillaFuzz):
    """TargetedFuzz """
    
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)
    
    def get_updated_args_for_fuzzer(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Returns specific LibFuzzer & Jazzer args for VanillaFuzz."""

        return {}, {}
 
    def run(self):
        try:
            log.debug("Starting TargetedFuzz run")
            # TODO: Implement TargetedFuzz
            pass
            
        except Exception as e:
            log.error(f"Error in TargetedFuzz: {e}", exc_info=True)
            raise

# --------------------------------------
# 🔹 Fuzzing Modes - Crash Exploration
# --------------------------------------

class CrashExploration(VanillaFuzz):
    """Crash Exploration """
    
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)
    
    def get_updated_args_for_fuzzer(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Returns specific LibFuzzer & Jazzer args for VanillaFuzz."""
        return {}, {}
 
    def run(self):
        try:
            log.debug("Starting CrashExploration run")
            # TODO: Implement CrashExploration
            pass
            
        except Exception as e:
            log.error(f"Error in CrashExploration: {e}", exc_info=True)
            raise

class JazzerFactory:
    @staticmethod
    def compile_aijon():
        out_dir = Path("/out")
        cmd = [
            "javac",
            "-cp",
            out_dir / "jazzer_agent_deploy.jar",
            out_dir / "IJONJava.java",
        ]
        subprocess.run(cmd, check=True)
        cmd = ["jar", "cf", out_dir / "ijon.jar", out_dir / "IJONJava.class"]
        subprocess.run(cmd, check=True)

    @staticmethod
    def create(mode: str, cli_args: List[str]):
        """Create appropriate wrapper based on mode"""
        log.debug(f"Creating Jazzer wrapper for mode: {mode}")

        modes = {
            # 'fuzz': [VanillaFuzz, LosanFuzz, Nautilus, TargetedFuzz],
            'fuzz': [VanillaFuzz, LosanFuzz],
            'crash_explore': [CrashExploration],
            'run_pov': [RunPovFuzz]
        }

        # if we are using the patched jazzer_agent then nautilus is available
        jazzer_agent = os.environ.get("ARTIPHISHELL_JAZZER_AGENT") or os.environ.get("LOSAN_JAZZER_DRIVER")
        if jazzer_agent and not jazzer_agent.endswith(".orig"):
            modes['fuzz'] += [NautilusFuzz]

        log.debug(f"Supported modes: {modes}")
        if os.environ.get("ARTIPHISHELL_IJON_MODE", None) is not None:
            log.debug("IJON mode is enabled. Switching to VanillaFuzz")
            modes["fuzz"] = [VanillaFuzz]
            mode = "fuzz"

        if mode in modes:
            fuzzer_class = random.choice(modes[mode])
            log.debug(f"Selected fuzzer class: {fuzzer_class}")
        else:
            log.warning(f"Unknown mode '{mode}', defaulting to VanillaFuzz")
            fuzzer_class = VanillaFuzz

        return fuzzer_class(cli_args)

# Main entry point
if __name__ == '__main__':
    try:
        log.debug(f"Existing Jazzer args: {sys.argv[1:]}")
        mode = os.getenv('MODE')
        # Run run_pov for LOSAN POVguy based on the instance name
        if mode is None and os.getenv('ARTIPHISHELL_FUZZER_INSTANCE_NAME') == "run_pov":
            mode = "run_pov"
        log.debug(f"Running Jazzer with mode: {mode}")
        
        wrapper = JazzerFactory.create(mode, sys.argv[1:])
        wrapper.run()
        
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
