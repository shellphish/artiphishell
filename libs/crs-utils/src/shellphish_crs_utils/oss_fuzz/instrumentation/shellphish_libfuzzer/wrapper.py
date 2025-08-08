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

log = logging.getLogger("libFuzzer_wrapper")

# -------------------------------------------
# 🔹 Base Configuration Classes (Pydantic)
# -------------------------------------------


class LibFuzzerConfig(BaseModel):
    """All possible libFuzzer options with their defaults"""
    
    # LibFuzzer Integer options with defaults
    verbosity: int = 1
    # timeout: int = 60 # FIXME: If timeout not set from aixcc organizers, do something about it
    # max_len: int = 0
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
    ignore_crashes: int = 0
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
    fork: int = 1
    # shrink: bool = False
    # reduce_inputs: bool = False
    # shuffle_at_startup: bool = True
    # prefer_small: bool = True
    # only_ascii: bool = False
    # entropic: bool = True
    fork_corpus_groups: int = 1
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


# ----------------------------------------------
# 🔹 Read Environment Variables from Pipeline
# ----------------------------------------------


class FuzzingEnvironmentConfig(BaseModel):
    """Configuration for fuzzing environment"""

    #FIXME: force paths to end with a slash
    crashing_seeds: Optional[Path] = Field(None, description="Path to crashing seeds directory")
    benign_seeds: Optional[Path] = Field(None, description="Path to benign seeds directory")
    fuzzer_sync_path: Optional[Path] = Field(None, description="Path to fuzzer sync directory for this harness")
    cross_harness_fuzzer_sync_path:Optional[Path] = Field(None, description="Path to fuzzer sync directory for cross-harness fuzzing") #TODO
    fuzzing_log: Optional[Path] = Field(None, description="Path to fuzzing log file")

    # OSS-FUZZ and mounted paths
    src_dir: Path = Path("/src")
    out_dir: Path = Path("/out")
    work_dir: Path = Path("/work")
    shellphish_path: Path = Path("/shellphish")
    codeql_strings_dict: Optional[Path] = Field("/shellphish/dict.txt", description="Path to codeql strings dict")

    @classmethod
    def load_from_env(cls):
        """Load environment variables and validate"""
        env_vars = {
            "crashing_seeds": os.environ.get("ARTIPHISHELL_LIBFUZZER_CRASHING_SEEDS", "/shared/libfuzzer/crashing"),
            "benign_seeds": os.environ.get("ARTIPHISHELL_LIBFUZZER_BENIGN_SEEDS"),
            "fuzzer_sync_path": os.environ.get("ARTIPHISHELL_FUZZER_SYNC_PATH"),
            "fuzzing_log": os.environ.get("ARTIPHISHELL_LIBFUZZER_FUZZING_LOG", "/tmp/fuzzer.log"),
        }

        log.debug(f"🔎 Environment Variables Loaded: {env_vars}")
        try:
            return cls(**env_vars) 
        except ValidationError as e:
            log.error(f"❌ Environment variable validation failed! {e}")


# -----------------------------------
# 🔹 Abstract Base Fuzz Class
# -----------------------------------

class libFuzzerFuzz(ABC):
    def __init__(self, cli_args: List[str]):
        log.debug(f"Initializing {self.__class__.__name__} with args: {cli_args}")
        self.cli_args = cli_args

        # Load configurations
        self.fuzzing_environment_config = self.load_fuzzing_environment_config()
        
        updated_fuzzer_args = self.update_fuzzer_args()
        self.mandatory_args, self.optional_args = updated_fuzzer_args.get("mandatory", {}), updated_fuzzer_args.get("optional", {})
        log.debug(f"Loaded libFuzzer configs! with updated args: {updated_fuzzer_args}")


    def load_fuzzing_environment_config(self) -> FuzzingEnvironmentConfig:
        """Load libfuzzer specific configuration directly from environment variables"""
        try:
            config = FuzzingEnvironmentConfig.load_from_env()
            return config
        except ValidationError as e:
            log.error(f"❌ Fatal error: Missing required environment variables: {e} ::\n{config}")
        return config

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
        """Applies updates to both LibFuzzer configurations and returns only updated fields."""

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
                cli_args_dict[key] = optional_args[key]

        return cli_args_dict, seeds_dirs


    def build_args(self, additional_seeds_args: Optional[List[str]] = None, min_optional_args: int = 1, max_optional_args: int = 1) -> List[str]:
        """Build final fuzzing argument list, ensuring correct updates and handling additional seed directories."""
        # Always copy agent if path is set

        log.debug("Building fuzzer arguments")
        selected_args, detected_benign_seeds_dir = self.add_or_update_fuzzer_cli_args(min_optional_args, max_optional_args)
        final_args = [f"{key}={value}" if not isinstance(value, bool) else key for key, value in selected_args.items()]

        if additional_seeds_args:
            log.debug(f"📂 Adding additional seed directories: {additional_seeds_args}")
            final_args.extend(additional_seeds_args)

        log.debug(f"Final fuzzer args: {final_args}")
        return final_args

    def run_libfuzzer(self, args: List[str], job_name: str) -> str:
        """Run libFuzzer with the given arguments"""
        try:
            log.debug(f"Starting {job_name} libFuzzer!")
            #TODO: probably nothing?
            fuzzing_args = [f"{sys.argv[0]}.instrumented"] + args
            
            # Prepare script
            fuzz_script = f'''#!/bin/bash
            set -x
            mkdir -p {self.fuzzing_environment_config.out_dir}
            

            # snapshot any pre-existing log
            if [[ -f "{self.fuzzing_environment_config.fuzzing_log}" ]]; then
                mv "{self.fuzzing_environment_config.fuzzing_log}" "{self.fuzzing_environment_config.fuzzing_log}.$(date +%d%H%M%S)"
            fi
            
            # nohup bash /work/auto_kill.sh > /work/tmpkill_{job_name}.log & 
            {" ".join(str(x) for x in fuzzing_args)}

            '''

            script_path = Path(self.fuzzing_environment_config.out_dir, f"fuzz_{job_name}.sh")
            with open(script_path, "w") as f:
                f.write(fuzz_script)
            log.debug(f"Created fuzzing script at: {script_path} and fuzzing args: {fuzzing_args}")
            
            # Execute
            os.system(f'chmod +x {script_path}')
            replica_id = os.environ.get("REPLICA_ID")
            log.debug(f"Replica ID: {replica_id}")
            if replica_id and 1 <= int(replica_id) <= 8:
                os.system(f'/bin/bash {script_path} 2>&1 | tee {self.fuzzing_environment_config.fuzzing_log}')
            else:
                os.system(f'/bin/bash {script_path}')
            
            # Lets check if we have injected seeds, if so we copy thme into the crashes dir
            if os.path.exists("/shared/injected-seeds"):
                log.debug(f"We have crashing seeds, copying injected seeds to {self.fuzzing_environment_config.crashing_seeds}")
                os.system(f'cp -r /shared/injected-seeds/. {self.fuzzing_environment_config.fuzzer_sync_path}/libfuzzer-minimized/crashes/')
            


        except Exception as e:
            log.error(f"Error running libFuzzer: {e}", exc_info=True)
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

class VanillaFuzz(libFuzzerFuzz):
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

        self.fuzzing_environment_config.crashing_seeds.mkdir(exist_ok=True, parents=True)
        libfuzzer_updates = {
            "mandatory": {
                "verbosity": 2,
                "reload": 200,
                "fork": 1,
                "fork_corpus_groups": 1,
                "ignore_crashes": 1,
                "artifact_prefix": f'{self.fuzzing_environment_config.crashing_seeds}/',
            },
            "optional": {
                "fuzzer_dict": self.fuzzing_environment_config.codeql_strings_dict,
                "use_value_profile": 1,
            }
        }

        return {"libfuzzer": libfuzzer_updates}

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
                additional_seeds_args.append(f'{self.fuzzing_environment_config.fuzzer_sync_path}/libfuzzer-minimized/queue/')

                # Sync seeds from other components
                corpusguy_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy" / "queue"
                kickstarter_corpus = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-kickstart" / "queue"
                corpus_guy_kickstart_crashes_path = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-kickstart-crashes" / "queue"
                permanence_corpus = self.fuzzing_environment_config.fuzzer_sync_path / "sync-corpusguy-permanence" / "queue"
                disco_guy_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-discoguy" / "queue"

                # ggs
                sync_grammar_agent_explorer_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammar-agent-explore" / "queue"
                sync_grammar_guy_fuzz_path = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammar-guy-fuzz" / "queue"
                sync_grammarroomba = self.fuzzing_environment_config.fuzzer_sync_path / "nonsync-grammarroomba" / "queue"

                corpus_collection = [corpusguy_path, kickstarter_corpus, corpus_guy_kickstart_crashes_path, permanence_corpus,
                sync_grammar_agent_explorer_path, sync_grammar_guy_fuzz_path, sync_grammarroomba, disco_guy_path]

                for path in corpus_collection:
                    path.mkdir(parents=True, exist_ok=True)
                    additional_seeds_args.append(str(path))

                # directories matching "sync-grammar-agent-explore-* because we can have N number of replicas"
                # for agent_dir in self.fuzzing_environment_config.fuzzer_sync_path.glob("sync-grammar-agent-explore-*"):
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
            self.run_libfuzzer(final_args, "vanilla_fuzz")

        except Exception as e:
            log.error(f"Error in vanilla fuzzing: {e}", exc_info=True)
            raise


# --------------------------------------
# 🔹 Fuzzing Modes - Targeted Fuzzing
# --------------------------------------

class TargetedFuzz(VanillaFuzz):
    """TargetedFuzz """
    
    def __init__(self, cli_args: List[str]):
        super().__init__(cli_args)
    
    def get_updated_args_for_fuzzer(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Returns specific LibFuzzer args for VanillaFuzz."""

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
        """Returns specific LibFuzzer args for VanillaFuzz."""
        return {}, {}

    def run(self):
        try:
            log.debug("Starting CrashExploration run")
            # TODO: Implement CrashExploration
            pass
            
        except Exception as e:
            log.error(f"Error in CrashExploration: {e}", exc_info=True)
            raise

class LibfuzzerFactory:
    @staticmethod
    def create(mode: str, cli_args: List[str]):
        """Create appropriate wrapper based on mode"""
        log.debug(f"Creating Libfuzzer wrapper for mode: {mode}")

        modes = {
            'fuzz': [VanillaFuzz],
            # 'crash_explore': [CrashExploration],
            # 'run_pov': [RunPovFuzz]
        }

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
        log.debug(f"Existing Libfuzzer args: {sys.argv[1:]}")
        # mode = os.getenv('MODE')
        mode = "fuzz"

        wrapper = LibfuzzerFactory.create(mode, sys.argv[1:])
        wrapper.run()
        
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
