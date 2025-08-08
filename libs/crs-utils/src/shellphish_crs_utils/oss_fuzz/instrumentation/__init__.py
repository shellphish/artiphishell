


import abc
import os
from pathlib import Path
import re
from typing import Optional, TypeAlias

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

SUPPORTED_INSTRUMENTATIONS = {}

class Instrumentation(abc.ABC):

    # This is the name of the fuzzing engine to be used during building (by default).
    # The script named f"compile_{TOOL_NAME}" will be sourced in the environment before building.
    # This script must be copied in the Docker.builder to be available at building time.
    # NOTE: this is the default behavior if there is no alias (_internal_tool_replacement_alias) defined.
    #       in that case, the script name will be f"compile_{WHATEVER_IS_IN_THE_ALIAS}".
    # NOTE: before you use an alias, ask Lukas.
    def get_tool_name(self) -> str:
        return None


    # This is an alias for the tool name (see previous comment).
    # NOTE: This is useful for Java build systems that require a specific fuzzing engine names.
    def _internal_tool_replacement_alias(self) -> Optional[str]:
        return None

    # Customize the build context directory.
    def prepare_context_dir(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        # NOTE: EVERY instrumentation implementation must overload this function.
        assert False, "This function must be overloaded!"

    #####################################################################################################################
    ################################################### PREBUILDING #####################################################
    #####################################################################################################################
    # This is the name of the prebuild image. This should be passed to the Dockerfile.builder as an argument,
    # and can be used to copy data from the prebuild image to the builder image. This should generally include
    # any data that is not target-specific and can be built ahead of time.
    #
    # If the instrumentation does not have a prebuild image, this function should return None.
    #
    ########## WARNING WARNING WARNING
    # THIS SHOULD ONLY BE OVERLOADED AFTER TALKING TO LUKAS. THIS HAS FAR-REACHING CONSEQUENCES.
    # THIS IS NOT JUST A NAME.
    ########## WARNING WARNING WARNING
    #
    # NOTE: it is the instrumentation maintainer's responsibility to ensure that the prebuild image is up to date
    #       with the latest version of the OSS-fuzz base image.
    #       This is not done automatically.
    def get_prebuild_image_name(self, oss_fuzz_project: OSSFuzzProject) -> Optional[str]:
        # if no prebuild image is defined, return None
        if self.get_prebuild_dockerfile(oss_fuzz_project) is None:
            return None

        tool_name = self.get_tool_name()
        tool_name = tool_name.replace("_", "-")
        assert re.match(r"^[a-zA-Z0-9.-]+$", tool_name)
        return os.environ.get("DOCKER_IMAGE_PREFIX", "") + "oss-fuzz-instrumentation-prebuild-" + self.get_tool_name()

    # Return the path to the Dockerfile used to prebuild an image for this specific fuzzing
    # engine (i.e., Dockerfile.prebuild). This
    def get_prebuild_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None
    #####################################################################################################################

    # Return the path to the Dockerfile used to build this specific fuzzing engine (i.e., Dockerfile.builder)
    def get_builder_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None

    # Return the path to the Dockerfile used to run this specific fuzzing engine (i.e., Dockerfile.runner)
    def get_runner_dockerfile(self, oss_fuzz_project: OSSFuzzProject) -> Path:
        return None

    # ========================================================================
    # THE FOLLOWING FUNCTIONS MUST NOT BE OVERLOADED!
    # NOTE: if you need for any reasons to overload them, please ask Lukas.
    # ========================================================================

    # Just a helper function to see if the alias replace an existing oss-fuzz fuzzing engine.
    # NOTE: you need to use this ONLY if you are using aliases.
    # NOTE: This function should not be modified.
    def get_internal_tool_replacement_alias(self) -> Optional[str]:
        alias = self._internal_tool_replacement_alias()
        assert alias in [None, 'libfuzzer', 'afl', 'honggfuzz', 'centipede', 'coverage', 'none']
        return alias

    # Just a helper function.
    # NOTE: This function should not be modified.
    def get_fuzzing_engine_name(self) -> str:
        return self.get_internal_tool_replacement_alias() or self.get_tool_name()

    def post_build(self, oss_fuzz_project: OSSFuzzProject) -> None:
        # NOTE: This function should not be modified.
        pass

def supported_instrumentation(cls):
    global SUPPORTED_INSTRUMENTATIONS
    assert issubclass(cls, Instrumentation)
    SUPPORTED_INSTRUMENTATIONS[cls().get_tool_name()] = cls()
    return cls

from . import aflpp
from . import aflrun
from . import benzene
from . import codechecker
from . import codeql
from . import jazzer
from . import clang_indexer
from . import griller
from . import griller_flag
from . import builtins
from . import coverage_fast
from . import dyva
from . import aijon
from . import discoveryguy
from . import shellphish_libfuzzer

LosanInstrumentation: TypeAlias = jazzer.JazzerInstrumentation
