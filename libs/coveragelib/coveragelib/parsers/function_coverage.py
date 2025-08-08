import html
import json
import os
from pathlib import Path
import tempfile
import time
from typing import List, Set, TypeAlias, Union

from lxml import etree

from coveragelib import Parser, log
from coveragelib.parsers import FunctionCoverageParser
from coveragelib.parsers.utils import ParsingError
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, safe_decode_string

class C_FunctionCoverageParser_Profraw(FunctionCoverageParser):

    LANGUAGES = [LanguageEnum.c, LanguageEnum.cpp]
    HAS_INTERNAL_COMMAND = True
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    def __init__(self):
        super().__init__()

    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Union[Path, str]):
        # The following code is meant to be executed after the oss-fuzz-coverage script ran to perform
        # further processing.

        coverage_path = Path(coverage_path)
        # Check if the file exists
        if not os.path.exists(coverage_path):
            raise ParsingError(f"Error while parsing coverage report at {coverage_path}")

        with open(coverage_path, "rb") as infile:
            content = safe_decode_string(infile.read())
            covered_functions = set(f.strip() for f in content.splitlines())

        return covered_functions

    def get_internal_cmd(self, extra_vars=None):
        # This command is executed within the target container.
        # The paths are the default ones used by the oss-fuzz-coverage script.
        return f"llvm-profdata show --covered --output /out/dumps/merged.profdata.processed /out/dumps/merged.profdata"
    
    def __str__(self):
        return "SimpleProfrawParser"

class Java_FunctionCoverageParser_Jacoco(FunctionCoverageParser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    LANGUAGES = [LanguageEnum.jvm]

    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Path) -> Set[SourceLocation]:
        coverage_path = Path(coverage_path) # just to be sure
        log.info(f"Parsing coverage @ {coverage_path}")

        start_time = time.time()
        try:
            # Parse the XML file
            tree = etree.parse(coverage_path)
            method_nodes = tree.xpath('//method[counter[@type="LINE" and @covered>0]]')
            covered_functions = set()
            for method_node in method_nodes:
                assert method_node.tag == "method"
                assert set(method_node.attrib.keys()) == {"name", "desc", "line"}

                class_node = method_node.getparent()
                assert class_node.tag == "class"
                assert set(class_node.attrib.keys()) == {"name", "sourcefilename"}

                package_node = class_node.getparent()
                assert package_node.tag == "package"
                assert set(package_node.attrib.keys()) == {"name"}

                package = package_node.attrib["name"].replace("/", ".") if package_node.attrib["name"] else None
                class_filename = class_node.attrib["sourcefilename"]
                class_path = class_node.attrib["name"].replace('/', '.')
                method_name = html.unescape(method_node.attrib["name"])
                descriptor = method_node.attrib["desc"]

                full_method_path = f'{class_path}.{method_name}'
                java_info = JavaInfo(
                    full_method_path=full_method_path,
                    package=package,
                    class_path=class_path,  # Convert the class name to a valid Java class path
                    class_name=class_path.split('.')[-1],
                    method_name=method_name,
                    package_prefix=None,
                    method_descriptor=descriptor,
                )

                source_file_path = f'{package_node.attrib["name"]}/{class_filename}' if package_node.attrib["name"] else None
                source_location = SourceLocation(
                    relative_path=source_file_path,
                    full_file_path=None,
                    file_name=class_filename,
                    function_name=method_name,
                    line_number=int(method_node.attrib["line"]),
                    raw_signature=full_method_path + descriptor,
                    function_index_key=None,
                    function_index_signature=None,
                    java_info=java_info,
                )
                covered_functions.add(source_location)

            end_time = time.time()
            log.info(f"Parsed {len(covered_functions)} functions in {end_time - start_time:.2f}s")
            # Write the covered functions to a file
            # with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix='.json') as outfile:
            #     out = '['
            #     for loc in covered_functions:
            #         out += loc.model_dump_json() + ','
            #     out = out[:-1] + ']'
            #     outfile.write(json.dumps(json.loads(out), indent=2))

            return covered_functions

        except Exception as e:
            log.exception(f" 🤡 Error while parsing XML: {e}")
            raise ParsingError(f"Error while parsing XML")
