import cProfile
from collections import defaultdict
import logging
from pathlib import Path
import time
from typing import List, Set, Tuple, Union, Dict
from lxml import etree
from coveragelib.parsers import LineCoverageParser
from coveragelib.parsers.utils import ParsingError
from shellphish_crs_utils.models.coverage import CoverageLine, FileCoverageMap
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.symbols import SourceLocation
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from coveragelib.parsers.utils import parse_html_report
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, safe_decode_string

import yaml

log = logging.getLogger(__name__)

class C_LineCoverageParser_LLVMCovHTML(LineCoverageParser):
    LANGUAGES = [LanguageEnum.c, LanguageEnum.cpp]
    HAS_INTERNAL_COMMAND = True
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    def __init__(self, no_parsing=False):
        self.HAS_VALUE_PARSER = not no_parsing

    def __str__(self):
        return "LLVMCovHTMLCoverageReportParser"
    
    def parse(self, coverage_path):
        assert False
    
    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Union[Path, str]) -> FileCoverageMap:
        with open(coverage_path, "rb") as infile:
            html_report = safe_decode_string(infile.read())
        return parse_html_report(html_report)

    def get_internal_cmd(self, extra_vars=None):
        current_harness = extra_vars['harness_name']
        target_dir = extra_vars['target_dir']
        return f"llvm-cov show /out/{current_harness} -format=html -instr-profile=/out/dumps/merged.profdata --path-equivalence=\"/,{target_dir}/artifacts/out\" > /out/dumps/merged.profdata.processed"
    

def java_parse_line_coverage_report(coverage_path: Path) -> FileCoverageMap:
    coverage_path = Path(coverage_path) # just to be sure
    # Parse the XML file
    tree = etree.parse(coverage_path)
    line_nodes = tree.xpath('//sourcefile[counter[@type="LINE" and @covered>0]]/line')
    cov_lines: CoverageLine = defaultdict(list)
    for line in line_nodes:
        assert set(line.attrib.keys()) == {"nr", "mi", "ci", "mb", "cb"}
        
        sourcefile_node = line.getparent()
        assert sourcefile_node.tag == "sourcefile"
        assert set(sourcefile_node.attrib.keys()) == {"name"}

        package_node = sourcefile_node.getparent()
        assert package_node.tag == "package"
        assert set(package_node.attrib.keys()) == {"name"}

        line_no = int(line.attrib['nr'])
        # missed_instructions = int(line.attrib['mi'])
        covered_instructions = int(line.attrib['ci'])
        # missed_branchs = int(line.attrib['mb'])
        # covered_branchs = int(line.attrib['cb'])

        path = Path(package_node.attrib['name']) / sourcefile_node.attrib['name']
        cov_lines[path].append(CoverageLine(
            line_number=line_no,
            count_covered=covered_instructions,
            # count_missed=missed_instructions,
            # count_branches_covered=covered_branchs,
            # count_branches_missed=missed_branchs,
            # code=None
        ))
    return cov_lines

def logging_java_parse_line_coverage_report(coverage_path: Path) -> FileCoverageMap:
    start_time = time.time()
    cov_lines = java_parse_line_coverage_report(coverage_path)
    end_time = time.time()
    num_lines_total = sum(len(lines) for lines in cov_lines.values())
    log.info(f"Parsed {len(cov_lines)} files with {num_lines_total} lines in {end_time - start_time:.2f} seconds")
    return cov_lines

class Java_LineCoverageParser_Jacoco(LineCoverageParser):
    HAS_INTERNAL_COMMAND = False
    HAS_EXTERNAL_PROCESSING = False
    HAS_VALUE_PARSER = True

    LANGUAGES = [LanguageEnum.jvm]

    def parse_values(self, oss_fuzz_project: OSSFuzzProject, coverage_path: Path) -> FileCoverageMap:
        log.info(f"Parsing coverage @ {coverage_path}")

        try:
            return logging_java_parse_line_coverage_report(coverage_path)
        except Exception as e:
            log.exception(f" 🤡 Error while parsing XML: {e}")
            raise ParsingError(f"Error while parsing XML")

def cli_main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("report_path", type=str)
    parser.add_argument('--language', type=LanguageEnum, default="c", choices=["c", "c++", "jvm"])
    parser.add_argument("--oss-fuzz_project", type=Path, default=None)
    parser.add_argument('--output', type=Path, default=None)
    parser.add_argument('--print', action='store_true', help="Print the coverage report")
    args = parser.parse_args()
    if args.language == "c" or args.language == "c++":
        parser = C_LineCoverageParser_LLVMCovHTML()
    elif args.language == "jvm":
        parser = Java_LineCoverageParser_Jacoco()
    else:
        raise NotImplementedError(f"Language {args.language} not implemented")
    
    project = OSSFuzzProject(args.oss_fuzz_project) if args.oss_fuzz_project else None
    line_coverage = parser.parse_values(project, args.report_path)
    if args.output:
        with open(args.output, "w") as outfile:
            yaml.safe_dump({str(p) : [tuple(l) for l in v] for p, v in line_coverage.items()}, stream=outfile)
    if args.print:
        print(yaml.safe_dump({str(p) : [tuple(l) for l in v] for p, v in line_coverage.items()}))

if __name__ == '__main__':
    # cProfile.run('cli_main()', 'line_coverage.prof')
    cli_main()