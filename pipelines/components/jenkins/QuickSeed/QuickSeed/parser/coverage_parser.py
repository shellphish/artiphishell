from typing import Dict, List
from pydantic import BaseModel
import os
import glob
from lxml import etree
from collections import defaultdict, Counter
from itertools import islice
from pathlib import Path

import logging

_l = logging.getLogger(__name__)

class FileCoverage(BaseModel):
    file_name: str
    lines: Dict[int, bool]

class CoverageAnalysis:
    def __init__(self, directory_path):
        self.directory_path = directory_path
        self.file_line_coverage = defaultdict(dict)
        self.coverage_count = defaultdict(Counter)
        self.total_seeds = 0
        self.all_report_packages = defaultdict(dict)
    

    def parse_xml(self, xml_path):
        with open(xml_path, 'r', encoding='UTF-8') as f:
            xml_data = f.read()

        tree = etree.XML(xml_data.encode())
        packages = tree.xpath(".//package")
        for pkg in packages:
            pkg_name = pkg.get('name')
            _l.debug(f'pkg_name is {pkg_name}')
                
            for sourcefile in pkg.findall('sourcefile'):
                file_name = sourcefile.get("name")
                full_name = f"{pkg_name}/{file_name}"
                line_elements = sourcefile.xpath(".//line")

                for line in line_elements:
                    line_number = int(line.get("nr"))
                    covered = int(line.get("ci")) > 0
                    self.file_line_coverage[full_name][line_number] = covered or self.file_line_coverage[file_name].get(line_number, False)
                    if covered:
                        self.coverage_count[full_name][line_number] += 1
                    else:
                        self.coverage_count[full_name][line_number] += 0
    

    def aggregate_coverage(self):
        xml_files = glob.glob(os.path.join(self.directory_path, '*'))
        self.total_seeds = len(xml_files)
        for xml_file in xml_files:
            self.parse_xml(xml_file)
    
    def get_individual_coverage(self) -> List[FileCoverage]:
        return [FileCoverage(file_name=f, lines=coverage) for f, coverage in self.file_line_coverage.items()]

    def get_summary_coverage(self) -> Dict[str, Dict[str, List[int]]]:
        summary = defaultdict(lambda: {'always_covered': [], 'always_missed': []})
        for file_name, counts in self.coverage_count.items():
            for line_number, count in counts.items():
                if count == self.total_seeds:
                    summary[file_name]['always_covered'].append(line_number)
                elif count == 0:
                    summary[file_name]['always_missed'].append(line_number)
        return summary

# coverage_analyzer = CoverageAnalysis('/home/ati/projects/aixcc/sss/QuickSeed/tests/resource/jazzer_coverage/')
# coverage_analyzer.aggregate_coverage()
# individual_coverage_results = coverage_analyzer.get_individual_coverage()
# summary_results = coverage_analyzer.get_summary_coverage()
# package_mappings = coverage_analyzer.get_package_mappings()


# # Print the results
# print("Individual File Line Coverage Results:")
# for coverage in individual_coverage_results:
#     assert coverage.file_name=='UtilMain.java'
#     assert list(coverage.lines.keys())[0] == 64

# print("\nSummary of Coverage:")
# for file, details in summary_results.items():
#     print(f"{file} - Always Covered Lines: {details['always_covered']}")
#     print(f"{file} - Always Missed Lines: {details['always_missed']}")
