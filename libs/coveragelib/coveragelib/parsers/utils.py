######## WARNING: this is implementation is extremely carefully optimized and profiled to perform best on llvm-cov HTML reports.
# DO NOT CHANGE the llvm-cov report generation unless you're extremely sure you know what you're doing. No guarantees are made for other types of reports.
# This is an extremely critical path for the performance of anything tracing coverage, especially coverage-guy which has to trace all seeds.


import html
from pathlib import Path
import logging
import re
import time
from typing import Iterator

from shellphish_crs_utils.models.coverage import CoverageLine, FileCoverage, FileCoverageMap
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, safe_decode_string

from lxml import etree

log = logging.getLogger(__name__)
log.setLevel(logging.CRITICAL)

# Precompile XPath expressions
XPATH_FILENAME = etree.XPath('/body/div/table/div[@class="source-name-title"]/pre/text()')
XPATH_ROWS = etree.XPath('/body/div/table//tr[td[@class="line-number"]]')

class ParsingError(Exception):
    pass


start_tag_split_cache = {}
end_tag_split_cache = {}
def strip_tag_known_working(html, start_tag, end_tag):
    split = html.split(start_tag)

    result = split[0]
    for v in split[1:]:
        if end_tag and end_tag in v:
            result += v.split(end_tag, 1)[1]
        else:
            result += v
    return result
def strip_tag_faster(html, start_tag, end_tag):
    # assert start_tag in html, f"Start tag {start_tag} not found in HTML"
    if start_tag not in html:
        return html
    split = html.split(start_tag)

    # result = ''.join([split[0]] + [v.split(end_tag, 1)[1] if end_tag and end_tag in v else v for v in split[1:]])
    end_tag_len = len(end_tag) if end_tag else 0
    result = split[0]
    # import ipdb; ipdb.set_trace()
    for v in split[1:]:
        v: str
        # import ipdb; ipdb.set_trace()
        if end_tag and ((idx := v.find(end_tag)) != -1):
            # import ipdb; ipdb.set_trace()
            result += v[idx + end_tag_len:]
        else:
            result += v
    return result

def strip_tag(html, start_tag, end_tag):
    # assert strip_tag_known_working(html, start_tag, end_tag) == strip_tag_faster(html, start_tag, end_tag), "Stripping tags not working properly"
    return strip_tag_faster(html, start_tag, end_tag)

def extract_code_from_pre(pre_element: etree._Element) -> str:
    """Extracts and reconstructs the full source code text from a <pre> element."""
    if pre_element.tag != 'pre':
        raise ValueError(f"Expected <pre> element, got {etree.dump(pre_element)}")

    # Use `.itertext()` for fast text extraction
    return html.unescape("".join(pre_element.itertext()))


def parse_cov_count(num_str: str) -> int:
    """Parses a coverage count from a string."""
    val = num_str
    if num_str.endswith('k'):
        val = float(num_str[:-1]) * 1000
    elif num_str.endswith('M'):
        val = float(num_str[:-1]) * 1000000
    elif num_str.endswith('G'):
        val = float(num_str[:-1]) * 1000000000
    elif num_str.endswith('E'):
        # NOTE: this seems to be a known error in coverage collection...
        val = float(num_str[:-1]) * 1_000_000_000_000_000_000
    return int(val)

def parse_row(row):
    assert len(row) >= 2, f"Expected at least 2 columns in row, found {len(row)} in {etree.dump(row)}"
    col_lineno, col_count = row[:2]
    line_number = int(col_lineno.text)
    if not len(col_count):
        return None
    count = parse_cov_count(col_count[0].text)
    return CoverageLine(line_number=line_number, count_covered=count)

def parse_single_html_coverage_report_fast(html: str) -> FileCoverage:
    """Parses a single HTML coverage report and extracts file coverage data."""
    tree = etree.fromstring(html)
    filename_nodes = XPATH_FILENAME(tree)
    if not filename_nodes:
        raise ValueError("Filename not found in coverage report.")
    filename = Path(filename_nodes[0].strip())
    lines = [v for v in (parse_row(row) for row in XPATH_ROWS(tree)) if v is not None]
    return filename, lines


regex_body = re.compile(r'<body>.*</body>', re.DOTALL)
regex_doctype = re.compile(r'<!doctype')
line_number_regex = re.compile("<a name='L\d+' href='#L\d+'><pre>(\d+)</pre></a>")

def parse_html_report_iter(html_report: str) -> Iterator[FileCoverage]:
    """Splits the HTML report into sections and parses each one iteratively."""
    # import ipdb; ipdb.set_trace()
    parse_times = []
    for i, report in enumerate(regex_doctype.split(html_report)[1:]):

        try:
            #print(f"Processing report {i}")
            report = '<!doctype' + report
            report_body_match = regex_body.search(report)
            if not report_body_match:
                raise ParsingError(f"Could not find <body> tag in HTML report. Report: {report}")
            report = report_body_match.group(0)

            # strip_start = time.time()
            # These expressions seem hard to parse for libxml because of the code decoding they have to do. Instead, just remove them as the code isn't
            # necessary for us to retrieve anymore since we don't get it from java anyways, so anyone using coverage has to get it from clang-indexer anyways.
            report = report.replace('jump to first uncovered line</a>)</pre></td></td>', 'jump to first uncovered line</a>)</pre></td>')
            report = report.replace("<pre>Source</pre></td></td>", "<pre>Source</pre></td>") # Known badness (assimp, March 14)
            
            if "</td></td>" in report:
                log.critical(f"Found double </td> in report {i}. This is a bug in the HTML report generation. Please report this to @degrigis.")
                log.critical(f"Offending Report: {report}")
                if artiphishell_should_fail_on_error():
                    # We want to see this during development, but not in production.
                    raise ParsingError(f"Found double </td> in report {i}. This is a bug in the HTML report generation. Please report this to @degrigis.")
                else:
                    # Yolo-patch.
                    report = report.replace("</td></td>", "</td>")
        
            report = strip_tag(report, "<div class='expansion-view'><div class='centered'><table>", "</table></div></div>")
            report = strip_tag(report, "<div class='expansion-view'><div class='source-name-title'><pre>Unexecuted instantiation: ", "</pre></div></div>")
            report = strip_tag(report, "<td class='code'>", "</td>")
            report = strip_tag(report, "<style", "</style>")
            # assert line_number_regex.sub(r"\1", report) == strip_tag(report, "<a name=", "<pre>").replace("</pre></a>", ''), "Line numbers not stripped properly"
            report = strip_tag(report, "<a name=", "<pre>").replace("</pre></a>", '')
            
            # with open('./reports/{}.html'.format(i), 'w') as f:
            #     f.write(report)
            parsed = parse_single_html_coverage_report_fast(report)
        
        except Exception as e:
            log.critical(f"Critical error while parsing report {i}: {e}")
            log.critical(f" - Offending Report content: {report}")
            if artiphishell_should_fail_on_error():
                raise Exception(f"Critical error while parsing report {i}: {e}")
            else:
                print(" --> Continuing to next coverage report...")
                continue

        yield parsed


def parse_html_report(html_report: str) -> FileCoverageMap:
    """Parses a full HTML report containing multiple coverage files."""
    start_time = time.time()
    result = {k: v for k, v in parse_html_report_iter(html_report)}
    print(f"Time taken to parse the HTML report: {time.time() - start_time:.4f}s")
    # import ipdb; ipdb.set_trace()
    return result
