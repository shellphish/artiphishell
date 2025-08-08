# BASE IMPORTS
import os
import logging
import time 
from pprint import pprint 
from collections import defaultdict
from typing import Iterator
from grammar_guy.common.utils import set_up_webview, is_covered_function, check_token_limit

# GRAMMAR GUY IMPORTS
from grammar_guy.common import config
from grammar_guy.gg.antique import build_grammar_corpus
from grammar_guy.common.agents.report_agent import setup_report_agent
from grammar_guy.gg.antique import check_grammar, evaluate_grammar_coverage, move_files_to_afl_dir, clear_input_directory, update_grammar_dict
# CRS IMPORTS
from shellphish_crs_utils.sarif_resolver import *
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.coverage import FunctionCoverageMap
from crs_telemetry.utils import init_otel, init_llm_otel, get_otel_tracer, status_ok

# AGENTLIB IMPORTS
from agentlib.lib.common import LLMApiBudgetExceededError
from agentlib import enable_event_dumping, set_global_budget_limit

# ANALYSIS GRAPH IMPORTS
from analysis_graph.api.dynamic_coverage import register_grammar_function_coverage

init_otel("grammar-guy-sarif", "input-generation", "llm_grammar_generation")
init_llm_otel()
tracer = get_otel_tracer()

# SET LOGGING LEVEL
log = logging.getLogger("grammar_guy_sarif")
log.setLevel(logging.INFO)
## Key on sarif_meta.project_id
def get_codeflow_location_reports(location_map: dict):
    ''' Gets reports for all locations in a code flow.
    :param location_map: dict[location: FUNCTION_INDEX_KEY] mapping locations to function keys
    :return: dict[location: report] mapping aggregated location to report.
    '''
    assert isinstance(location_map, dict), "location_map must be a dictionary"
    assert len(location_map['aggregated_locations']) > 0, "location_map cannot be empty"

    location_agent = setup_report_agent(system_prompt_template='location.system.j2', user_prompt_template='location.user.j2')
    report_dict = defaultdict(dict)
    # store reports for all locations in the codeflow
    # dump the location_map to a file and print path 
    with open(config.stats_dir() / "location_map.json", 'w') as f:
        import json
        json.dump(location_map, f, indent=4)
        pprint(f"Saved location map {str(config.stats_dir() / 'location_map.json')}")

        aggregated_locations = location_map['aggregated_locations']
        for function_key, function_entry in aggregated_locations.items():
            # Somehow get the source code of the function at location
            input_dict = dict(
                            rule_id = location_map['rule_id'],
                            message = location_map['message'],
                            short_description = location_map['short_description'],
                            long_description = location_map['long_description'],
                            resolved_location = function_key,
                            resolved_location_source = function_entry['function_source'],
                            lines_of_interest = ', '.join(str(function_entry['lines'])),
            )
            if check_token_limit(input_dict.values()): 
                log.warning("Input dictionary is too large. Waiting for 1 minute before retrying.")
                break
            
            while True:
                try: 
                    while config.get_new_report() is None:
                        location_agent.invoke(input=input_dict)
                except LLMApiBudgetExceededError:
                    log.error("LLM API budget exceeded. Waiting for 1 minute before retrying.")
                    time.sleep(60)
                except Exception as e:
                    log.error(f"An error occurred while generating report for {function_key}: {e}")
                    raise e
                break

            report_dict[function_key] = {
                'codeflow_id': location_map['flow_id'],
                'rule_id': location_map['rule_id'],
                'message': location_map['message'],
                'short_description': location_map['short_description'],
                'resolved_location': function_key,
                'resolved_location_source': function_entry['function_source'],
                'lines_in_location': ', '.join(str(function_entry['lines'])),
                'report': config.get_new_report()
            }
            config.log_event("generate_code_flow_location_report", config.get_new_report())
            config.set_new_report(None)
            # pprint(f"Generated report for {function_key}: {report_dict[function_key]['report']}")
    return report_dict

def store_report_and_grammar(codeflow_location_report: str, grammar: str, codeflow: SarifCodeFlow):
    assert codeflow_location_report is not None, "Code flow location report cannot be None"
    assert grammar is not None, "Grammar cannot be None"
    assert codeflow is not None, "Code flow cannot be None"
    # Time in dd:mm:hh:mm:ss format
    time_str = time.strftime("%d:%m:%H:%M:%S", time.gmtime())
    os.makedirs(str(config.FUZZER_SYNC_DIR / "sarif-report-dude"), exist_ok=True)
    with open(str(config.FUZZER_SYNC_DIR / "sarif-report-dude" / f"{codeflow.code_flow_id}_report_{time_str}.md"), 'w') as f:
        f.write(codeflow_location_report)
        pprint(f"🏳️‍🌈 Saved codeflow {codeflow.code_flow_id} report for {len(codeflow.locations)} "
            f"locations to {config.FUZZER_SYNC_DIR / 'sarif-report-dude' / f'{codeflow.code_flow_id}_report_{time_str}.md'}")
        time.sleep(1)

    with open(str(config.FUZZER_SYNC_DIR / "sarif-report-dude" / f"{codeflow.code_flow_id}_grammar_{time_str}.txt"), 'w') as f:
        f.write(grammar)
        pprint(f"🏳️‍🌈 Saved codeflow {codeflow.code_flow_id} grammar to "
               f'{config.FUZZER_SYNC_DIR / "sarif-report-dude" / f"{codeflow.code_flow_id}_grammar_{time_str}.txt"}')

def format_report(entry: dict):
    ''' Formats a report entry into a string.
    :param entry: dict containing location, function_name, function_source, and report
    :return: formatted report string
    '''
    assert entry is not None, "entry cannot be None"
    assert isinstance(entry, dict), "entry must be a dictionary"
    assert 'codeflow_id' in entry, "entry must contain 'codeflow_id'"
    assert 'resolved_location' in entry, "entry must contain 'function_name'"
    assert 'resolved_location_source' in entry, "entry must contain 'function_source'"
    assert 'report' in entry, "entry must contain 'report'"

    code_flow_id = entry['codeflow_id']
    resolved_location = entry['resolved_location']
    resolved_location_source = entry['resolved_location_source']
    report = entry['report']
    
    return f'''
# START OF FUNCTIONR REPORT FOR {resolved_location} IN CODEFLOW {code_flow_id}
## FUNCTION NAME: {resolved_location}

## FUNCTION SOURCE:

```
{resolved_location_source}
```

## REPORT:

{report}
---
'''

def build_codeflow_location_report(codeflow, location_map: dict, message='', short_description=''):
    ''' Builds a grammar for a code flow.
    :param codeflow: the code flow to build the grammar for
    :return: the formatted list of reports to feed to llm bro
    '''
    assert codeflow is not None, "Code flow cannot be None"
    assert location_map['aggregated_locations'] is not None, "Location map must contain 'locations' key"

    report_dict: dict = get_codeflow_location_reports(location_map)
    formatted_reports = []
    for function_name, entry in report_dict.items():
        # -- Do something with the location reports --
        formatted = format_report(entry)
        assert type(formatted) is str, "Formatted report must be a string"
        formatted_reports.append(formatted) 
    
    pprint(f'Lenght of formatted reports: {len(formatted_reports)}')
    return '\n'.join(formatted_reports)

def aggregate_locations(locations: Iterator[FUNCTION_INDEX_KEY]) -> dict:
    ''' Aggregates locations into a dictionary.
    :param locations: an iterator of FUNCTION_INDEX_KEY objects
    :param location_keys: a list of location keys to aggregate
    :return: a dictionary aggregating lines for their keys. 
    '''
    assert isinstance(locations, list), "locations must be an iterator"
    assert len(locations) > 0, "locations cannot be empty"
    # Aggregates locations by their keys. Collects lines for each key
    aggregated_locations = {} # key: [line, line, line]
    for loc in locations:
        if loc.keyindex not in aggregated_locations:
            aggregated_locations[loc.keyindex] = {
                'function_name': loc.func,
                'function_source': config.FUNCTION_RESOLVER.get_code(loc.keyindex)[-1],
                'lines': [loc.line],
            }
        else: 
            assert loc.keyindex in aggregated_locations.keys(), f"Location key {loc.keyindex} not found in aggregated locations"
            aggregated_locations[loc.keyindex]['lines'].append(loc.line)
    return aggregated_locations

def check_sink_hit(fun_cov_map: FunctionCoverageMap, codeflow: SarifCodeFlow) -> bool:
    ''' Checks if a sink was hit in the code flow.
    :param fun_cov_map: a map of function coverage
    :param codeflow: the code flow to check
    :return: boolean indicating whether sink was hit
    '''
    assert fun_cov_map is not None, "Function coverage map cannot be None"
    assert codeflow is not None, "Code flow cannot be None"
    hit = False
    sink = codeflow.locations[-1].keyindex
    if sink in fun_cov_map.keys():
        if is_covered_function(fun_cov_map[sink]):
            log.info(f"Sink {sink} was hit in code flow {codeflow.code_flow_id}.")
            hit = True
            # Register the coverage in the analysis graph
        else:
            log.warning(f"Sink {sink} was not hit in code flow {codeflow.code_flow_id}.")
    return hit

def build_sarif_grammars():
    ''' Builds grammars for SARIF mode, which is a special mode for grammar guy.
    :return: None
    '''
    grammar_dict = defaultdict(list) # make defaultdict to list
    grammar_coverage: Dict[str, FunctionCoverageMap] = dict() # maps grammars to the coverage they hit
    sarif_tuples : List[tuple]= []
    for sarif_report in os.listdir(config.SARIF_PATH):
        sarif_path = config.SARIF_PATH / sarif_report
        sar_resolver: SarifResolver = SarifResolver(sarif_path, config.FUNCTION_RESOLVER)
        if sar_resolver.is_valid():
            # Report and Resolver
            sarif_tuples.append((sarif_report, sar_resolver))
        else: 
            log.error(f"Invalid SARIF report: {sarif_path}. Skipping.")
            continue

    log.info("📝 Building grammars for SARIF mode")
    while True:
        for sarif_tup in sarif_tuples:
                short_description = "Not provided!"
                long_description =  "Not provided!"
                message = "Not provided!"

                log.info(f"📖 Processing SARIF report {sarif_tuples.index(sarif_tup)} / {len(sarif_tuples)}")
                report_results = sarif_tup[1].get_results()
                if len(report_results) > 1:
                    log.error("🔥🔥 More than 1 result in the SarifResolver. This WILL CAUSE PROBLEMS 🔥🔥")
                result = sarif_tup[1].get_results()[0]
                if len(result.codeflows) == 0 or len(result.locations) == 0:
                    log.warning(f"Skipping SARIF result {result.rule_id} with no code flows or locations.")
                    continue
                # ---- Information from the result object
                if result.message != '':
                    message = result.message
                rule_id = result.rule_id
                # ---- Information from the rule object
                sarif_rule = result.sarif_rule
                if sarif_rule is not None:
                    if sarif_rule.short_description != '':
                        short_description = sarif_rule.short_description
                    if sarif_rule.long_description != '':
                        long_description = sarif_rule.long_description                    

                log.info(f"💭 Generating grammar for SARIF result:\n \
                          Message: {result.message} \n Short Description: {short_description}")
                
                # ---- Going through the codeflows one at a time.
                for codeflow in result.codeflows: 
                    if codeflow is not None and codeflow.locations is not None and len(codeflow.locations) > 0:
                        log.info(f"💭 Generating grammar for codeflow {result.codeflows.index(codeflow)} / {len(result.codeflows)} codeflows in result")
                        aggregated_locations = aggregate_locations(codeflow.locations)
                        # -- Build grammar for code flow --
                        location_map = {
                                        'flow_id': codeflow.code_flow_id,
                                        'message': message,
                                        'rule_id': rule_id,
                                        'short_description': short_description,
                                        'long_description': long_description,
                                        'aggregated_locations': aggregated_locations,
                                        }
                        codeflow_location_report = build_codeflow_location_report(codeflow, location_map)
                        grammar = generate_grammar_from_report(codeflow_location_report)
                        store_report_and_grammar(codeflow_location_report, grammar, codeflow)
                        broken_grammar = True
                        fix_ct = 0
                        while broken_grammar:
                            fix_ct += 1
                            if fix_ct >= 6:
                                log.error("❌ Grammar is broken, but cannot be fixed. Breaking codeflow loop.")
                                break
                            broken_grammar = check_grammar(grammar)
                            if broken_grammar is None:
                                log.warning("💭 Grammar is broken, regenerating grammar.")
                                continue
                            else: 
                                # set grammar to now valid grammar and exit for loop
                                log.info("✅ Grammar is valid, proceeding to build corpus.")
                                grammar = broken_grammar 
                                broken_grammar = False
                        
                        # generate input data
                        fun_cov_map = evaluate_grammar_coverage(grammar)
                        if update_grammar_dict(grammar_dict, grammar_coverage, grammar, fun_cov_map) or check_sink_hit(fun_cov_map, codeflow):
                            log.info(f"✅ Grammar {grammar} is valid and has coverage or hit sink. Adding to grammar dict.")
                            register_grammar_function_coverage(
                                config.HARNESS_INFO_ID,
                                config.HARNESS_INFO,
                                grammar_type='nautilus-python',
                                grammar=grammar,
                                cov=fun_cov_map,
                            )
                        move_files_to_afl_dir(config.generated_inputs_path())
                        clear_input_directory()
                        print(f'AFL inputs moved to {config.generated_inputs_path()}')
                    else:
                        try:
                            clear_input_directory()
                        except Exception as e:
                            log.error(f"An error occurred while clearing input directory: {e}")
                        log.warning(f"Code flow {codeflow.code_flow_id} has no locations. Skipping.")

def generate_grammar_from_report(codeflow_location_report: str):
    # check grammar
    assert codeflow_location_report is not None, "Code flow location report cannot be None"
    
    codeflow_grammar_agent = setup_report_agent('codeflow_grammar.system.j2', 'codeflow_grammar.user.j2')
    input_dict = dict(
                    harness_source = config.get_harness_src(),
                    reports = codeflow_location_report,
                )
    while check_token_limit(input_dict.values()):
        # Remove the input dictionary to fit the token limit
        input_dict['reports'] = input_dict['reports'][:190000]
    
    while True:
        try: 
            while config.get_new_report() is None:
                codeflow_grammar_agent.invoke(input=input_dict)
            grammar = config.get_new_report()
            config.set_new_report(None)
            return grammar
        except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded. Waiting for 1 minute before retrying.")
                time.sleep(60)
        except Exception as e:
            log.error(f"An error occurred while generating grammar: {e}")
            raise e

def grammar_guy():
    # -- all the modules for grammar guy being called --
    if config.SARIF_MODE:
        build_sarif_grammars()
    else: 
        raise ValueError("SARIF mode is not enabled. Please enable SARIF mode to run this function.")

def main():
    set_up_webview()
    grammar_guy()
    import sys; sys.exit(0)

if __name__ == "__main__":
    config.parse_config_from_args()
    logging.basicConfig(level=logging.WARNING)

    enable_event_dumping(str(config.stats_dir()))
    # TODO Update the budget here (NOT RUNNING IN FINAL SYSTEM)
    set_global_budget_limit(
        price_in_dollars=10,
        exit_on_over_budget=True,
        lite_llm_budget_name='grammar-budget'
    )

    with tracer.start_as_current_span("grammar_guy_sarif") as span:
        with config.launch_coverage_tracer():
            main()
        span.set_status(status_ok())
#--------------------------- ---------------------------------------------------------- #