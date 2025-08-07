from pathlib import Path
import unittest
import os
import logging
from git import Repo
import subprocess
from typing import Optional
from QuickSeed.data import Program
from QuickSeed.parser import TaintParser, CoverageAnalysis
from QuickSeed.utils import setup_aicc_target
TESTDIR = Path(os.getcwd()) / "tests"
RESOURCE = TESTDIR / "resource"
HARNESS = RESOURCE / "harness_code"
TARGET = TESTDIR / "target"
import QuickSeed
from itertools import islice
_l = logging.getLogger("QuickSeed")
_l.setLevel(logging.DEBUG)

class TestQuickSeed(unittest.TestCase):
    # def test_harness_analyzer(self):
    #     # TODO: rewrite this harness test
    #     harness_path = HARNESS / "jenkins_backdoor/JenkinsTwo.java"
    #     print(TESTDIR)
    #     model = 'gpt-4o'
    #     # target_dir = setup_aicc_target(
    #         # "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git", RESOURCE, TARGET)
    #     target_dir = Path(os.path.dirname(__file__)) / "target/targets-semis-aixcc-sc-challenge-002-jenkins-cp"
    #     resource_dir=RESOURCE
    #     dict = {
    #         "src_root": target_dir / "src/plugins/pipeline-util-plugin",
    #         "report": resource_dir / "taint_report.txt"
    #     }
    #     program = Program(**dict)
    #     analyze_harness_code(
    #         harness_path, 
    #         model, 
    #         program, 
    #         resource_dir / "json_output_dirs/jenkins" , 
    #         resource_dir / "function_indices.json",
    #         resource_dir / "jazzer_sanitizer.json"
    #         )
    def test_interesting_poi_analyzer(self):
        # target_dir = setup_aicc_target(
        #     "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git",
        #     RESOURCE,
        #     TARGET
        # )
        target_dir = Path(os.path.dirname(__file__)) / "target/jenkins_cp_promax"
        resource_dir=RESOURCE
        dict = {
            "src_root": target_dir / "src/plugins/pipeline-util-plugin",
            "report": resource_dir / "deserialize.txt"
        }
        func_indices = resource_dir / 'deserialize_function_indices.json'
        func_json_dir = resource_dir / 'deserialize_json_output_dir'
        program = Program(**dict)
        taint_parser = TaintParser(program, resource_dir / "json_output_dirs/jenkins" , resource_dir / "function_indices.json")
        taint_parser.visualize_graph()
        source_id = 0
        sink_id = 1
        func_indices = resource_dir / 'function_indices.json'
        func_json_dir = resource_dir / 'json_output_dirs/jenkins'
        interesting_pois = []
        sources, sinks = taint_parser.retrive_source_sink_from_callgraph()
        source_id = sources[0]
        sink_id = sinks[0]
        print(f"sources are {sources}, sinks are {sinks}")
        for path in taint_parser.retrieve_call_graph_for_llm(source_id , sink_id):
            print("A new path generate from source to sink")
            print([p.callable for p in path])
            interesting_pois = analyze_interesting_pois( "gpt-4o", path, func_indices, func_json_dir)
            break
        assert len(interesting_pois) > 0




    def test_taint_parser(self):
        # target_dir = setup_aicc_target(
            # "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git",
            # RESOURCE,
            # TARGET
        # )
        target_dir = Path(os.path.dirname(__file__)) / "target/targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        resource_dir=RESOURCE
        program_info = {
            "src_root": target_dir / "src/plugins/pipeline-util-plugin",
            "report": resource_dir / "taint_report.txt"
        }
        program = Program(**program_info)
        taint_parser = TaintParser(program)

        taint_parser.visualize_graph()

    def test_taint_parser_with_target(self):
        # target_dir = setup_aicc_target(
            # "https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp.git",
            # RESOURCE,
            # TARGET
        # )
        target_dir = Path(os.path.dirname(__file__)) / "target/targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        resource_dir=RESOURCE
        dict = {
            "src_root": target_dir / "src/plugins/pipeline-util-plugin",
            "report": resource_dir / "taint_report.txt"
        }
        program = Program(**dict)
        taint_parser = TaintParser(program, resource_dir / "json_output_dirs/jenkins" , resource_dir / "function_indices.json")
        taint_parser.visualize_graph()
        for node in taint_parser.nodes:
            _l.debug(f"The function source code is {node.func_src}")
            _l.debug(f"The function linetext is {node.linetext}")

        dict1 = {
            "src_root": target_dir / "src", # Not all  coed is in plugin
            "report": resource_dir / "fuzzer_flow.txt"
        }

        program = Program(**dict1)
        taint_parser = TaintParser(program, resource_dir / "json_output_dirs/jenkins" , resource_dir / "function_indices.json")
        taint_parser.visualize_graph()
        for node in taint_parser.nodes:
            _l.debug(f"The function source code is {node.func_src}")
            _l.debug(f"The function linetext is {node.linetext}")


    def test_print_coverage_results(self):


        test_directory_path = Path(os.path.dirname(__file__)) / "resource/jazzer_coverage"
        assert test_directory_path.exists()

        resource_dir=RESOURCE

        coverage_analyzer = CoverageAnalysis(directory_path=test_directory_path)
        coverage_analyzer.aggregate_coverage()
        individual_coverage_results = coverage_analyzer.get_individual_coverage()
        summary_results = coverage_analyzer.get_summary_coverage()
        
        _l.debug("\nIndividual File Line Coverage Results:")

        for coverage in islice(individual_coverage_results,10):
            _l.debug(f"file_name is {coverage.file_name}")
            _l.debug(f"coverage is {coverage.lines}")
            


        _l.debug("\nSummary of Coverage:")
        for f, details in summary_results.items():
            _l.debug(f"file name is {f}")
            _l.debug(f"details is {details}")
            break



    def test_call_graph_gen(self):
        target_dir = Path(os.path.dirname(__file__)) / "target/targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        resource_dir=RESOURCE
        dict = {
            "src_root": target_dir / "src",
            "report": resource_dir / "codeql_report.yaml"
        }
        program = Program(**dict)
        taint_parser = TaintParser(program, resource_dir / "json_output_dirs/jenkins" , resource_dir / "function_indices.json")
        taint_parser.visualize_graph()

        for node in taint_parser.nodes:
            _l.debug(f"next nodes of {node.id} is {node.next_nodes}")

    def test_find_shortest_path_taint_parser(self):
        target_dir = Path(os.path.dirname(__file__)) / "target/targets-semis-aixcc-sc-challenge-002-jenkins-cp"
        resource_dir=RESOURCE
        dict = {
            "src_root": target_dir / "src",
            "report": resource_dir / "command_injection_call_graph.json"
        }
        program = Program(**dict)
        taint_parser = TaintParser(program, resource_dir / "json_output_dirs/jenkins" , resource_dir / "function_indices.json")
        for node in taint_parser.nodes:
            if node.is_source and node.is_harness and node.funcname == "fuzzerTestOneInput":
                source_node = node
            if node.is_sink:
                sink_node = node
        _l.debug(f"This source node is {source_node.id}. The sink node is {sink_node.id}")
        path = taint_parser.find_shortest_path_bfs(source_node, sink_node)
        no_harness_path = taint_parser.cut_harness_from_path(path)
        print(no_harness_path)
        node_edge_info = taint_parser.retrieve_source_code_for_llm_from_path(no_harness_path)
        
        print(node_edge_info)
            
        for node in taint_parser.nodes:
            _l.debug(f"filepath of {node.id} is {node.filepath}")
            
            _l.debug(f"is harness is {node.is_harness}")
            _l.debug(f"source node is {node.funcname}")
            _l.debug(f"is_source is {node.is_source}")



