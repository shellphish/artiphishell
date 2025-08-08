import unittest 
import pathlib
import agentlib
import sys
import os


class TestInteralFunctionality(unittest.TestCase):
    def setUp():
        os.makedirs("/tmp/grammar-guy-test/")
        self.assertTrue(os.path.exists("/tmp/grammar-guy-test/"), "Failed to create test directory.")
    
    def tearDown():
        os.rmdir("/tmp/grammar-guy-test/")
        self.assertFalse(os.path.exists("/tmp/grammar-guy-test/"), "Failed to remove test directory.")
        
    def sanity_check(self):
        print("Sanity checking InternalStuff.")
        self.assertTrue(True, "Sanity check failed")
        
class TestGrammarAndInputFunctionality(unittest.TestCase):
    
    def setUp():
        os.makedirs("/tmp/grammar-guy-test/")
        self.assertTrue(os.path.exists("/tmp/grammar-guy-test/"), "Failed to create test directory.")
    
    def tearDown():
        os.rmdir("/tmp/grammar-guy-test/")
        self.assertFalse(os.path.exists("/tmp/grammar-guy-test/"), "Failed to remove test directory.")
    
    def sanity_check(self):
        print("Sanity checking GrammarInputFunctionality.")
        self.assertTrue(True, "Sanity check failed")
        
    def test_split_grammar_from_message(self):
        from grammar_guy.utils import split_grammar_from_message
        grammar = "Dis is some stupid ass text before the grammar ```` ` antlr ```antlr\nstart \
            of grammar grammar spearfuzz;\n\nstart: 'a';\nend of grammar```grammar stuff outside of grammar"
        
        self.assertEqual(split_grammar_from_message(grammar), "start of grammar grammar spearfuzz;\n\nstart: 'a';\nend of grammar")
    
    def test_split_grammar_from_message_weird_af(self):
        from grammar_guy.utils import split_grammar_from_message
        grammar = "Dis is some stupid ass text before the gramamr ```` ` antlr ```antlr\nstart of grammar grammar '```antlr as part of grammar' spearfuzz;\n\nstart: 'a';\nend of grammar```grammar stuff outside of grammar"
        self.assertEqual(split_grammar_from_message(grammar), "start of grammar grammar '```antlr as part of grammar' spearfuzz;\n\nstart: 'a';\nend of grammar")
#  
#     def test_generate_grammar_regular_harness(self): 
#         from grammar_guy.grammar_guy import try_generate_initial_function_grammar        
#         simple_harness_src = "/shellphish/grammar-guy/test_harnesses/simple_harness_src"
#         test_grammar = try_generate_initial_function_grammar(simple_harness_src)
#         self.assertFalse(True, "Not Implemented")
        
#     def test_generate_grammar_broken_harness(self): 
#         from grammar_guy.grammar_guy import try_generate_initial_function_grammar
#         self.assertFalse(True, "Not Implemented")
    
#     def test_check_grammar_generate_inputs(): 
#         from grammar_guy.grammar_guy import generate_input_check_grammar
#         self.assertFalse(True, "Not Implemented")


# class TestTracingAndParsingFunctionality(unittest.TestCase):
    
#     def setUp():
#         os.makedirs("/tmp/grammar-guy-test/")
#         self.assertTrue(os.path.exists("/tmp/grammar-guy-test/"), "Failed to create test directory.")
    
#     def tearDown():
#         os.rmdir("/tmp/grammar-guy-test/")
#         self.assertFalse(os.path.exists("/tmp/grammar-guy-test/"), "Failed to remove test directory.")
    
#     def trace_single_input():
#         # Fixed input, crafted to hit certain lines 
#         # Assert that these lines are hit by parsing coverage files
#         # Assert correct hitcount
#         self.assertFalse(True, "Not Implemented")
    
#     def trace_multiple_inputs():
#         # Same as for single input, but multiple inputs
#         self.assertFalse(True, "Not Implemented")
    
#     def trace_and_parse_single_input():
#         # Fixed input
#         # Fixed target 
#         # Fixed output
#         # Assert that ouput of parsing is equal to fixed output
#         self.assertFalse(True, "Not Implemented")
    
#     def trace_and_parse_multiple_inputs():
#         self.assertFalse(True, "Not Implemented")

class TestNautilusScripts(unittest.TestCase):
    
    def setUp():
        os.makedirs("/tmp/grammar-guy-test/")
        self.assertTrue(os.file.exists("/tmp/grammar-guy-test/test-grammar.json"), "Test grammar does not exist.")
        self.assertTrue(os.file.exists("/tmp/grammar-guy-test/test-grammar-broken.json"), "Broken test grammar does not exist.")
        self.assertTrue(os.path.exists("/tmp/grammar-guy-test/"), "Failed to create test directory.")
        self.assertTrue(os.path.exists(script_location), "Script does not exist.")
    
    def tearDown():
        os.rmdir("/tmp/grammar-guy-test/")
        self.assertFalse(os.path.exists("/tmp/grammar-guy-test/"), "Failed to remove test directory.")
    
    def test_generate_single_input_nautilus():
        # Generate grammar from nautilus
        script_location = "shellphish/grammar-guy/src/scripts/generate_input_nautilus.sh"
        gen_output_dir = "/test-files/internal/output/nautilus_input_single"
        self.assertTrue(os.path.exists(script_location), "Script does not exist.")
        self.assertTrue(os.file.exists(self.correct_grammar_path), "Grammar does not exist.")
        
        # Remove and create output directory
        os.rmdir(gen_output_dir)
        os.makedirs(gen_output_dir)
        gen_inputs = 1
        script_inputs = [str(gen_inputs), self.correct_grammar_path, "/test-files/internal/output/nautilus_input_single"]
        run_output = subprocess.run([script_location, *script_inputs], capture_output=True)
        if run_output.errorcode != 0:
            self.assertFalse(True, f"Input generation failed, {run_output.stderr}")
        dir_entries = len(os.listdir(gen_output_dir))
        self.assertEqual(dir_entries, gen_inputs, "Inputs generated do not match the requested num of inputs.")
        
    def test_generate_500_inputs_nautilus():
        # Generate grammar from nautilus
        # Assert that grammar is generated
        script_location = "shellphish/grammar-guy/src/scripts/generate_input_nautilus.sh"
        gen_output_dir = "/test-files/internal/output/nautilus_input_single"
        self.assertTrue(os.path.exists(script_location), "Script does not exist.")

        # Remove and create output directory
        os.rmdir(gen_output_dir)
        os.makedirs(gen_output_dir)
        gen_inputs = 500
        script_inputs = [str(gen_inputs), self.correct_grammar_path, "/test-files/internal/output/nautilus_input_single"]
        run_output = subprocess.run([script_location, *script_inputs], capture_output=True)
        if run_output.errorcode != 0:
            self.assertFalse(True, f"Input generation failed, {run_output.stderr}")
        dir_entries = len(os.listdir(gen_output_dir))
        self.assertEqual(dir_entries, gen_inputs, "Inputs generated do not match the requested num of inputs.")
        
        
class TestGrammarinatorScripts(unittest.TestCase): 

    def setUp():
        os.makedirs("/tmp/grammar-guy-test/")
        self.assertTrue(os.file.exists("/tmp/grammar-guy-test/test-grammar.g4"), "Test grammar does not exist.")
        self.assertTrue(os.file.exists("/tmp/grammar-guy-test/test-grammar-broken.g4"), "Broken test grammar does not exist.")
        self.assertTrue(os.path.exists("/tmp/grammar-guy-test/"), "Failed to create test directory.")
        self.assertTrue(os.path.exists(script_location), "Script does not exist.")
    
    def tearDown(): 
        os.rmdir("/tmp/grammar-guy-test/")
        self.assertFalse(os.path.exists("/tmp/grammar-guy-test/"), "Failed to remove test directory.")

    def test_generate_500_inputs_grammarinator():
        # Generate grammar from nautilus
        # Assert that grammar is generated
        script_location = "shellphish/grammar-guy/src/scripts/generate_input_grammarinator.sh"
        gen_output_dir = "/test-files/internal/output/nautilus_input_single"
        self.assertTrue(os.path.exists(script_location), "Script does not exist.")

        # Remove and create output directory
        os.rmdir(gen_output_dir)
        os.makedirs(gen_output_dir)
        gen_inputs = 500
        script_inputs = [str(gen_inputs), self.correct_grammar_path, "/test-files/internal/output/nautilus_input_single"]
        run_output = subprocess.run([script_location, *script_inputs], capture_output=True)
        if run_output.errorcode != 0:
            self.assertFalse(True, f"Input generation failed, {run_output.stderr}")
        dir_entries = len(os.listdir(gen_output_dir))
        self.assertEqual(dir_entries, gen_inputs, "Inputs generated do not match the requested num of inputs.")
        
    def test_generate_single_input_grammarinator():
        # Generate grammar from nautilus
        # Assert that grammar is generated
        script_location = "shellphish/grammar-guy/src/scripts/generate_input_grammarinator.sh"
        gen_output_dir = "/test-files/internal/output/nautilus_input_single"
        self.assertTrue(os.file.exists(grammar_location), "Grammar does not exist.")

        # Remove and create output directory
        os.rmdir(gen_output_dir)
        os.makedirs(gen_output_dir)
        gen_inputs = 1
        script_inputs = [str(gen_inputs), self.correct_grammar_path, "/test-files/internal/output/nautilus_input_single"]
        run_output = subprocess.run([script_location, *script_inputs], capture_output=True)
        if run_output.errorcode != 0:
            self.assertFalse(True, f"Input generation failed, {run_output.stderr}")
        dir_entries = len(os.listdir(gen_output_dir))
        self.assertEqual(dir_entries, gen_inputs, "Inputs generated do not match the requested num of inputs.")
        
class test_coverage_stuff(unittest.TestCase):
    
    def test_shitty_grammar_shitty_coverage(self): 
        from grammar_guy import evaluate_grammar_coverage
        # read grammar from file 
        with open("/shellphish/grammar-guy/ci_tests/test_files/grammars/shitty_grammar.json", "r") as f:
            shitty_grammar = f.read()
    
        initial_grammar = evaluate_grammar_coverage(0, harness_src)
        
        for i in initial_grammar.keys(): 
            self.assertTrue(type(i) == str, "Grammar keys are not strings.")
            function_dict = initial_grammar[i]
            for line in function_dict.keys(): 
                self.assertTrue(line is not None, f"Line {line} in dictionary {i} is None.")
                line_dict = function_dict[line]
                self.assertEqual(type(line_dict["hitcount"]) is int, "Hitcount is not an integer.")
                
                    
    def test_parse_coverage_dict(self): 
        from grammar_guy import get_covered_uncovered_lines
        coverage_dict_littlecov = {}  
        coverage_dict_muchcov = {}
        
    def test_is_covered_function():
        # TODO test if is_covered_function returns True for a function with coverage
        pass    
    def test_function_pair_selection(): 
        # test if function_pair_selection actually returns a pair that is a pair according to in clang indexer
        pass