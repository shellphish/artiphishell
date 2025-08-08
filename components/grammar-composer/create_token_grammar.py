from morpheus.tokens import extract_tokens_and_generate_grammar
import os
import time

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py <output_path> <grammar_dir>")
        sys.exit(1)
    
    output_path = sys.argv[1]
    grammar_dir = sys.argv[2]
    
    # Filter files: *.py, not @CORPUS.PY, not token_grammar_*, older than 30 mins
    grammar_paths = []
    now = time.time()
    for f in os.listdir(grammar_dir):
        if (
            f.lower().endswith('.py') and 
            not f.lower().endswith('@corpus.py') and 
            not f.lower().startswith('token_grammar_') and
            os.path.isfile(os.path.join(grammar_dir, f)) and
            now - os.path.getmtime(os.path.join(grammar_dir, f)) > 1800
        ):
            grammar_paths.append(os.path.join(grammar_dir, f))
    
    extract_tokens_and_generate_grammar(grammar_paths, output_path)