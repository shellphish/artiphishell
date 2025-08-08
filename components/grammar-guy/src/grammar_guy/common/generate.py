from pathlib import Path
import subprocess
import tempfile
import logging
import shutil
import hashlib
import sys
import os

log = logging.getLogger('grammar_guy')

def generate_nautilus_inputs(num_inputs: int, grammar_path: Path, out_dir: Path, timeout=200) -> tuple:
    ''' Generate inputs using Nautilus.
    :return: (success, stdout, stderr)
    '''
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nautilus-generator-") as temp_dir:
        grammar_dest = os.path.join(temp_dir, "grammar.py")
        shutil.copy(grammar_path, grammar_dest)
        deriv_dir = os.path.join(temp_dir, "serialized_derivation_trees")
        os.makedirs(deriv_dir, exist_ok=True)
        # Run
        process = subprocess.run([
            "/shellphish/libs/nautilus/target/release/generator",
            "-r", "serialized_derivation_trees",
            "-n", str(num_inputs),
            "-g", "grammar.py",
            "-t", str(timeout),
            "-s",
            "-c", "corpus"
        ], cwd=temp_dir, capture_output=True, text=True)
        if process.returncode != 0:
            return False, str(process.stdout), str(process.stderr)
        else:
        # Move and rename generated files
            corpus_dir = os.path.join(temp_dir, "corpus")
            for file_name in os.listdir(corpus_dir):
                file_path = os.path.join(corpus_dir, file_name)
                if os.path.isfile(file_path):
                    # Calculate MD5 hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                    
                    # Move file to output directory with hash name
                    shutil.move(file_path, os.path.join(out_dir, file_hash))
            
            print("Successfully generated inputs")
        return True, str(process.stdout), str(process.stderr)

def generate_grammarinator_inputs(num_inputs, grammar_path, out_dir, rule="spearfuzz", depth=25) -> tuple:
    ''' Generate inputs using Grammarinator.
    :return: (success, stdout, stderr)
    '''
    # Ensure output directory exists
    os.makedirs(out_dir, exist_ok=True)
    # Collect stdout and stderr
    success = True
    with tempfile.TemporaryDirectory(prefix="grammar-guy-generators-") as temp_dir:
        generator_dir = os.path.join(temp_dir, "generators")
        os.makedirs(generator_dir, exist_ok=True)
        gen_dir = os.path.join(out_dir, "tmp_hashes")
        os.makedirs(gen_dir, exist_ok=True)
        std_err = []
        std_out = []

        process = subprocess.run([
            "grammarinator-process", 
            grammar_path, 
            "--rule", rule, 
            "-o", generator_dir
        ], capture_output=True, text=True)
        
        # Generate inputs
        generator_name = f"{rule}Generator.{rule}Generator"
        process2 = subprocess.run([
            "grammarinator-generate", 
            "--sys-path", generator_dir,
            generator_name,
            "--rule", rule,
            "-d", str(depth),
            "-o", os.path.join(gen_dir, f"{rule}_input_%d"),
            "-n", str(num_inputs)
        ], capture_output=True, text=True, check=True)
        
        if process.returncode != 0 or process2.returncode != 0:
            std_err.append(process.stderr)
            std_out.append(process.stdout)
            std_err.append(process2.stderr)
            std_out.append(process2.stdout)
            shutil.rmtree(gen_dir, ignore_errors=True)
            success = False
        else:
            # Move and rename generated files
            for file_name in os.listdir(gen_dir):
                file_path = os.path.join(gen_dir, file_name)
                if os.path.isfile(file_path):
                    # Calculate MD5 hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                    
                    # Move file to output directory with hash name
                    shutil.move(file_path, os.path.join(out_dir, file_hash))
            print("Successfully generated inputs")
    return success, '\n'.join(std_out), '\n'.join(std_err)

def invoke_generator(generator, num_inputs, grammar_path, out_dir, timeout=100) -> tuple:

    if generator == "nautilus":
        return generate_nautilus_inputs(num_inputs, grammar_path, out_dir, timeout)
    elif generator == "grammarinator":
        return generate_grammarinator_inputs(num_inputs, grammar_path, out_dir, timeout)
    elif generator == "gramatron":
        raise NotImplementedError("Gramatron input generation is not implemented yet.")
    else:
        raise ValueError(f"Unknown generator: {generator}") 
        