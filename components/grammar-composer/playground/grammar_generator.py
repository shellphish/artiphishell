#!/usr/bin/env python3

import openai

API_KEY = "sk-artiphishell-da-best!!!"
API_BASE = "http://wiseau.seclab.cs.ucsb.edu:666"
MODEL = "gemini-2.5-pro"
# claude-3-haiku, claude-3-opus, claude-3-sonnet, claude-3.5-haiku, claude-3.5-sonnet, claude-3.7-sonnet, gemini-1.5-flash-8b, gemini-1.5-pro, gemini-2.0-flash, gemini-2.0-flash-lite, gemini-2.5-pro, gemini-2.5-pro-preview, mst-oai-gpt-4o, oai-gpt-4.1, oai-gpt-4.1-mini, oai-gpt-4.1-nano, oai-gpt-4o, oai-gpt-4o-latest, oai-gpt-4o-mini, oai-gpt-o1, oai-gpt-o1-mini, oai-gpt-o1-preview, oai-gpt-o3, oai-gpt-o3-mini, oai-gpt-o4-mini, oai-text-embedding-3-large, oai-text-embedding-3-small

CLIENT = openai.OpenAI(
    api_key=API_KEY,
    base_url=API_BASE
)

def query_openai(messages):
    response = CLIENT.chat.completions.create(
        model=MODEL,
        messages=messages
    )
    return response.choices[0].message.content

DESIGN_SYSTEM_PROMPT = """
Your are a fuzzing expert. Your task is to design the perfect grammar for fuzzing a given file format.
Your grammar will be used to generate seeds for fuzzing a target.
When designing the grammar, you should consider the following:
- the grammar should be able to generate valid files of the given format
- the grammar should be appropriate for fuzzing, meaning it should be able to generate seeds that are also interesting and diverse
- the grammar might generate invalid seeds, but only to test the robustness of the target

Remember that your task is to design the grammar features, not to write the grammar itself.
"""

DESIGN_USER_PROMPT = """
Write an exhaustive and detailed list of desirable features that must be integrated to craft a robust grammar for fuzzing {fformat} (mime types: {mimetypes}).
"""

NAUTILUS_101 = """
# Nautilus Grammar Essentials

Consider the following guidelines when writing grammars for Nautilus:
```python
####################
# RULE
# `ctx.rule(NONTERM: string, RHS: bytes)` adds a rule NONTERM->RHS.
####################
# IMPORTANT: All non terminals must be capitalized.

# Your grammar must include a START rule that defines the entry point for the fuzzer.
ctx.rule("START", b"<xml>{XML_CONTENT}</xml>")

# Use `.rule` to concatenate nonterminals or combine nonterminals in a context-insensitive way.
# IMPORTANT: Each occurrence of a nonterminal is regenerated independently. Even repeated symbols like {TAG}{TAG} in a `.rule` will yield different outputs in separate subtrees.
# Use {NONTERM} in the RHS to request a recursion.
ctx.rule("XML_CONTENT", b"{XML_ELEMENT}{XML_CONTENT}")

# Define alternatives as separate rules.
ctx.rule("XML_ELEMENT", b"<data-element>{DATA}</data-element>")
ctx.rule("XML_ELEMENT", b"<encoded-element>{BASE64}</encoded-element>")

ctx.rule("TAG", b"{HEX_DIGITS}")

ctx.rule("DATA", b"{BYTES}")
ctx.rule("DATA", "{BLOB}")
ctx.rule("DATA", b"{HEX_DIGITS}")


####################
# LITERAL
# `ctx.literal(NONTERM: string, value: bytes)` adds a literal (constant raw bytes) rule.
# Always use `.literal` rules when the RHS of a rule does not contain any nonterminals.
####################

ctx.literal("XML_CONTENT", b"")
ctx.literal("BLOB", b"}{\x00\x01\x02\x03")


####################
# BYTES
# `ctx.bytes(NONTERM: string, width: int)` adds a fixed-width random bytes rule.
# Use `.bytes` rules to generate random bytes with a given width.
# The width parameter specifies the number of bytes.
####################

ctx.bytes("BYTES", 4)  # -> b"\x01\x02\x03\x04"


####################
# REGEX
# `ctx.regex(NONTERM: string, regex: string)` adds a regex rule.
####################
# IMPORTANT: All regex generations must be valid Unicode characters: avoid negations (`^`) and greedy quantifiers (like `.*` or `.?`) unless you are absolutely sure they only generate Unicode characters.
# IMPORTANT: The regex generator supports a subset of regex features: literal characters, character classes (only Unicode ranges), alternation (`|`), concatenation, and grouping. 
# It also supports common repetition operators like zero-or-one (?), zero-or-more (*), one-or-more (+), and bounded repetitions ({m} or {m,n}). 
# Other features like anchors, backreferences or lookaround are NOT supported.

ctx.regex("HEX_DIGITS", "[A-Fa-f0-9]+")


####################
# HELPER FUNCTIONS
# `def helper_function(NONTERM+):` defines a helper function.
# YOU MUST DEFINE ALL YOUR HELPER FUNCTIONS BEFORE THE RESPECTIVE `.script` RULES and only if you really, really need them.
####################

# IMPORTANT: Each helper function must have at least one NONTERM parameter.
# IMPORTANT: The NONTERM parameters must match each exactly the NONTERMS of the respective invoking `.script` rules (see below).
def build_xml_element(TAG: bytes, XML_CONTENT: bytes) -> bytes:
    return b"<" + TAG + b">" + XML_CONTENT + b"</" + TAG + b">"

def encode_base64(data: bytes) -> bytes:
    # IMPORTANT: Import modules inside the function, not at the top of the file.
    # IMPORTANT: Never use global variables.
    # Any other source of information like .input() or random number generators is not available.
    import base64
    return base64.b64encode(data)


####################
# SCRIPT
# `ctx.script(NONTERM: string, RHS: List[NONTERM+], func: function)` adds a rule NONTERM->func(*RHS).
# In contrast to `.rule`, RHS is an array of nonterminals.
# Use `.script` and a helper function `func` to combine nonterminals in a context-sensitive way.
# IMPORTANT: Only use `.script` rules when it is really necessary. Never use `.script` rules when you can use `.rule` or `.literal` rules instead.
####################

# IMPORTANT: `.script` rules must have at least one NONTERM in their RHS.
ctx.script("XML_ELEMENT", ["TAG", "XML_CONTENT"], build_xml_element)

ctx.script("BASE64", ["DATA"], encode_base64)


####################
# Best Practices for Writing Good Grammars:
# - Break complex structures into small, reusable rules.
# - Always include terminating productions (base case) to prevent infinite recursion.
# - Avoid left-recursion and prefer explicit recursion to prevent infinite loops.
# - Avoid using python random number generators. Instead, use nonterminal rules like `.bytes` or `.regex`. Every source of randomness in your grammar must come from the nonterminal rules.
####################
```
"""

GENERATION_SYSTEM_PROMPT = """
Your are a fuzzing expert. Your task is to design the perfect grammar for fuzzing a given file format.
Your grammar will be used to generate seeds for fuzzing a target.
When designing the grammar, you should consider the following:
- the grammar should be able to generate valid files of the given format
- the grammar should be appropriate for fuzzing, meaning it should be able to generate seeds that are also interesting and diverse
- the grammar might generate invalid seeds, but only to test the robustness of the target

"""
GENERATION_SYSTEM_PROMPT += NAUTILUS_101

GENERATION_USER_PROMPT = """
Consider carefully the guidance above, then write a nautilus grammar fuzzing {fformat} (mime types: {mimetypes}).
First design your grammar: what fields do you need? how will you link fields to each other? will you need to use helper functions for complex relationships (like length encoding, checksums, encoding, chunk compression) or simple rule concatenation?
Then implement your Nautilus grammar.
Your grammar must be able to generate well-formed documents without errors.
Please avoid script rules (unless really needed) and instead encode as much as you can into other nonterminals.
Otherwise, your grammar will be inappropriate for fuzzing.
Provide the grammars in a copy-pasteable format starting with triple-backticks and ending with triple-backticks only.
"""


from collections import defaultdict

from morpheus.magic import MIME_TO_NAME

name_to_mime_types = defaultdict(set)
for mime_type, name in MIME_TO_NAME.items():
    name_to_mime_types[name].add(mime_type)

name_to_mime_types = {name: " ".join(mime_types) for name, mime_types in name_to_mime_types.items()}


import subprocess
import tempfile
import random

from tqdm import tqdm

from morpheus.grammar import Grammar

import os
os.environ["ARTIPHISHELL_FAIL_EARLY"] = "1"

for name, mime_types in name_to_mime_types.items():
    print("="*100)
    print("="*100)
    print("="*100)
    print(f"Generating grammar for {name} ({mime_types})")
    print("="*100)
    # skip if the grammar already exists
    if os.path.exists(f"/home/ruaronicola/artiphishell/components/grammar-composer/playground/grammar_drafts/{name}.py"):
        print(f"Grammar for {name} already exists. Skipping...")
        continue
    
    messages = [{"role": "system", "content": DESIGN_SYSTEM_PROMPT}]
    messages.append({"role": "user", "content": DESIGN_USER_PROMPT.format(fformat=name, mimetypes=mime_types)})

    design_response = query_openai(messages)
    print("="*100)
    print(f"Design response: \n{design_response}")

    messages = [{"role": "system", "content": GENERATION_SYSTEM_PROMPT}]
    messages.append({"role": "user", "content": DESIGN_USER_PROMPT.format(fformat=name, mimetypes=mime_types)})
    messages.append({"role": "assistant", "content": design_response})
    messages.append({"role": "user", "content": GENERATION_USER_PROMPT.format(fformat=name, mimetypes=mime_types)})

    def verify_generation_response(generation_response, messages, fformat, retries=0, widened=False):
        if retries > 10:
            print("Failed to generate a valid grammar after 10 retries.")
            return None

        print("="*100)
        print(f"Verifying generation response: \n{generation_response}")

        messages_backup = list(messages)

        # FIRST EXTRACT THE GRAMMAR
        print("Extracting grammar...")
        if generation_response.count("```") != 2:
            print("Failed to extract grammar. Retrying...")
            messages.append({"role": "assistant", "content": generation_response})
            messages.append({"role": "user", "content": "Please provide the grammar in a copy-pasteable format starting with triple-backticks and ending with triple-backticks only."})
            generation_response = query_openai(messages)

            return verify_generation_response(generation_response, messages_backup, fformat=fformat, retries=retries+1, widened=widened)

        # SECOND LOAD THE GRAMMAR
        print("Loading grammar...")
        grammar_string = generation_response.split("```")[1]
        grammar_string = "\n".join(grammar_string.split("\n")[1:-1])
        try:
            grammar = Grammar.from_string(grammar_string)
        except Exception as e:
            print(f"Failed to load grammar: {e}. Retrying...")
            messages.append({"role": "assistant", "content": generation_response})
            messages.append({"role": "user", "content": f"Failed to load grammar: {e}\n\nPlease cafefully consider the reported error, revise your grammar, and provide a new one. Are there other locations in the grammar that could cause the same error?"})
            generation_response = query_openai(messages)
        
            return verify_generation_response(generation_response, messages, fformat=fformat, retries=retries+1, widened=widened)

        # THIRD CHECK THAT THE GRAMMAR HAS ENOUGH GENERATION CAPACITY
        print("Checking generation capacity...")
        generations = set(grammar.seed_iterator(nt="START", n=1000))
        if len(generations) < 500:
            print(f"Grammar has too few generations: {len(generations)}. Retrying...")
            messages.append({"role": "assistant", "content": generation_response})
            messages.append({"role": "user", "content": f"Your grammar is not able to generate enough seeds. Please revise your grammar and provide a new one. How can the grammar be widened to generate more seeds?"})
            generation_response = query_openai(messages)
        
            return verify_generation_response(generation_response, messages, fformat=fformat, retries=retries+1, widened=widened)

        # FOURTH CHECK THAT (MOST OF) THE GENERATED SEEDS MATCH THE WANTED FORMAT
        print("Checking generation validity...")
        generations = random.shuffle(list(generations))[:100]
        total = len(generations)
        valid = 0
        for generation in tqdm(generations):
            with tempfile.NamedTemporaryFile(delete=True) as f:
                f.write(generation)
                f.flush()
                try:
                    subprocess.check_call(["/home/ruaronicola/artiphishell/components/grammar-composer/playground/verify_fformat.sh", f.name, fformat.lower()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    valid += 1
                except subprocess.CalledProcessError as e:
                    pass
        
        if valid / total < 0.5:
            print(f"Grammar is not able to generate valid {fformat} files: {valid}/{total}. Retrying...")
            messages.append({"role": "assistant", "content": generation_response})
            messages.append({"role": "user", "content": f"Your grammar is not able to generate valid {fformat} files: {total-valid} out of {total} generations are malformed. Please revise your grammar and provide a new one. Pay particular attention to what makes an {fformat} file valid. Why is your grammar not able to generate valid {fformat} files? How can it be improved?"})
            generation_response = query_openai(messages)
                    
            return verify_generation_response(generation_response, messages, fformat=fformat, retries=retries+1, widened=widened)

        if not widened:
            # FINALLY WIDEN THE GRAMMAR FOR FUZZING
            print("Widening grammar for fuzzing...")
            messages.append({"role": "assistant", "content": generation_response})
            messages.append({"role": "user", "content": f"Your grammar is able to generate valid {fformat} files: {valid}/{total} generations are valid. Now please revise your grammar to make it more 'fuzzable' (if needed). How can the grammar be widened to generate more interesting seeds? Are there any important missing grammar features? Is the grammar capable of generating meaningful {fformat} files?"})
            generation_response = query_openai(messages)

            return verify_generation_response(generation_response, messages, fformat=fformat, retries=retries, widened=True)

        print(f"Grammar is valid: {valid}/{total} ({valid/total*100:.2f}%)")
        return grammar.serialize()

    generation_response = query_openai(messages)
    grammar_string = verify_generation_response(generation_response, messages, fformat=name)

    print("="*100)
    if grammar_string:
        with open(f"/home/ruaronicola/artiphishell/components/grammar-composer/playground/grammar_drafts/{name}.py", "w") as f:
            f.write(grammar_string)
        print(f"Grammar for {name} saved to /home/ruaronicola/artiphishell/components/grammar-composer/playground/grammar_drafts/{name}.py")
    else:
        print(f"Failed to generate a valid grammar for {name}")