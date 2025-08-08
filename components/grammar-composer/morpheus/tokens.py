import random

from morpheus.grammar import Grammar
from morpheus.rule import PlainRule, LiteralRule, RegExpRule


def extract_tokens_and_generate_grammar(grammar_paths, output_path):
    """
    Extract tokens from grammar files and generate a new grammar that matches sequences of those tokens.
    
    Args:
        grammar_paths: List of paths to input grammar files
        output_path: Path where the generated grammar will be written
    """
    
    def split_tokens(production, non_terms):
        """Split a production string by non-terminals to extract literal tokens."""
        strings = [production]
        for non_term in non_terms:
            new_strings = []
            for s in strings:
                if non_term in s:
                    new_strings.extend(s.split(non_term))
                else:
                    new_strings.append(s)
            strings = new_strings
        return set(strings)
    
    def tokens_for_grammar(path):
        """Extract tokens from a single grammar file."""
        g = Grammar.from_file(path)
        if g is None:
            print(f"Warning: Failed to load grammar from {path}. Skipping...")
            return set()
        
        tokens = set()
        seen_types = set()
        
        for rule in g.rules:
            if rule.nt == "ANYRULE":
                continue
            elif isinstance(rule, PlainRule):
                # Extract non-terminals formatted as {name} in bytes
                non_terms = [(b'{' + nt.encode() + b'}') for nt in rule.children_nts]
                tokens.update(split_tokens(rule.production, non_terms))
            elif isinstance(rule, (LiteralRule)):
                # For LiteralRule, we can directly use the production as a token
                if isinstance(rule.production, bytes):
                    tokens.add(rule.production)
                elif isinstance(rule.production, str):
                    tokens.add(rule.production.encode())
            elif isinstance(rule, RegExpRule):
                # Generate 5 seeds (bytes) and add as tokens
                seeds = set(g.seed_iterator(rule=rule, n=100))
                seeds = sorted(seeds, key=lambda x: len(x))[:5]
                tokens.update(seeds)
            else:
                # Warn about unsupported rule types (only once per type)
                if type(rule) not in seen_types:
                    print(f"Warning: skipping unsupported rule type: {type(rule).__name__}")
                    seen_types.add(type(rule))

        # Then loop through all the helper_functions and gram the _co_consts
        def extract_bytes_strings(obj):
            results = []
            if isinstance(obj, bytes):
                results.append(obj)
            elif isinstance(obj, str):
                results.append(obj.encode())
            elif isinstance(obj, (tuple, list, frozenset)):
                for item in obj:
                    results.extend(extract_bytes_strings(item))
            elif hasattr(obj, 'co_consts'):  # code object
                results.extend(extract_bytes_strings(obj.co_consts))
            return results

        consts = set()
        for name, func_str in g.helper_functions.items():
            namespace = {}
            exec(func_str, namespace)
            co_consts = namespace[name].__code__.co_consts
            consts.update(extract_bytes_strings(co_consts))

        tokens.update(consts)
        
        return tokens
    
    # Collect tokens from all grammar files
    all_tokens = set()
    for grammar_path in grammar_paths:
        all_tokens.update(tokens_for_grammar(grammar_path))
    
    # Generate the token grammar
    token_grammar = r'''ctx.rule("START", "{TOKENS}")
ctx.rule("MAYBE_WS", "")
ctx.rule("MAYBE_WS", " ")
ctx.rule("MAYBE_WS", "\t")
ctx.rule("MAYBE_WS", "\r")
ctx.rule("MAYBE_WS", "\r\n")
ctx.rule("TOKENS", "")
ctx.rule("TOKENS", "{TOKEN}")
ctx.rule("TOKENS", "{TOKEN}{MAYBE_WS}{TOKEN}")
ctx.rule("TOKENS", "{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKEN}")
ctx.rule("TOKENS", "{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKENS}")
ctx.rule("TOKENS", "{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKEN}{MAYBE_WS}{TOKENS}")

'''

    # Discard empty or too long tokens
    all_tokens = {token for token in all_tokens if token and len(token) <= 256}

    # Limit to 20,000 tokens --> if necessary, shuffle, then truncate, then sort
    if len(all_tokens) > 20000:
        print(f"Warning: More than 20,000 tokens found ({len(all_tokens)}). Limiting to 20,000.")
        all_tokens = list(all_tokens)
        random.shuffle(all_tokens)
        all_tokens = all_tokens[:20000]
    all_tokens = sorted(all_tokens)
    
    
    # Add individual token rules
    for token in all_tokens:
        token_grammar += f'ctx.rule("TOKEN", {repr(token)})\n'
    
    # Add marker
    token_grammar += '\n# ARTIPHISHELL TOKEN TOKEN TOKEN '
    
    # Write the grammar to the output file
    with open(output_path, 'w') as f:
        f.write(token_grammar)
