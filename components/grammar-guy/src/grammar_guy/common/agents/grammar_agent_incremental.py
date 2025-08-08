import re
import logging

from agentlib import Agent, LLMFunction
from agentlib.lib.common.parsers import BaseParser

logger = logging.getLogger('GrammarAgent')
logger.setLevel(logging.INFO)

OUTPUT_DESCRIPTION = """
After completing the analysis, you MUST output the report in the following specified format.

```
<grammar_report>
<change>
<type>...</type>
<line>
<start>...</start>
<end>...</end>
</line>
<grammar>...</grammar>
</change>
 ...
</grammar_report>
```

For each change in the grammar, you must generate a `<change>...</change>` block that includes:
- `<type>...</type>`: replace the ... with the type (string) of change (only use "add", "delete", or "modify").
- `<line>...</line>`: replace the ... with the line number information
    - `<start>...</start>`: replace the ... with the start line number (integer) of the change.
    - `<end>...</end>`: replace the ... with the end line number (integer) of the change (for addition provide 'n/a'; for deletion and modification, provide the end line number).
- `<grammar>...</grammar>`: replace the ... with the grammar changes string (for deletion, provide 'n/a'; for addition, provide the new grammar; for modification, provide the modified grammar).

IMPORTANT NOTES:
1. IN <grammar> TAGS, JUST OUTPUT THE GRAMMAR THAT NEEDS TO BE ADDED OR MODIFIED, NOT THE ENTIRE GRAMMAR!
   - Include only the exact line numbers that correspond to the line numbers in the original grammar.
2. NEVER OUTPUT THE LINE NUMBERS WITHIN <grammar> TAGS! 
   - Ensure that only the new or modified grammar content is present in these tags, without any line numbers.
3. YOU MUST ADD SEPARATE <change> TAGS FOR EACH CHANGE IN THE GRAMMAR!
4. FOR EACH CHANGE, YOU MUST PROVIDE ALL TAGS AS DESCRIBED ABOVE!
    - For addition, provide both `<start>` and `<end>` tags, but for `<end>` tag provide 'n/a'. Similarly, for deletion, provide 'n/a' for the `<grammar>` tag.
5. FOR `<type>` TAGS, ONLY USE "add", "delete", OR "modify"!
"""

class MyParser(BaseParser):
    MAX_FORMAT_FIX_ATTEMPTS = 3
    RECOVERY_MODEL = 'gpt-4.1-mini'

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        return self.parse(msg.content)
    
    def fix_format(self, text: str) -> str:
        logger.info(f'🚨 Inc Text = {text}')
        fix_llm = LLMFunction.create(
            "Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}",
            model=self.RECOVERY_MODEL,
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        logger.info(f'🚨 Fixed Text = {fixed_text}')
        return fixed_text
    
    def extract_changes(self, text: str):
        try_itr = 1
        while try_itr <= self.MAX_FORMAT_FIX_ATTEMPTS:
            changes = re.findall(r'<change>\s*<type>(.*?)</type>\s*<line>\s*<start>(.*?)</start>\s*<end>(.*?)</end>\s*</line>\s*<grammar>([\s\S]*?)</grammar>\s*</change>', text, re.DOTALL)
            
            if len(changes) != 0:
                logger.info('✅ Regexp-Parser: Successfully parsed the grammar changes from the agent output!')
                return changes

            logger.info('🤡 Regexp-Error: Could not parse the grammar changes from the ouput!')
            logger.info('🤡 Regexp-Error: Trying to fix the format of the grammar report... Attempt %d!', try_itr)
            text = self.fix_format(text)
            try_itr+=1
        return []

    def extract_grammar(self, text: str):
        allowed_type_tags = ['add', 'delete', 'modify']
        try_itr = 1
        while try_itr <= self.MAX_FORMAT_FIX_ATTEMPTS:
            changes = self.extract_changes(text)
            # Process each <change> entry
            grammar = []
            change_id = 0
            error = False
            for change_type, start_loc, end_loc, grammar_chng in changes:
                # ---------------------------------
                # Guard for the type of change (in 
                # case of a tag other than the allowed ones)
                if change_type.strip() not in allowed_type_tags:
                    logger.info(f'🤡 Parsing-Error: Invalid change type "{change_type.strip()}" found in the grammar report!')
                    error = True
                    break
                # ---------------------------------
                try:
                    parsed_change = {
                        "change_id": int(change_id),
                        "type": change_type.strip(),
                        "line": {
                            "start": int(start_loc.strip()),
                            "end": int(end_loc.strip()) if end_loc.strip().lower() != 'n/a' else None
                        },
                        "grammar": grammar_chng.strip()
                    }
                except Exception as e:
                    logger.info('🤡 Parsing-Error: Could not parse the grammar from the regexp-match! %s', e)
                    error = True
                    break
                grammar.append(parsed_change)
                change_id+=1

            if error:
                logger.info('🤡 Parsing-Error: Trying to fix the format of the grammar report... Attempt %d!', try_itr)
                text = self.fix_format(text)
                try_itr+=1
            else:
                logger.info('✅ Data-Parser: Successfully parsed the grammar data from the output!')
                return grammar
        return []

    def parse(self, text: str):
        try_itr = 1
        while try_itr <= self.MAX_FORMAT_FIX_ATTEMPTS:
            raw_grammar = re.search(r'<grammar_report>([\s\S]*?)</grammar_report>', text)

            if raw_grammar:
                grammar = self.extract_grammar(raw_grammar.group(0))
                return grammar
            else:
                logger.info('🤡 Regexp-Error: Could not parse the grammar from the ouput!')
                logger.info('🤡 Regexp-Error: Trying to fix the format of the grammar report... Attempt %d!', try_itr)
                text = self.fix_format(text)
                try_itr+=1

        logger.info('Error: Could not parse the grammar from the ouput!')
        assert(False)

class GrammarAgentIncremental(Agent[dict,str]):
    __LOGGER__ = logging.getLogger('GrammarAgent')
    __LOGGER__.setLevel('INFO')
    __OUTPUT_PARSER__ = MyParser

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        return vars

    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost

def apply_grammar_changes(grammar: str, changes: list) -> str:
    if changes is None or grammar is None or grammar == "" or len(changes) == 0:
        return None
    buffer = grammar.splitlines()
    changes_sorted = sorted(changes, key=lambda c: c["line"]["start"])
    offset = 0

    for ch in changes_sorted:
        op      : str = ch["type"]
        start0  : int = ch["line"]["start"] - 1
        end0    : int = (ch["line"].get("end") or ch["line"]["start"]) - 1

        # Adjust for previous insertions/deletions/additions
        start = start0 + offset
        end   = end0   + offset

        new_text = ch.get("grammar") or ""
        new_lines = new_text.splitlines() if op in ("modify", "add") else []

        if op == "delete":
            del buffer[start : end + 1]
            offset -= (end - start + 1)

        elif op == "modify":
            old_len = end - start + 1
            buffer[start : end + 1] = new_lines
            offset += len(new_lines) - old_len

        elif op == "add":
            insert_at = min(start, len(buffer))
            buffer[insert_at : insert_at] = new_lines
            offset += len(new_lines)

        else:
            raise ValueError(f"Unknown grammar type {op!r}")

    updated_grammar = "\n".join(buffer)
    return updated_grammar
