import re

def parse(text: str):
    def extract(tag: str) -> str:
        m = re.search(rf'<{tag}>\s*(.*?)\s*</{tag}>', text, re.DOTALL)
        return m.group(1) if m else ''

    rule_id          = extract('rule_id')
    rule_name        = extract('rule_name')
    rule_description = extract('rule_description')
    level            = extract('level')

    # Extract all flow items
    flows_raw = re.search(r'<flow>\s*(.*?)\s*</flow>', text, re.DOTALL)
    flow_pattern = (
        r'<flow_item>\s*'
        r'<filepath>\s*(.*?)\s*</filepath>\s*'
        r'<startline>\s*(.*?)\s*</startline>\s*'
        r'</flow_item>'
    )
    flow_items = re.findall(flow_pattern, flows_raw.group(1) if flows_raw else '', re.DOTALL)

    if not flow_items or not rule_id or not rule_name or not rule_description or not level:
        # Technically, this should never happen
        # the parser should make sure that the output is always in the format.
        assert False
    
    return {
                'RULE_ID': rule_id,
                'RULE_NAME': rule_name,
                'RULE_DESCRIPTION': rule_description.replace('\n', ' '),
                'LEVEL': level,
                'FLOW': flow_items
            }
    
print(parse(open('sarif.xml').read()))