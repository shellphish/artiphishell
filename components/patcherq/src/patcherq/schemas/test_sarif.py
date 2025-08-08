from jinja2 import Template
import json

with open('sarif.j2', 'r') as file:
    template_string = file.read()
    
template = Template(template_string)

context = {
    "RULE_ID": "John Doe",
    "RULE_NAME": "John Doe",
    "RULE_DESCRIPTION": "John Doe",
    "LEVEL": "John Doe",
    "FLOW": [
        ["File1", 123],
        ["File2", 456],
        ["File3", 789],
    ]
    }

rendered_string = template.render(context)

print(rendered_string)
with open('sarif.sarif', 'w') as f:
    f.write(rendered_string)