import logging

from jinja2 import Template, StrictUndefined, meta, Environment

_l = logging.getLogger(__name__)

class PromptGenerator:
    def __init__(self, prompt_template: str, variable_dict: dict):
        self.prompt_template = prompt_template
        self.variable_dict = variable_dict
        self.template: Template | None = None
        self.env = Environment()

    def _check_placeholder(self):
        ast = self.env.parse(self.prompt_template)
        variables = meta.find_undeclared_variables(ast)
        user_variables = set(self.variable_dict.keys())
        for var in user_variables:
            if var not in variables:
                self.variable_dict.pop(var)
        for var in variables:
            if var not in user_variables:
                self.variable_dict[var] = ""

    def _build_template(self):
        self.template = Template(self.prompt_template, undefined=StrictUndefined)

    def _render_template(self) -> str:
        return self.template.render(self.variable_dict)

    @classmethod
    def render(cls, template: str, placrholders: dict) -> str:
        prompt = cls(template, placrholders)
        prompt._build_template()
        prompt._check_placeholder()
        return prompt._render_template()


