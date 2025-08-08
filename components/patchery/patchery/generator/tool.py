class Tool:
    def __init__(self, prompt_template: str, variable_dict: dict):
        self.prompt_template = prompt_template
        self.variable_dict = variable_dict

    def generate_prompt(self):
        raise NotImplementedError
