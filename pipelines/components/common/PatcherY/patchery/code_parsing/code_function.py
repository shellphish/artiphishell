class CodeFunction:
    def __init__(self, name, start_line, end_line, code=None, global_vars=None):
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.code = code
        self.global_vars = global_vars or []
