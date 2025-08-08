from pathlib import Path


class PatchedFunction:
    """
    A Patched Program Point of Interest is a Program Point of Interest with old and new code.
    """
    def __init__(
        self,
        function_name: str = None,
        file: Path = None,
        init_start_line: int = None,
        init_end_line: int = None,
        old_code: str = None,
        new_code: str = None,
    ):
        self.function_name = function_name
        self.file = file
        self.init_start_line = init_start_line
        self.init_end_line = init_end_line
        self.new_code = new_code or ""
        self.old_code = old_code or ""
        
    def __str__(self):
        patched_func_str = f"<{self.__class__.__name__} file={self.file}, func={self.function_name}"
        patched_func_str += ">"
        return patched_func_str
    
    def __repr__(self):
        return self.__str__()