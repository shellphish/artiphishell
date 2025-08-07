import sys
import os
import ast
import astunparse
from typing import List, Optional, Any, TypeVar
Self = TypeVar("Self", bound="Code")

from langchain_core.output_parsers import BaseOutputParser

from .object import SaveLoadObject
from .base import load_prompt_template_from_file

class CallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.callees = set()

    def visit_Call(self, node):
        # Get the name of the callee function
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr
        else:
            callee_name = "unknown"

        self.callees.add(callee_name)
        self.generic_visit(node)


class CodeExecutionEnvironment(SaveLoadObject):
    pass

class CodeExecutionException(SaveLoadObject):
    exception_type: str
    exception_message: str

    @classmethod
    def from_exception(cls, e: Exception) -> "CodeExecutionException":
        return cls(
            exception_type=type(e).__name__,
            exception_message=str(e)
        )

    def __str__(self):
        return f"{self.exception_type}: {self.exception_message}"
    
    def __repr__(self):
        return str(self)

class PythonCodeExecutionEnvironment(CodeExecutionEnvironment):
    __CODE_OUTPUT_DIR__ = 'generated_code'
    __TOP_LEVEL_INDENT__ = 4 # For defining on class level
    __CODE_TEMPLATE__ = 'py_exec_simple.py'

    def get_code_template(self) -> str:
        return load_prompt_template_from_file(
            self.__CODE_TEMPLATE__,
            directory='execution_environments'
        )

    def module_entrypoint(self, mod):
        raise NotImplementedError

    def execute(self, code: "Code") -> "CodeExecutionResult":
        source_code = self.template_with_code(code)
        source_dir = os.path.abspath(self.__CODE_OUTPUT_DIR__)
        os.makedirs(source_dir, exist_ok=True)
        source_fp = os.path.join(
            source_dir,
            self.__CODE_TEMPLATE__ # TODO should be unique?
        )
        # Remove existing file
        if os.path.exists(source_fp):
            os.remove(source_fp)
        with open(source_fp, 'w') as f:
            f.write(source_code)

        mod_name = os.path.splitext(os.path.basename(source_fp))[0]
        
        # TODO we do this every time, should be done once?
        sys.path.insert(1, source_dir)
        import importlib
        try:
            mod = importlib.import_module(mod_name)
            importlib.reload(mod)

            res = self.module_entrypoint(code, mod)
            return CodeExecutionResult(
                code=code,
                return_value=res
            )

        except Exception as e:
            return CodeExecutionResult(
                code=code,
                exception=CodeExecutionException.from_exception(e)
            )
    
    def template_with_code(self, code: "Code", **kw) -> str:
        template = self.get_code_template()
        args = dict(
            source_code = code.get_source(),
            prefix = code.exec_prefix or '',
            postfix = code.exec_postfix or '',
            suffix = code.exec_postfix or '',
        )
        args.update(**kw)
        code_res = template.invoke(args).text
        return code_res


class Code(SaveLoadObject):
    name: Optional[str] = None
    source_code: Optional[str] = None
    arguments: Optional[List[Any]] = None
    functions: Optional[dict] = None
    language: Optional[str] = "python"

    """Appended before the code when executed"""
    exec_prefix: Optional[str] = None
    """Appended after the code when executed"""
    exec_postfix: Optional[str] = None

    def add_exec_prefix(self, prefix: str):
        if self.exec_prefix:
            self.exec_prefix += prefix
        else:
            self.exec_prefix = prefix
            
    def add_exec_postfix(self, postfix: str):
        if self.exec_postfix:
            self.exec_postfix += postfix
        else:
            self.exec_postfix = postfix

    def get_source(self, include_prefix=False, **kw) -> str:
        if self.source_code:
            return self.source_code
        body = ''
        if not self.functions:
            return None
        for f in self.functions.values():
            body += f['body'] + '\n\n'
        if include_prefix and self.exec_prefix:
            body = self.exec_prefix + '\n' + body
        return body

    def get_function(self, name: str) -> Optional[dict]:
        return self.functions.get(name)

    def get_main_function(self) -> Optional[dict]:
        return self.get_function(self.name)

    @classmethod
    def from_generic_source(cls, source_code: str) -> Self:
        return cls(source_code=source_code)

    @classmethod
    def from_python_source(cls, source_code: str) -> Self:
        parsed = ast.parse(source_code)
        functions = []
        assert len(parsed.body) > 0, "No python functions were found in the previous output. Please make sure this is expected."
        for i, node in enumerate(parsed.body):
            if not isinstance(node, ast.FunctionDef):
                continue
            visitor = CallVisitor()
            visitor.visit(node)
            callees = visitor.callees
            callees.discard(node.name)
            callees = list(callees)

            name = str(node.name)

            def name_to_str(name):
                if name is None:
                    return None
                if isinstance(name, ast.Constant):
                    return name.value
                if isinstance(name, ast.Name):
                    return name.id
                if isinstance(name, ast.Attribute):
                    return name_to_str(name.value) + '.' + name.attr
                return str(name)

            params = []
            func_prototype = f"def {name}("
            for a in node.args.args:
                func_prototype += f"{a.arg}, "
                params.append(dict(
                    arg=str(a.arg),
                    annotation=name_to_str(a.annotation)
                ))
            func_prototype = func_prototype.strip(' ,')
            func_prototype += '):\n    pass'


            # TODO type hints?

            functions.append(
                {
                    "name": name,
                    "body": astunparse.unparse(node).strip(),
                    "params": params,
                    "callees": callees,
                    "prototype": func_prototype
                }
            )
        
        main_func = next((
            f for f in functions
            if all(
                f['name'] not in f['callees']
                for f in functions
            )
        ), None)
        if not main_func:
            raise ValueError('No main function found in result')

        program_code = '\n\n'.join(f['body'] for f in functions)

        cls.warn_static(f'Program code: {main_func["body"]}')

        return cls(
            name=main_func['name'],
            source_code=program_code,
            arguments=main_func['params'],
            #exec_code=exec_code,
            functions={f['name']: f for f in functions}
        )

    def get_function_main_prototype(self) -> str:
        func_info = self.functions.get(self.name)
        if not func_info:
            raise ValueError(f'Function {self.name} not found in code')
        return func_info.get('prototype')

    def execute_code(
        self,
        *args,
        code_exec_environment=None,
        **kwargs
    ) -> "CodeExecutionResult":
        """Run the generated code withing the given environment and return the result"""
        if code_exec_environment is None:
            code_exec_environment = CodeExecutionEnvironment()
        return code_exec_environment.execute(self)

    def create_execution_result(self, return_val: Any, exception=None):
        if exception:
            if isinstance(exception, Exception):
                exception = CodeExecutionException.from_exception(exception)
            elif not isinstance(exception, CodeExecutionException):
                exception = CodeExecutionException.from_exception(
                    Exception(str(exception))
                )
        return CodeExecutionResult(
            code=self,
            return_value=return_val,
            exception=exception
        )


    @classmethod
    def missing_code(cls) -> "Code":
        return MissingCode()

class MissingCode(Code):
    """Used to denote that no code was generated"""
    source_code: str = 'NO VALID SOURCE CODE GENERATED'
    name: str = 'missing_code'
    arguments: None = None
    functions: None = None
    language: str = "none"



class CodeExecutionResult(SaveLoadObject):
    return_value: Any
    code: Optional[Code] = None
    exception: Optional[CodeExecutionException] = None

    @classmethod
    def from_exception(cls, e: Exception) -> "CodeExecutionResult":
        return cls(
            code=Code.missing_code(),
            exception=CodeExecutionException.from_exception(e)
        )
    

class GeneratedCode(Code):
    pass

class PythonCode(Code):
    language: str = "python"