import argparse
import functools
import hashlib
import logging
import os
import tempfile
import shutil
import json
import multiprocessing

from typing import List, Dict, Tuple, Set, Optional, Union
from pathlib import Path

import git
import yaml
from antlr4 import *
from antlr4.error.ErrorListener import ErrorListener
from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES_JVM
from shellphish_crs_utils.utils import (
    artiphishell_should_fail_on_error,
    safe_decode_string,
)
from tqdm import tqdm

from antlrlib import JavaParserVisitor
import antlr4
from antlrlib import JavaParserListener
from antlrlib.JavaLexer import JavaLexer
from antlrlib.JavaParser import JavaParser

from git import Repo

from shellphish_crs_utils.models.indexer import FunctionIndex
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject

try:
    from crs_telemetry.utils import (
        init_otel,
        get_otel_tracer,
        get_current_span,
        status_ok,
    )
except ImportError:
    if not os.getenv("ARTIPHISHELL_TELEMETRY_OPTIONAL", "0") == "1":
        raise

init_otel("antlr4_indexer", "static_analysis", "file_and_function_indexing")
tracer = get_otel_tracer()

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]")
log = logging.getLogger("AntlrParser")
# log.propagate = False


def adjust_path_info(
    file_artifacts_path: Path, project: OSSFuzzProject
) -> Optional[Tuple[Path, Optional[Path]]]:
    container_path = project.target_container_path(artifact_path=file_artifacts_path)
    if not project.is_source_container_path_relevant(container_path):
        return None
    return container_path, project.focus_repo_rel_path(container_path=container_path)


def format_variable_declaration(var_type: str, var_name: str) -> str:
    return f"{var_type} {var_name}".strip()


def create_global_variable_reference(var_type: str, var_name: str) -> Dict[str, str]:
    declaration = f"{var_type} {var_name}".strip()
    return {
        "unique_identifier": f"{var_type}::{var_name}",
        "name": var_name,
        "type": var_type,
        "declaration": declaration,
        "raw_comment": None,
        "declaration_start_line": 0,
        "declaration_end_line": 0,
        "declaration_start_offset": 0,
        "declaration_end_offset": 0,
        "declaration_start_column": 0,
        "declaration_end_column": 0,
    }


class ImportCollector(JavaParserListener):
    def __init__(self):
        self.imports = []
        self.package_name = ""

    def enterPackageDeclaration(self, ctx):
        self.package_name = ctx.qualifiedName().getText()

    def enterImportDeclaration(self, ctx):
        import_stmt = ctx.getText()
        # Remove 'import' and trailing semicolon
        import_stmt = import_stmt.replace("import", "").replace(";", "").strip()
        self.imports.append(import_stmt)


class FieldDeclarationInInterfaceDeclarationSubTreeListener(JavaParserListener):
    def __init__(self):
        self.depth = 0
        self.root_interface = None
        self.field_declarations = []

    def enterInterfaceDeclaration(self, ctx):
        if not self.root_interface:
            self.root_interface = ctx
            return
        if ctx == self.root_interface:
            return
        self.depth += 1

    def exitInterfaceDeclaration(self, ctx):
        if ctx == self.root_interface:
            return
        self.depth -= 1
        assert self.depth >= 0, "Depth is negative"

    def enterFieldDeclaration(self, ctx):
        if self.depth == 0:
            vdecl = ctx.variableDeclarators()
            if vdecl is None:
                return
            var_decl_list = vdecl.variableDeclarator()
            if var_decl_list is None:
                return
            for variable_declarator in var_decl_list:
                try:
                    var_name = variable_declarator.variableDeclaratorId().getText()
                    var_type = (
                        ctx.typeType().getText() if ctx.typeType() is not None else ""
                    )
                    # Return structured format for global variables
                    self.field_declarations.append(create_global_variable_reference(var_type, var_name))
                except Exception as e:
                    log.warning("Skipping field declaration due to error: %s", e)


class FieldDeclarationInClassDeclarationSubTreeListener(JavaParserListener):
    def __init__(self):
        self.depth = 0
        self.root_cd = None
        self.field_declarations = []

    def enterClassDeclaration(self, ctx):
        if not self.root_cd:
            self.root_cd = ctx
            return
        if ctx == self.root_cd:
            return
        self.depth += 1

    def exitClassDeclaration(self, ctx):
        if ctx == self.root_cd:
            return
        self.depth -= 1
        assert self.depth >= 0, "Depth is negative"

    def enterFieldDeclaration(self, ctx):
        if self.depth == 0:
            vdecl = ctx.variableDeclarators()
            if vdecl is None:
                return
            var_decl_list = vdecl.variableDeclarator()
            if var_decl_list is None:
                return
            for variable_declarator in var_decl_list:
                try:
                    var_name = variable_declarator.variableDeclaratorId().getText()
                    var_type = (
                        ctx.typeType().getText() if ctx.typeType() is not None else ""
                    )
                    self.field_declarations.append(create_global_variable_reference(var_type, var_name))
                except Exception as e:
                    log.warning("Skipping field declaration due to error: %s", e)


class MethodDeclarationSubTreeListener(JavaParserListener):
    def __init__(self):
        self.depth = 0
        self.root_md = None

    def enterMethodDeclaration(self, ctx):
        if not self.root_md:
            self.root_md = ctx
            return
        if ctx == self.root_md:
            return
        self.depth += 1

    def exitMethodDeclaration(self, ctx):
        if ctx == self.root_md:
            return
        self.depth -= 1
        assert self.depth >= 0, "Depth is negative"


class MethodCallInMDSTListener(MethodDeclarationSubTreeListener):
    def __init__(self):
        super().__init__()
        self.method_calls = []

    def enterMethodCall(self, ctx):
        if self.depth == 0:
            self.method_calls.append(ctx.getText())


class LocalVariableDeclarationInMDSTListener(MethodDeclarationSubTreeListener):
    def __init__(self):
        super().__init__()
        self.variable_declarations = []

    def enterLocalVariableDeclaration(self, ctx):
        if self.depth == 0:
            vdecl = ctx.variableDeclarators()
            if vdecl is None:
                return
            var_decl_list = vdecl.variableDeclarator()
            if var_decl_list is None:
                return
            for variable_declarator in var_decl_list:
                try:
                    var_name = variable_declarator.variableDeclaratorId().getText()
                    var_type = (
                        ctx.typeType().getText() if ctx.typeType() is not None else ""
                    )
                    self.variable_declarations.append(format_variable_declaration(var_type, var_name))
                except Exception as e:
                    log.warning(
                        "Skipping local variable declaration due to error: %s", e
                    )


class VariableReferenceInMDSTListener(MethodDeclarationSubTreeListener):
    def __init__(self):
        super().__init__()
        self.variable_references = set()
        self.local_variable_names = set()

    def set_local_variables(self, local_vars):
        for var_decl in local_vars:
            # Extract variable name from declaration like "String name"
            parts = var_decl.strip().split()
            if len(parts) >= 2:
                var_name = parts[-1]  # Last part is the variable name
                self.local_variable_names.add(var_name)

    def enterPrimary(self, ctx):
        if self.depth == 0 and ctx.identifier():
            var_name = ctx.identifier().getText()
            # Only add if it's not a local variable
            if var_name not in self.local_variable_names:
                self.variable_references.add(var_name)

    def enterExpression(self, ctx):
        if self.depth == 0:
            # Handle field access expressions like this.fieldName or obj.fieldName
            if hasattr(ctx, 'bop') and ctx.bop and ctx.bop.text == '.':
                # Get the right side of the dot
                if len(ctx.children) >= 3:
                    right_side = ctx.children[2].getText()
                    # Only add if it's not a local variable
                    if right_side not in self.local_variable_names:
                        self.variable_references.add(right_side)

    def enterFieldAccess(self, ctx):
        if self.depth == 0 and ctx.identifier():
            field_name = ctx.identifier().getText()
            # Only add if it's not a local variable
            if field_name not in self.local_variable_names:
                self.variable_references.add(field_name)


class InterfaceMethodVariableReferenceListener(JavaParserListener):
    def __init__(self):
        self.variable_references = set()
        self.local_variable_names = set()

    def set_local_variables(self, local_vars):
        for var_decl in local_vars:
            # Extract variable name from declaration like "String name"
            parts = var_decl.strip().split()
            if len(parts) >= 2:
                var_name = parts[-1]  # Last part is the variable name
                self.local_variable_names.add(var_name)

    def enterPrimary(self, ctx):
        if ctx.identifier():
            var_name = ctx.identifier().getText()
            # Only add if it's not a local variable
            if var_name not in self.local_variable_names:
                self.variable_references.add(var_name)

    def enterExpression(self, ctx):
        # Handle field access expressions like this.fieldName or obj.fieldName
        if hasattr(ctx, 'bop') and ctx.bop and ctx.bop.text == '.':
            # Get the right side of the dot
            if len(ctx.children) >= 3:
                right_side = ctx.children[2].getText()
                # Only add if it's not a local variable
                if right_side not in self.local_variable_names:
                    self.variable_references.add(right_side)

    def enterFieldAccess(self, ctx):
        if ctx.identifier():
            field_name = ctx.identifier().getText()
            # Only add if it's not a local variable
            if field_name not in self.local_variable_names:
                self.variable_references.add(field_name)


def get_used_global_variables(method_ctx, all_global_variables, local_variables, is_interface_method=False):
    if is_interface_method:
        # For interface methods, check if there's a method body
        if not (hasattr(method_ctx, "methodBody") and method_ctx.methodBody() and method_ctx.methodBody().block()):
            return []
        method_body = method_ctx.methodBody()
    else:
        # For regular methods
        if not (hasattr(method_ctx, "methodBody") and method_ctx.methodBody() and method_ctx.methodBody().block()):
            return []
        method_body = method_ctx.methodBody()
    
    # Collect all variable references in the method
    walker = antlr4.ParseTreeWalker()
    if is_interface_method:
        var_ref_listener = InterfaceMethodVariableReferenceListener()
    else:
        var_ref_listener = VariableReferenceInMDSTListener()
    
    var_ref_listener.set_local_variables(local_variables)
    walker.walk(var_ref_listener, method_body)
    
    # Filter global variables to only include those referenced in the method
    used_globals = []
    referenced_names = var_ref_listener.variable_references
    
    for global_var in all_global_variables:
        # Extract variable name from the global variable info
        var_name = global_var.get("name", "")
        if var_name in referenced_names:
            used_globals.append(global_var)
    
    return used_globals


class AnnotationCollector(JavaParserListener):
    def __init__(self):
        self.annotations = []

    def enterAnnotation(self, ctx):
        try:
            # Get the annotation name without the @ symbol
            annotation_name = ctx.qualifiedName().getText()
            self.annotations.append(annotation_name)
        except Exception as e:
            log.warning("Error processing annotation: %s", e)


class MethodExtractorListener(JavaParserListener):
    def __init__(self, filename: str, imports=None):
        self.methods = []
        self.filename = filename
        self.anon_counter = {}
        self.imports = imports or []

    def get_annotations_start_line(self, ctx, current_ctx=None):
        if current_ctx is None:
            current_ctx = ctx.parentCtx
        
        first_annotation_line = None
        
        while current_ctx is not None:
            if isinstance(current_ctx, JavaParser.ClassBodyDeclarationContext):
                if hasattr(current_ctx, "modifier") and current_ctx.modifier():
                    for mod in current_ctx.modifier():
                        if mod.getText().startswith("@"):
                            # This is an annotation
                            annotation_line = mod.start.line
                            if first_annotation_line is None or annotation_line < first_annotation_line:
                                first_annotation_line = annotation_line
                break
            elif isinstance(current_ctx, JavaParser.InterfaceBodyDeclarationContext):
                # For interface methods, check interface body declaration
                if hasattr(current_ctx, "interfaceMethodModifier") and current_ctx.interfaceMethodModifier():
                    for mod in current_ctx.interfaceMethodModifier():
                        if mod.getText().startswith("@"):
                            annotation_line = mod.start.line
                            if first_annotation_line is None or annotation_line < first_annotation_line:
                                first_annotation_line = annotation_line
                break
            current_ctx = current_ctx.parentCtx
        
        return first_annotation_line

    def _trim_leading_whitespace(self, text):
        lines = text.split('\n')
        if not lines:
            return text
            
        # Find the minimum indentation (excluding empty lines)
        non_empty_lines = [line for line in lines if line.strip()]
        if not non_empty_lines:
            return text
            
        min_indent = min(len(line) - len(line.lstrip()) for line in non_empty_lines)
        
        # Remove the minimum indentation from all lines
        trimmed_lines = []
        for line in lines:
            if line.strip():  # Non-empty line
                trimmed_lines.append(line[min_indent:] if len(line) >= min_indent else line)
            else:  # Empty line
                trimmed_lines.append('')
                
        return '\n'.join(trimmed_lines)

    def _signature_is_complete(self, method_text, modifiers, annotations):
        lines = method_text.split('\n')
        first_few_lines = '\n'.join(lines[:10])  # Check first 10 lines for signature
        
        # Check for annotations
        for annotation in annotations:
            if f"@{annotation}" not in first_few_lines:
                return False
        
        # Check for modifiers (but be careful with keywords that might appear in method body)
        for modifier in modifiers:
            if modifier not in first_few_lines:
                return False
        
        return True

    def _reconstruct_complete_method(self, original_method_text, modifiers, annotations, return_type, method_name, parameters):
        try:
            # Find the method body (everything after the method declaration)
            lines = original_method_text.split('\n')
            
            # Find where the method body starts (look for opening brace)
            method_body_start = -1
            declaration_lines = []
            in_declaration = True
            
            for i, line in enumerate(lines):
                if in_declaration:
                    declaration_lines.append(line)
                    if '{' in line:
                        method_body_start = i
                        in_declaration = False
                        # If there's content after the opening brace, keep it
                        brace_pos = line.find('{')
                        if brace_pos + 1 < len(line) and line[brace_pos + 1:].strip():
                            declaration_lines[-1] = line[:brace_pos + 1]
                            # Add the rest as the start of method body
                            if i + 1 < len(lines):
                                lines[i + 1] = line[brace_pos + 1:] + '\n' + lines[i + 1]
                            else:
                                lines.append(line[brace_pos + 1:])
                        break
            
            if method_body_start == -1:
                # Abstract method or interface method without body
                method_body = ""
            else:
                method_body = '\n'.join(lines[method_body_start + 1:])
            
            # Reconstruct complete signature
            signature_parts = []
            
            # Add annotations
            for annotation in annotations:
                signature_parts.append(f"@{annotation}")
            
            # Add modifiers, return type, method name, and parameters
            modifier_str = " ".join(modifiers).strip()
            if modifier_str:
                method_declaration = f"{modifier_str} {return_type} {method_name}({', '.join(parameters)})"
            else:
                method_declaration = f"{return_type} {method_name}({', '.join(parameters)})"
            
            signature_parts.append(method_declaration.strip())
            
            # Combine signature with method body
            if method_body_start != -1:
                # Method has a body
                complete_method = '\n'.join(signature_parts) + " {\n" + method_body
            else:
                # Abstract method or interface method
                if any(line.strip().endswith(';') for line in declaration_lines):
                    complete_method = '\n'.join(signature_parts) + ";"
                else:
                    complete_method = '\n'.join(signature_parts) + " {\n" + method_body
            
            return complete_method
            
        except Exception as e:
            log.warning(f"Could not reconstruct complete method signature: {e}")
            # Final fallback: just return original text
            return original_method_text

    def get_method_code_with_complete_signature(self, method_ctx, actual_start_line, modifiers, annotations, return_type, method_name, parameters):
        try:
            input_stream = method_ctx.start.getInputStream()
            
            # If actual_start_line is different from method_ctx.start.line,
            # it means we have annotations before the method
            if actual_start_line < method_ctx.start.line:
                # Get the full text and split into lines to calculate character offset
                full_text = input_stream.getText(0, method_ctx.stop.stop)
                lines = full_text.split('\n')
                
                # Calculate character offset for actual_start_line (1-based line numbers)
                char_offset = 0
                for i in range(actual_start_line - 1):
                    if i < len(lines):
                        char_offset += len(lines[i]) + 1  # +1 for newline character
                
                # Extract from annotation start to method end
                extracted_text = input_stream.getText(char_offset, method_ctx.stop.stop)
                # Remove leading whitespace from each line while preserving relative indentation
                return self._trim_leading_whitespace(extracted_text)
            
            # No annotations before method, but we still need to ensure complete signature
            extracted_text = input_stream.getText(method_ctx.start.start, method_ctx.stop.stop)
            extracted_text = self._trim_leading_whitespace(extracted_text)
            
            # Verify that the extracted text contains all modifiers and annotations
            # If not, reconstruct the signature
            if not self._signature_is_complete(extracted_text, modifiers, annotations):
                return self._reconstruct_complete_method(extracted_text, modifiers, annotations, return_type, method_name, parameters)
            
            return extracted_text
            
        except Exception as e:
            log.warning(f"Could not extract method with complete signature: {e}")
            # Fallback: reconstruct the method with complete signature
            return self._reconstruct_complete_method(
                method_ctx.start.getInputStream().getText(method_ctx.start.start, method_ctx.stop.stop),
                modifiers, annotations, return_type, method_name, parameters
            )

    def process_annotations(self, annotations_list, method_specific_info):
        annotations_info = []

        for annotation in annotations_list:
            # Check if annotation exists in imports
            possible_imports = []
            exact_match = False

            for import_stmt in self.imports:
                # Check for exact match
                if import_stmt.endswith(f".{annotation}"):
                    possible_imports = [import_stmt]
                    exact_match = True
                    break
                # Check for wildcard imports
                if import_stmt.endswith(".*"):
                    possible_imports.append(import_stmt)

            # If no exact match but there are wildcards, include all wildcards
            if not exact_match and possible_imports:
                annotations_info.append(
                    {
                        "identifier": f"@{annotation}",
                        "possible_import": possible_imports,
                    }
                )
            # If there's an exact match, just include that one
            elif exact_match:
                annotations_info.append(
                    {
                        "identifier": f"@{annotation}",
                        "possible_import": possible_imports,
                    }
                )

        # Only add annotations if there are any
        if annotations_info:
            method_specific_info["annotations"] = annotations_info

        return method_specific_info

    def enterInterfaceMethodDeclaration(self, ctx):
        if hasattr(ctx, 'interfaceCommonBodyDeclaration') and ctx.interfaceCommonBodyDeclaration():
            common_body = ctx.interfaceCommonBodyDeclaration()
            if hasattr(common_body, 'identifier') and common_body.identifier():
                self._process_interface_method_declaration(ctx, common_body)

    def _process_interface_method_declaration(self, interface_method_ctx, common_body_ctx):
        method_name = common_body_ctx.identifier().getText()
        
        package_name = ""
        class_names = []
        outer_method = None
        anon_context = None
        current = interface_method_ctx.parentCtx
        class_or_interface_decl_ctx = None
        
        is_interface_method = True
        container_type = "interface"

        modifiers = []
        method_annotations = []

        first_annotation_line = None
        if hasattr(interface_method_ctx, 'interfaceMethodModifier'):
            for mod_ctx in interface_method_ctx.interfaceMethodModifier():
                if mod_ctx:
                    modifier_text = mod_ctx.getText()
                    if modifier_text.startswith("@"):
                        method_annotations.append(modifier_text[1:])
                        # Track the first annotation's line
                        annotation_line = mod_ctx.start.line
                        if first_annotation_line is None or annotation_line < first_annotation_line:
                            first_annotation_line = annotation_line
                    else:
                        modifiers.append(modifier_text)

        # Use annotation start line if available, otherwise use method start line
        actual_start_line = first_annotation_line if first_annotation_line is not None else interface_method_ctx.start.line

        modifier_str = " ".join(modifiers).strip()

        method_specific_info = {}
        self.process_annotations(method_annotations, method_specific_info)

        current = interface_method_ctx.parentCtx
        while current:
            for child in current.children or []:
                if isinstance(child, JavaParser.PackageDeclarationContext):
                    package_name = child.qualifiedName().getText()
                    break
                    
            if isinstance(current, JavaParser.ObjectCreationExpressionContext):
                anon_context = current
                
            if isinstance(current, JavaParser.InterfaceDeclarationContext):
                try:
                    identifier = current.identifier().getText()
                    class_names.insert(0, identifier)
                    class_or_interface_decl_ctx = current
                except Exception:
                    class_names.insert(0, f"Anonymous${len(class_names) + 1}")
                    
            elif isinstance(current, JavaParser.ClassDeclarationContext):
                try:
                    identifier = current.identifier().getText()
                    class_names.insert(0, identifier)
                    class_or_interface_decl_ctx = current
                except Exception:
                    class_names.insert(0, f"Anonymous${len(class_names) + 1}")
                    
            elif isinstance(current, JavaParser.EnumDeclarationContext):
                try:
                    identifier = current.identifier().getText()
                    class_names.insert(0, identifier)
                    class_or_interface_decl_ctx = current
                except Exception:
                    class_names.insert(0, f"Anonymous${len(class_names) + 1}")
                    
            current = current.parentCtx
            
        class_path = ".".join(class_names)
        full_name = (
            f"{package_name}.{class_path}.{method_name}"
            if class_path
            else f"{package_name}.{method_name}"
        )
        
        # Get return type from common body declaration
        return_type = ""
        if hasattr(common_body_ctx, "typeTypeOrVoid") and common_body_ctx.typeTypeOrVoid():
            return_type = common_body_ctx.typeTypeOrVoid().getText()
        
        parameters = []
        if hasattr(common_body_ctx, 'formalParameters') and common_body_ctx.formalParameters():
            formal_params = common_body_ctx.formalParameters()
            if formal_params.formalParameterList():
                for param in formal_params.formalParameterList().formalParameter():
                    param_type = param.typeType().getText() if param.typeType() else ""
                    param_name = param.variableDeclaratorId().getText() if param.variableDeclaratorId() else ""
                    parameters.append(f"{param_type} {param_name}")

        # Extract complete method including annotations and modifiers with original formatting
        complete_method_text = self.get_method_code_with_complete_signature(
            interface_method_ctx, actual_start_line, modifiers, method_annotations, return_type, method_name, parameters
        )

        has_body = hasattr(common_body_ctx, "methodBody") and common_body_ctx.methodBody() and common_body_ctx.methodBody().block()
        
        # Set interface method type
        method_specific_info["is_interface_method"] = True
        if "default" in modifier_str:
            method_specific_info["interface_method_type"] = "default"
        elif "static" in modifier_str:
            method_specific_info["interface_method_type"] = "static"
        else:
            method_specific_info["interface_method_type"] = "abstract"

        signature = f"{modifier_str} {return_type} {method_name}({', '.join(parameters)})".strip()

        local_variables = []
        if has_body:
            walker = antlr4.ParseTreeWalker()
            local_variable_listener = LocalVariableDeclarationInMDSTListener()
            walker.walk(local_variable_listener, common_body_ctx.methodBody())
            local_variables = local_variable_listener.variable_declarations

        func_calls = []
        if has_body:
            walker = antlr4.ParseTreeWalker()
            method_call_listener = MethodCallInMDSTListener()
            walker.walk(method_call_listener, common_body_ctx.methodBody())
            func_calls = method_call_listener.method_calls

        # Get ALL global variables first
        all_global_variables = []
        if class_or_interface_decl_ctx:
            walker = antlr4.ParseTreeWalker()
            global_variable_listener = FieldDeclarationInInterfaceDeclarationSubTreeListener()
            walker.walk(global_variable_listener, class_or_interface_decl_ctx)
            all_global_variables = global_variable_listener.field_declarations

        # Filter to only include global variables used by this method
        global_variables = get_used_global_variables(
            common_body_ctx, all_global_variables, local_variables, is_interface_method=True
        )

        comments = []
        
        unique_identifier = f"{return_type} {full_name}({', '.join(parameters)})"

        method_info = {
            "code": complete_method_text, # https://github.com/shellphish-support-syndicate/artiphishell/issues/2342
            "unique_identifier": unique_identifier,
            "raw_comment": "\n".join(comments),
            "target_compile_args": {},
            "was_directly_compiled": True,
            "start_line": actual_start_line, # From Boise, I was asked to modify the function's starting line to match the first annotation's line number of the function if function has annotation(s).
            "end_line": interface_method_ctx.stop.line,
            "start_offset": interface_method_ctx.start.start,
            "end_offset": interface_method_ctx.stop.stop,
            "start_column": interface_method_ctx.start.column,
            "end_column": interface_method_ctx.stop.column,
            "global_variables": global_variables,
            "signature": signature,
            "funcname": method_name,
            "full_funcname": full_name,
            "func_return_type": return_type,
            "arguments": parameters,
            "local_variables": local_variables,
            "func_calls_in_func_with_fullname": func_calls,
            "filename": self.filename,
            "class_name": f"{package_name}.{class_path}"
            if package_name
            else class_path,
            "comments": comments,
            "cfg": None,
            "package": package_name,
            "language_specific_info": method_specific_info,
        }
        
        self.methods.append(method_info)

    def enterMethodDeclaration(self, ctx):
        method_name = ctx.identifier().getText()
        package_name = ""
        class_names = []
        outer_method = None
        anon_context = None
        current = ctx.parentCtx
        class_body_decl_ctx = None
        class_decl_ctx = None

        modifiers = []
        method_annotations = []

        current = ctx.parentCtx
        while current is not None:
            if isinstance(current, JavaParser.ClassBodyDeclarationContext) and hasattr(
                current, "modifier"
            ):
                class_body_decl_ctx = current
                for mod in current.modifier():
                    if mod.getText().startswith("@"):
                        annotation_text = mod.getText()[1:]  # Remove @ symbol
                        method_annotations.append(annotation_text)
                    else:
                        modifiers.append(mod.getText())
                break
            current = current.parentCtx

        modifier_str = " ".join(modifiers).strip()

        method_specific_info = {}
        self.process_annotations(method_annotations, method_specific_info)

        # Get the start line - use annotation start line if annotations exist
        annotations_start_line = self.get_annotations_start_line(ctx)
        actual_start_line = annotations_start_line if annotations_start_line is not None else ctx.start.line

        current = ctx.parentCtx
        while current:
            for child in current.children or []:
                if isinstance(child, JavaParser.PackageDeclarationContext):
                    package_name = child.qualifiedName().getText()
                    break
            if isinstance(current, JavaParser.ObjectCreationExpressionContext):
                anon_context = current
            if (
                isinstance(current, JavaParser.MethodDeclarationContext)
                and outer_method is None
                and not isinstance(current, JavaParser.ObjectCreationExpressionContext)
            ):
                try:
                    outer_method = current.identifier().getText()
                except Exception:
                    pass
            if isinstance(
                current,
                (
                    JavaParser.ClassDeclarationContext,
                    JavaParser.InterfaceDeclarationContext,
                    JavaParser.EnumDeclarationContext,
                ),
            ):
                try:
                    identifier = current.identifier().getText()
                    class_names.insert(0, identifier)
                    if isinstance(current, JavaParser.ClassDeclarationContext):
                        class_decl_ctx = current
                except Exception:
                    class_names.insert(0, f"Anonymous${len(class_names) + 1}")
            current = current.parentCtx
        
        class_path = ".".join(class_names)
        if anon_context:
            key = (
                outer_method if outer_method is not None else "",
                anon_context.start.start,
            )
            if key not in self.anon_counter:
                self.anon_counter[key] = (
                    sum(1 for k in self.anon_counter if k[0] == key[0]) + 1
                )
            anon_label = f"Anonymous${self.anon_counter[key]}"
            if outer_method:
                full_name = f"{package_name}.{class_path}.{outer_method}.{anon_label}.{method_name}"
            else:
                full_name = f"{package_name}.{class_path}.{anon_label}.{method_name}"
        else:
            full_name = (
                f"{package_name}.{class_path}.{method_name}"
                if class_path
                else f"{package_name}.{method_name}"
            )
        
        return_type = (
            ctx.typeTypeOrVoid().getText()
            if hasattr(ctx, "typeTypeOrVoid") and ctx.typeTypeOrVoid()
            else ""
        )
        parameters = [
            f"{param.typeType().getText()} {param.variableDeclaratorId().getText()}"
            for param in (
                ctx.formalParameters().formalParameterList().formalParameter()
                if ctx.formalParameters()
                and ctx.formalParameters().formalParameterList()
                else []
            )
        ]

        # Extract complete method including annotations and modifiers with original formatting
        complete_method_text = self.get_method_code_with_complete_signature(
            ctx, actual_start_line, modifiers, method_annotations, return_type, method_name, parameters
        )

        signature = f"{modifier_str} {return_type} {method_name}({', '.join(parameters)})".strip()

        local_variables = []
        if hasattr(ctx, "methodBody") and ctx.methodBody() and ctx.methodBody().block():
            walker = antlr4.ParseTreeWalker()
            local_variable_listener = LocalVariableDeclarationInMDSTListener()
            walker.walk(local_variable_listener, ctx.getRuleContext())
            local_variables = local_variable_listener.variable_declarations

        if hasattr(ctx, "methodBody") and ctx.methodBody() and ctx.methodBody().block():
            for block_stmt in ctx.methodBody().block().blockStatement():
                if (
                    block_stmt.localVariableDeclaration()
                    and block_stmt.localVariableDeclaration().variableDeclarators()
                ):
                    local_decl = block_stmt.localVariableDeclaration()
                    var_type = (
                        local_decl.typeType().getText()
                        if local_decl.typeType() is not None
                        else ""
                    )
                    for (
                        variable_declarator
                    ) in local_decl.variableDeclarators().variableDeclarator():
                        try:
                            var_name = (
                                variable_declarator.variableDeclaratorId().getText()
                            )
                            var_declaration = format_variable_declaration(var_type, var_name)
                            if var_declaration not in local_variables:
                                local_variables.append(var_declaration)
                        except Exception as e:
                            log.warning(
                                "Skipping local variable in method body due to error: %s",
                                e,
                            )

        comments = []
        if class_body_decl_ctx:
            for token in reversed(
                class_body_decl_ctx.parser.getTokenStream().tokens[
                    : class_body_decl_ctx.start.tokenIndex
                ]
            ):
                if token.type == JavaParser.WS:
                    continue
                if (
                    token.type == JavaParser.COMMENT
                    and token.text.startswith("/**")
                    and token.text.endswith("*/")
                ):
                    javadoc = "\n".join(
                        [
                            line.strip().strip("*").strip()
                            for line in token.text.splitlines()
                            if not line.strip().startswith("/**")
                            and not line.strip().startswith("*/")
                        ]
                    )
                    comments.append(javadoc)
                break

        walker = antlr4.ParseTreeWalker()
        method_call_listener = MethodCallInMDSTListener()
        walker.walk(method_call_listener, ctx.getRuleContext())
        func_calls = method_call_listener.method_calls

        # Get ALL global variables first
        all_global_variables = []
        if class_decl_ctx:
            global_variable_listener = (
                FieldDeclarationInClassDeclarationSubTreeListener()
            )
            walker.walk(global_variable_listener, class_decl_ctx.getRuleContext())
            all_global_variables = global_variable_listener.field_declarations

        # Filter to only include global variables used by this method
        global_variables = get_used_global_variables(
            ctx, all_global_variables, local_variables, is_interface_method=False
        )

        unique_identifier = f"{return_type} {full_name}({', '.join(parameters)})"

        self.methods.append(
            {
                "code": complete_method_text, # https://github.com/shellphish-support-syndicate/artiphishell/issues/2342
                "unique_identifier": unique_identifier,
                "raw_comment": "\n".join(comments),
                "target_compile_args": {},
                "was_directly_compiled": True,
                "start_line": actual_start_line, # From Boise, I was asked to modify the function's starting line to match the first annotation's line number of the function if function has annotation(s).
                "end_line": ctx.stop.line,
                "start_offset": ctx.start.start,
                "end_offset": ctx.stop.stop,
                "start_column": ctx.start.column,
                "end_column": ctx.stop.column,
                "global_variables": global_variables,
                "signature": signature,
                "funcname": method_name,
                "full_funcname": full_name,
                "func_return_type": return_type,
                "arguments": parameters,
                "local_variables": local_variables,
                "func_calls_in_func_with_fullname": func_calls,
                "filename": self.filename,
                "class_name": f"{package_name}.{class_path}"
                if package_name
                else class_path,
                "comments": comments,
                "cfg": None,
                "package": package_name,
                "language_specific_info": method_specific_info,
            }
        )


def extract_methods(java_file_path: Path) -> List[Dict]:
    with open(java_file_path, "r") as file:
        code = file.read()

    input_stream = antlr4.InputStream(code)
    lexer = JavaLexer(input_stream)
    token_stream = antlr4.CommonTokenStream(lexer)
    parser = JavaParser(token_stream)
    root = parser.compilationUnit()

    # First, collect all imports
    import_collector = ImportCollector()
    walker = antlr4.ParseTreeWalker()
    walker.walk(import_collector, root)

    # Then extract methods with the imports information
    listener = MethodExtractorListener(
        filename=java_file_path.name, imports=import_collector.imports
    )
    walker.walk(listener, root)

    return listener.methods


@tracer.start_as_current_span("antlr4_indexer.process_file")
def process_file(file_path: Path, project: OSSFuzzProject) -> List[FunctionIndex]:
    if file_path.suffix not in VALID_SOURCE_FILE_SUFFIXES_JVM:
        return []
    try:
        result = adjust_path_info(file_path, project)
        if result is None:
            log.info(
                "Skipping file %s because it is in an ignored directory", file_path
            )
            return []
        target_container_path, focus_dir_relative_path = result
    except Exception as e:
        log.error(
            "Error computing relative paths for file %s: %s",
            file_path,
            e,
            exc_info=True,
        )
        if artiphishell_should_fail_on_error():
            raise
        return []

    try:
        methods = extract_methods(file_path)
        function_indexes = []
        for method in methods:
            method["target_container_path"] = str(target_container_path)
            method["focus_repo_relative_path"] = (
                str(focus_dir_relative_path)
                if focus_dir_relative_path is not None
                else None
            )
            method["is_generated_during_build"] = (
                project.is_path_generated_during_build(
                    container_path=target_container_path
                )
            )
            full_signature = method["unique_identifier"] + method["code"]
            method["hash"] = hashlib.sha256(full_signature.encode()).hexdigest()
            function_index = FunctionIndex(**method)
            function_indexes.append(function_index)
        return function_indexes
    except Exception as e:
        log.error("Error processing file %s: %s", file_path, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise
        return []


# --- Commit Mode Helper Functions ---


def _get_changed_files(commit: git.Commit) -> List[str]:
    changed_files = []
    if commit.parents:
        commit_diff = commit.diff(commit.parents[0], create_patch=True)
    else:
        commit_diff = commit.diff(git.NULL_TREE, create_patch=True)
    for diff in commit_diff:
        path = diff.a_path
        if path and any(
            path.endswith(suffix) for suffix in VALID_SOURCE_FILE_SUFFIXES_JVM
        ):
            changed_files.append(path)
    return changed_files


def _get_commit_ids(repo: git.Repo) -> List[str]:
    commit_ids = [commit.hexsha for commit in repo.iter_commits()]
    commit_ids.reverse()
    return commit_ids


def _get_changed_functions_in_commit(commit: git.Commit, src_dir: Path, project: OSSFuzzProject) -> List[FunctionIndex]:
    changed_functions = []
    
    if commit.parents:
        commit_diff = commit.diff(commit.parents[0], create_patch=True)
    else:
        commit_diff = commit.diff(git.NULL_TREE, create_patch=True)
    
    for diff in commit_diff:
        if not diff.a_path or not any(diff.a_path.endswith(suffix) for suffix in VALID_SOURCE_FILE_SUFFIXES_JVM):
            continue
            
        file_path = src_dir / diff.a_path
        if not file_path.exists():
            continue
            
        # Get all functions from the current version of the file
        current_functions = process_file(file_path, project)
        
        if not commit.parents:
            changed_functions.extend(current_functions)
            continue
            
        try:
            # Get file content from parent commit
            parent_commit = commit.parents[0]
            try:
                parent_file_content = parent_commit.tree[diff.a_path].data_stream.read().decode('utf-8')
                
                # Write to temporary file and process
                with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as temp_file:
                    temp_file.write(parent_file_content)
                    temp_file_path = Path(temp_file.name)
                
                try:
                    parent_functions = extract_methods(temp_file_path)
                    # Convert to same format as current functions for comparison
                    parent_function_hashes = set()
                    for func in parent_functions:
                        # Create temporary FunctionIndex to get hash
                        func["target_container_path"] = str(file_path)  # dummy value
                        func["focus_repo_relative_path"] = None
                        func["is_generated_during_build"] = False
                        full_signature = func["unique_identifier"] + func["code"]
                        func_hash = hashlib.sha256(full_signature.encode()).hexdigest()
                        parent_function_hashes.add(func_hash)
                    
                    # Only include functions that are new or changed
                    for func in current_functions:
                        if func.hash not in parent_function_hashes:
                            changed_functions.append(func)
                            
                finally:
                    os.unlink(temp_file_path)
                    
            except KeyError:
                # File didn't exist in parent commit - all functions are new
                changed_functions.extend(current_functions)
                
        except Exception as e:
            log.warning(f"Error comparing with parent commit for {diff.a_path}: {e}")
            # Fallback: include all functions from the file
            changed_functions.extend(current_functions)
    
    return changed_functions


@tracer.start_as_current_span("antlr4_indexer.process_commit")
def process_commit(
    commit_id: str,
    index: int,
    repo: git.Repo,
    src_dir: Path,
    output_dir: Path,
    project: OSSFuzzProject,
):
    span = get_current_span()
    span.set_attribute("antlr4_indexer.commit_id", commit_id)
    span.set_attribute("antlr4_indexer.index", index)
    
    try:
        repo.git.checkout(commit_id, quiet=True)
        
        # Get only the functions that actually changed in this commit
        changed_functions = _get_changed_functions_in_commit(repo.commit(commit_id), src_dir, project)

        # Create commit-specific folders
        commit_id_dir = f"{index}_{commit_id}"
        class_folder = output_dir / commit_id_dir / "CLASS"
        method_folder = output_dir / commit_id_dir / "METHOD"
        macro_folder = output_dir / commit_id_dir / "MACRO"
        function_folder = output_dir / commit_id_dir / "FUNCTION"

        # Create all folders
        class_folder.mkdir(exist_ok=True, parents=True)
        method_folder.mkdir(exist_ok=True, parents=True)
        macro_folder.mkdir(exist_ok=True, parents=True)
        function_folder.mkdir(exist_ok=True, parents=True)

        log.info(f"Processing commit {commit_id} with {len(changed_functions)} changed functions")
        
        # Write only the changed functions
        processed_hashes = set()
        for method in changed_functions:
            if method.hash in processed_hashes:
                continue
            processed_hashes.add(method.hash)
            
            # Write output into the METHODS folder
            output_file = method_folder / f"{method.hash}.json"
            output_file.write_text(method.model_dump_json(indent=4))
            
    except Exception as e:
        log.error("Error processing commit %s: %s", commit_id, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise


def process_all_commit_mode(project: OSSFuzzProject, output_dir: Path):
    src_dir = project.get_focus_repo_artifacts_path()
    repo = Repo(src_dir)  # Assumes get_focus_repo_artifacts_path is a Git repo.
    commit_ids = _get_commit_ids(repo)
    log.info("Found %s commits to process.", len(commit_ids))
    for index, commit_id in enumerate(commit_ids):
        process_commit(commit_id, index, repo, src_dir, output_dir, project)


# --- Process all files in full mode ---
def process_all_full_mode(project: OSSFuzzProject, output_dir: Path):
    src_dir = project.artifacts_dir
    files = [
        f
        for suffix in VALID_SOURCE_FILE_SUFFIXES_JVM
        for f in src_dir.rglob(f"**/*{suffix}")
    ]
    class_folder = output_dir / "CLASS"
    method_folder = output_dir / "METHOD"
    macro_folder = output_dir / "MACRO"
    function_folder = output_dir / "FUNCTION"
    # Create folders if they don't exist.
    for folder in [class_folder, method_folder, macro_folder, function_folder]:
        folder.mkdir(exist_ok=True, parents=True)
    log.info("Found %s Java files to process in full mode.", len(files))
    new_process = functools.partial(process_file, project=project)
    with multiprocessing.Pool() as pool:
        for file_results in tqdm(pool.imap(new_process, files), total=len(files)):
            for method in file_results:
                try:
                    output_file = method_folder / f"{method.hash}.json"
                    output_file.write_text(method.model_dump_json(indent=4))
                    log.info("File Write Completed: %s", method.signature)
                except Exception as e:
                    log.error(
                        "Error writing method %s to file: %s",
                        method.signature,
                        e,
                        exc_info=True,
                    )
                    raise e


if __name__ == "__main__":
    parser_arg = argparse.ArgumentParser()
    parser_arg.add_argument(
        "--mode",
        type=str,
        choices=["commit", "full"],
        required=True,
        help="running mode",
    )
    parser_arg.add_argument(
        "--canonical-build-artifact",
        type=Path,
        required=True,
        help="source code of the target",
    )
    parser_arg.add_argument(
        "--project-source", type=Path, required=True, help="project source"
    )
    parser_arg.add_argument(
        "--output-dir", type=Path, required=True, help="parsed output"
    )
    args = parser_arg.parse_args()

    ossfuzzproject = OSSFuzzProject(
        oss_fuzz_project_path=args.canonical_build_artifact,
        project_source=args.project_source,
    )

    with tracer.start_as_current_span("antlr4_indexer") as span:
        span.set_attribute("antlr4_indexer.mode", args.mode)

        if args.mode == "commit":
            # pass
            process_all_commit_mode(ossfuzzproject, args.output_dir)
        elif args.mode == "full":
            process_all_full_mode(ossfuzzproject, args.output_dir)

        span.set_status(status_ok())
