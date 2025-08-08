import argparse
import functools
import hashlib
import logging
import os
import tempfile
import shutil

from typing import List, Dict, Tuple, Set, Optional, Union
from multiprocessing import Pool, cpu_count
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
from antlrlib.JavaLexer import JavaLexer
from antlrlib.JavaParser import JavaParser

from git import Repo

from shellphish_crs_utils.models.indexer import FunctionIndex, GlobalVariableReference
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
#log.propagate = False


# --- Helper functions ---
def adjust_path_info(file_artifacts_path: Path, project: OSSFuzzProject) -> Optional[Tuple[Path, Optional[Path]]]:
    container_path = project.target_container_path(artifact_path=file_artifacts_path)
    if not project.is_source_container_path_relevant(container_path):
        return None

    return container_path, project.focus_repo_rel_path(container_path=container_path)


class VerboseErrorListener(ErrorListener):
    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        try:
            with open(self.filename, 'r') as f:
                lines = f.readlines()
                error_line = lines[line - 1].rstrip()
        except Exception as file_error:
            error_line = f"<unable to read file: {file_error}>"

        pointer = " " * (column - 1) + "^"
        token_text = getattr(offendingSymbol, "text", "<unknown>") if offendingSymbol else "<unknown>"
        error_message = (
            f"Syntax error in file '{self.filename}' at line {line}, column {column}:\n"
            f"{error_line}\n"
            f"{pointer}\n"
            f"Offending token: {token_text}\n"
            f"Error details: {msg}"
        )
        log.error(error_message)


class Parser(JavaParserVisitor):
    def __init__(self, target_container_path: Path, focus_dir_relative_path: Optional[str] = None):
        super().__init__()
        self._class: List[Dict[str, List[FunctionIndex]]] = []
        self.current_package = ""
        self.target_container_path = target_container_path
        self.focus_dir_relative_path = focus_dir_relative_path
        self.current_class_stack: List[str] = []
        self.anon_counter = 0
        self.interface_implementations = {}
        self.processed_anonymous_classes: Set[Tuple[int, int]] = set()
        self.processed_methods: Set[Tuple[int, int]] = set()
        self.interfaces = {}
        self.static_interfaces = {}  # Track static interfaces separately, oh noooooooooo

    def visitPackageDeclaration(self, ctx: JavaParser.PackageDeclarationContext):
        package_name = ctx.qualifiedName().getText()
        self.current_package = package_name
        log.debug("Set current package to: %s", self.current_package)

    def extract_method_information(self, method_declaration, class_name, is_anonymous=False, interface_name=None,
                                   is_interface_method=False):
        try:
            # Create a unique identifier for this method
            method_identifier = (method_declaration.start.start, method_declaration.stop.stop)

            # Skip if we've already processed this method
            if method_identifier in self.processed_methods:
                log.debug("Skipping already processed method at position %s", method_identifier)
                return None

            # Mark this method as processed
            self.processed_methods.add(method_identifier)

            log.debug("Extracting method information in class: %s", class_name)
            method_tokens = method_declaration.parser.getTokenStream()
            method_declaration_text = ""
            method_signature = ""
            arguments = []
            func_return_type = ""
            static_method = "static" in method_declaration.getText()
            func_calls = []
            local_variables = []
            overrides = []
            generic_type_params = ""

            # Handle generic type parameters if present
            if hasattr(method_declaration, 'typeParameters') and method_declaration.typeParameters() is not None:
                generic_type_params = method_declaration.typeParameters().getText()
                log.debug("Found generic type parameters: %s", generic_type_params)

            # Check for @Override annotation
            if method_declaration.parentCtx and hasattr(method_declaration.parentCtx, 'modifier'):
                for modifier in method_declaration.parentCtx.modifier():
                    if modifier.classOrInterfaceModifier() and modifier.classOrInterfaceModifier().annotation():
                        if "Override" in modifier.classOrInterfaceModifier().annotation().getText():
                            overrides.append("Override")

            if interface_name:
                overrides.append(f"Implements {interface_name}")

            if generic_type_params:
                method_signature += generic_type_params + " "

            if method_declaration.typeTypeOrVoid() is not None:
                func_return_type = method_declaration.typeTypeOrVoid().getText()
                method_signature += func_return_type + " "

            method_signature += method_declaration.identifier().getText()

            if method_declaration.formalParameters() is not None:
                method_signature += method_declaration.formalParameters().getText()
                if method_declaration.formalParameters().formalParameterList() is not None:
                    for param in method_declaration.formalParameters().formalParameterList().formalParameter():
                        arguments.append(param.variableDeclaratorId().getText())

            # Collect the complete method text
            for token_index in range(method_declaration.start.tokenIndex, method_declaration.stop.tokenIndex + 1):
                text = method_tokens.get(token_index).text
                method_declaration_text += text
                if "()" in text:
                    func_calls.append(text.strip())

            if (hasattr(method_declaration, "methodBody") and
                    method_declaration.methodBody() and
                    method_declaration.methodBody().block()):
                for block_stmt in method_declaration.methodBody().block().blockStatement():
                    if (block_stmt.localVariableDeclaration() and
                            block_stmt.localVariableDeclaration().variableDeclarators()):
                        local_decl = block_stmt.localVariableDeclaration()
                        var_type = local_decl.typeType().getText() if local_decl.typeType() is not None else ""
                        for variable_declarator in local_decl.variableDeclarators().variableDeclarator():
                            var_name = variable_declarator.variableDeclaratorId().getText()
                            local_variables.append(f"{var_type} {var_name}")

            startline = method_declaration.start.line
            startcol = method_declaration.start.column
            endline = method_declaration.stop.line
            endcol = method_declaration.stop.column
            stat_offset = method_declaration.start.start
            end_offset = method_declaration.stop.stop
            method_name = method_declaration.identifier().getText()

            full_method_signature = f"{self.current_package}.{class_name}.{method_signature}"
            full_class_name_qualified = f"{self.current_package}.{class_name}"
            method_hash = hashlib.sha256(f'{full_method_signature}-{method_declaration_text}'.encode()).hexdigest()

            global_vars = []
            if static_method and not is_anonymous:
                parent_ctx = method_declaration
                while parent_ctx and not hasattr(parent_ctx, 'classBody'):
                    parent_ctx = parent_ctx.parentCtx

                if parent_ctx and hasattr(parent_ctx, 'classBody'):
                    for member in parent_ctx.classBody().classBodyDeclaration():
                        try:
                            member_decl = member.memberDeclaration()
                            if member_decl is None or not member_decl.fieldDeclaration():
                                continue
                            if "static" not in member.getText():
                                continue
                            field_decl = member_decl.fieldDeclaration()
                            var_type = (field_decl.typeType().getText()
                                        if hasattr(field_decl, "typeType") and field_decl.typeType() is not None
                                        else "")
                            for field in field_decl.variableDeclarators().variableDeclarator():
                                var_name = field.variableDeclaratorId().getText()
                                global_vars.append(GlobalVariableReference(
                                    unique_identifier=f"{self.current_package}.{class_name}.{var_name}",
                                    name=var_name,
                                    declaration=var_type
                                    ))
                        except AttributeError as e:
                            log.error("Error processing global variables: %s", e, exc_info=True)
                            if artiphishell_should_fail_on_error():
                                raise

            comments = []
            if is_anonymous:
                comments.append("Anonymous class method")

            if is_interface_method:
                comments.append("Interface method")

            javadoc = self.extract_javadoc(method_declaration)
            if javadoc:
                comments.append(javadoc)

            index = FunctionIndex(
                hash=method_hash,
                code=method_declaration_text,
                start_line=startline,
                start_column=startcol,
                start_offset=stat_offset,
                end_line=endline,
                end_column=endcol,
                end_offset=end_offset,
                global_variables=global_vars,
                signature=full_method_signature,
                func_return_type=func_return_type,
                arguments=arguments,
                local_variables=local_variables,
                class_name=full_class_name_qualified,
                funcname=method_name,
                full_funcname=f"{self.current_package}.{class_name}.{method_name}",
                func_calls_in_func_with_fullname=func_calls,
                package=self.current_package,
                comments=comments + overrides,
                filename=self.target_container_path.name,
                target_container_path=self.target_container_path,
                focus_repo_relative_path=self.focus_dir_relative_path,
                is_generated_during_build=ossfuzzproject.is_path_generated_during_build(
                    container_path=self.target_container_path)
            )
            log.info("Extracted method '%s' from class '%s'", method_name, full_class_name_qualified)
            return index
        except AttributeError as e:
            log.error("Error extracting method info: %s", e, exc_info=True)
            if artiphishell_should_fail_on_error():
                raise
            return None

    def extract_interface_method_information(self, method_declaration, interface_name, is_static_interface=False):
        try:
            method_identifier = (method_declaration.start.start, method_declaration.stop.stop)

            if method_identifier in self.processed_methods:
                log.debug("Skipping already processed interface method at position %s", method_identifier)
                return None

            self.processed_methods.add(method_identifier)

            log.debug("Extracting method information in interface: %s", interface_name)
            method_tokens = method_declaration.parser.getTokenStream()
            method_declaration_text = ""
            method_signature = ""
            arguments = []
            func_return_type = ""
            func_calls = []

            if method_declaration.typeTypeOrVoid() is not None:
                func_return_type = method_declaration.typeTypeOrVoid().getText()
                method_signature += func_return_type + " "

            method_signature += method_declaration.identifier().getText()

            if method_declaration.formalParameters() is not None:
                method_signature += method_declaration.formalParameters().getText()
                if method_declaration.formalParameters().formalParameterList() is not None:
                    for param in method_declaration.formalParameters().formalParameterList().formalParameter():
                        arguments.append(param.variableDeclaratorId().getText())

            for token_index in range(method_declaration.start.tokenIndex, method_declaration.stop.tokenIndex + 1):
                text = method_tokens.get(token_index).text
                method_declaration_text += text
                if "()" in text:
                    func_calls.append(text.strip())

            startline = method_declaration.start.line
            startcol = method_declaration.start.column
            endline = method_declaration.stop.line
            endcol = method_declaration.stop.column
            stat_offset = method_declaration.start.start
            end_offset = method_declaration.stop.stop
            method_name = method_declaration.identifier().getText()

            full_method_signature = f"{self.current_package}.{interface_name}.{method_signature}"
            full_interface_name_qualified = f"{self.current_package}.{interface_name}"
            method_hash = hashlib.sha256(f'{full_method_signature}-{method_declaration_text}'.encode()).hexdigest()

            comments = []
            if is_static_interface:
                comments.append("Static interface method")
            else:
                comments.append("Interface method")

            # Extract javadoc comments
            javadoc = self.extract_javadoc(method_declaration)
            if javadoc:
                comments.append(javadoc)

            index = FunctionIndex(
                hash=method_hash,
                code=method_declaration_text,
                start_line=startline,
                start_column=startcol,
                start_offset=stat_offset,
                end_line=endline,
                end_column=endcol,
                end_offset=end_offset,
                global_variables=[],  # Interface methods don't have global variables
                signature=full_method_signature,
                func_return_type=func_return_type,
                arguments=arguments,
                local_variables=[],  # Interface methods don't have local variables
                class_name=full_interface_name_qualified,
                funcname=method_name,
                full_funcname=f"{self.current_package}.{interface_name}.{method_name}",
                func_calls_in_func_with_fullname=func_calls,
                package=self.current_package,
                comments=comments,
                filename=self.target_container_path.name,
                target_container_path=self.target_container_path,
                focus_repo_relative_path=self.focus_dir_relative_path,
                is_generated_during_build=ossfuzzproject.is_path_generated_during_build(
                    container_path=self.target_container_path),
            )
            log.info("Extracted method '%s' from interface '%s'", method_name, full_interface_name_qualified)
            return index
        except AttributeError as e:
            log.error("Error extracting interface method info: %s", e, exc_info=True)
            if artiphishell_should_fail_on_error():
                raise
            return None

    def extract_javadoc(self, ctx):
        if ctx.parentCtx and hasattr(ctx.parentCtx, 'start'):
            token_stream = ctx.parser.getTokenStream()
            for i in range(ctx.parentCtx.start.tokenIndex - 1, max(0, ctx.parentCtx.start.tokenIndex - 10), -1):
                token = token_stream.get(i)
                if token.channel == 1:  # HIDDEN channel typically contains comments
                    comment_text = token.text.strip()
                    if comment_text.startswith("/**") and comment_text.endswith("*/"):
                        lines = comment_text.split('\n')
                        cleaned_lines = []
                        for line in lines:
                            line = line.strip().strip('*').strip()
                            if line and not line.startswith("/**") and not line.startswith("*/"):
                                cleaned_lines.append(line)
                        return "\n".join(cleaned_lines)
        return None

    def visitClassDeclaration(self, ctx: JavaParser.ClassDeclarationContext):
        # Process a named (or abstract) class declaration.
        class_name = ctx.identifier().getText()
        if self.current_class_stack:
            full_class_name = f"{'.'.join(self.current_class_stack)}.{class_name}"
        else:
            full_class_name = class_name
        log.debug("Processing class declaration: %s", full_class_name)
        self.current_class_stack.append(class_name)

        # Track implemented interfaces.
        implemented_interfaces = []
        if hasattr(ctx, 'typeList') and ctx.typeList() is not None:
            type_list = ctx.typeList()
            if isinstance(type_list, list):
                for typeRef in type_list:
                    if hasattr(typeRef, 'classOrInterfaceType') and typeRef.classOrInterfaceType() is not None:
                        interface_name = typeRef.classOrInterfaceType().getText()
                        implemented_interfaces.append(interface_name)
            else:
                if hasattr(type_list, 'typeType'):
                    for typeRef in type_list.typeType():
                        if typeRef.classOrInterfaceType() is not None:
                            interface_name = typeRef.classOrInterfaceType().getText()
                            implemented_interfaces.append(interface_name)
        self.interface_implementations[full_class_name] = implemented_interfaces

        _temp = {}
        _temp["Class Name"] = f"{self.current_package}.{full_class_name}"
        tokens = ctx.parser.getTokenStream()
        _decl = [tokens.get(token_index).text for token_index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1)]
        _temp["Class Declaration"] = _decl
        _temp["Implements"] = implemented_interfaces

        method_list = []

        # Process class body for methods, nested classes, and static inner interfaces
        for member in ctx.classBody().classBodyDeclaration():
            if member.memberDeclaration():
                log.debug("Processing member in class '%s': %s", full_class_name, member.getText()[:50])
                if hasattr(member.memberDeclaration(),
                           'interfaceDeclaration') and member.memberDeclaration().interfaceDeclaration() is not None:
                    is_static = False
                    if hasattr(member, 'modifier'):
                        for modifier in member.modifier():
                            if modifier.getText() == "static":
                                is_static = True
                    if is_static or "static" in member.getText():
                        log.info("Found static inner interface in class %s", full_class_name)
                        self.visitStaticInnerInterface(member.memberDeclaration().interfaceDeclaration())

                # Regular method processing – handle generic methods as well.
                elif (member.memberDeclaration().genericMethodDeclaration() is not None) or (
                        member.memberDeclaration().methodDeclaration() is not None):
                    method_decl = None
                    if member.memberDeclaration().genericMethodDeclaration() is not None:
                        method_decl = member.memberDeclaration().genericMethodDeclaration().methodDeclaration()
                    elif member.memberDeclaration().methodDeclaration() is not None:
                        method_decl = member.memberDeclaration().methodDeclaration()
                    if method_decl:
                        interface_name = None
                        if implemented_interfaces:
                            method_name = method_decl.identifier().getText()
                            for interface in implemented_interfaces:
                                if interface in self.interfaces:
                                    for method in self.interfaces[interface].get("methods", []):
                                        if method == method_name:
                                            interface_name = interface
                                            break
                        method_index = self.extract_method_information(
                            method_decl,
                            full_class_name,
                            interface_name=interface_name
                        )
                        if method_index:
                            method_list.append(method_index)
                elif member.memberDeclaration().classDeclaration() is not None:
                    log.debug("Found nested class declaration inside %s", full_class_name)
                    self.visit(member.memberDeclaration().classDeclaration())
                elif hasattr(member.memberDeclaration(),
                             'enumDeclaration') and member.memberDeclaration().enumDeclaration() is not None:
                    log.debug("Found nested enum declaration inside %s", full_class_name)
                    self.visit(member.memberDeclaration().enumDeclaration())
                elif member.memberDeclaration().fieldDeclaration() is not None:
                    # Process field declarations for potential anonymous classes
                    self.visit(member.memberDeclaration().fieldDeclaration())

        _temp["Method Declarations"] = method_list
        self._class.append(_temp)
        self.current_class_stack.pop()
        return None

    def visitEnumDeclaration(self, ctx: JavaParser.EnumDeclarationContext):
        enum_name = ctx.identifier().getText()
        if self.current_class_stack:
            full_enum_name = f"{'.'.join(self.current_class_stack)}.{enum_name}"
        else:
            full_enum_name = enum_name
        log.debug("Processing enum declaration: %s", full_enum_name)
        self.current_class_stack.append(enum_name)

        _temp = {}
        _temp["Enum Name"] = f"{self.current_package}.{full_enum_name}"
        tokens = ctx.parser.getTokenStream()
        _decl = [tokens.get(token_index).text for token_index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1)]
        _temp["Enum Declaration"] = _decl

        method_list = []

        if hasattr(ctx, "enumConstants") and ctx.enumConstants() is not None:
            for enumConstant in ctx.enumConstants().enumConstant():
                if hasattr(enumConstant, "classBody") and enumConstant.classBody() is not None:
                    log.info("Processing enum constant '%s' with a class body in enum '%s'",
                             enumConstant.identifier().getText(), full_enum_name)
                    self.processAnonymousClass(enumConstant.classBody(), enum_name)

        if hasattr(ctx, "enumBodyDeclarations") and ctx.enumBodyDeclarations() is not None:
            for member in ctx.enumBodyDeclarations().classBodyDeclaration():
                if member.memberDeclaration():
                    if (member.memberDeclaration().genericMethodDeclaration() is not None) or \
                            (member.memberDeclaration().methodDeclaration() is not None):
                        method_decl = None
                        if member.memberDeclaration().genericMethodDeclaration() is not None:
                            method_decl = member.memberDeclaration().genericMethodDeclaration().methodDeclaration()
                        elif member.memberDeclaration().methodDeclaration() is not None:
                            method_decl = member.memberDeclaration().methodDeclaration()
                        if method_decl:
                            method_index = self.extract_method_information(method_decl, full_enum_name)
                            if method_index:
                                method_list.append(method_index)
                    elif member.memberDeclaration().classDeclaration() is not None:
                        self.visit(member.memberDeclaration().classDeclaration())
                    elif member.memberDeclaration().fieldDeclaration() is not None:
                        self.visit(member.memberDeclaration().fieldDeclaration())

        _temp["Method Declarations"] = method_list
        self._class.append(_temp)
        self.current_class_stack.pop()
        return None

    def visitStaticInnerInterface(self, ctx: JavaParser.InterfaceDeclarationContext):
        # Process a static inner interface declaration
        interface_name = ctx.identifier().getText()
        if self.current_class_stack:
            full_interface_name = f"{'.'.join(self.current_class_stack)}.{interface_name}"
        else:
            full_interface_name = interface_name

        log.debug("Processing static inner interface declaration: %s", full_interface_name)
        self.current_class_stack.append(interface_name)

        _temp = {}
        _temp["Interface Name"] = f"{self.current_package}.{full_interface_name}"
        tokens = ctx.parser.getTokenStream()
        _decl = [tokens.get(token_index).text for token_index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1)]
        _temp["Interface Declaration"] = _decl
        _temp["Type"] = "Static Interface"

        # Build interface methods UHHHHHHH
        interface_method_names = []
        method_list = []

        if ctx.interfaceBody():
            for member in ctx.interfaceBody().interfaceBodyDeclaration():
                if member.interfaceMemberDeclaration() is not None:
                    if hasattr(member.interfaceMemberDeclaration(), "interfaceMethodDeclaration") and \
                            member.interfaceMemberDeclaration().interfaceMethodDeclaration() is not None:
                        method_decl = member.interfaceMemberDeclaration().interfaceMethodDeclaration()

                        if hasattr(method_decl, "identifier") and method_decl.identifier() is not None:
                            method_name = method_decl.identifier().getText()
                            interface_method_names.append(method_name)

                            method_index = self.extract_interface_method_information(
                                method_decl,
                                full_interface_name,
                                is_static_interface=True
                            )

                            if method_index:
                                method_list.append(method_index)

        # Store the interface for later reference UHHHHHHH
        self.interfaces[full_interface_name] = {
            "methods": interface_method_names,
            "declaration": _decl,
            "is_static": True
        }

        _temp["Interface Methods"] = interface_method_names
        _temp["Method Declarations"] = method_list
        self._class.append(_temp)
        self.current_class_stack.pop()

    def visitInterfaceDeclaration(self, ctx: JavaParser.InterfaceDeclarationContext):
        interface_name = ctx.identifier().getText()
        if self.current_class_stack:
            full_interface_name = f"{'.'.join(self.current_class_stack)}.{interface_name}"
        else:
            full_interface_name = interface_name
        log.debug("Processing interface declaration: %s", full_interface_name)
        self.current_class_stack.append(interface_name)

        _temp = {}
        _temp["Interface Name"] = f"{self.current_package}.{full_interface_name}"
        tokens = ctx.parser.getTokenStream()
        _decl = [tokens.get(token_index).text for token_index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1)]
        _temp["Interface Declaration"] = _decl
        _temp["Type"] = "Interface"

        # Build interface methods.
        interface_method_names = []
        method_list = []
        if ctx.interfaceBody():
            for member in ctx.interfaceBody().interfaceBodyDeclaration():
                # Process interface method declarations
                if hasattr(member, 'interfaceMemberDeclaration') and member.interfaceMemberDeclaration() is not None:
                    if hasattr(member.interfaceMemberDeclaration(),
                               'interfaceMethodDeclaration') and member.interfaceMemberDeclaration().interfaceMethodDeclaration():
                        method_decl = member.interfaceMemberDeclaration().interfaceMethodDeclaration()
                        if hasattr(method_decl, 'identifier') and method_decl.identifier():
                            method_name = method_decl.identifier().getText()
                            interface_method_names.append(method_name)

                            # Extract the full method information for the interface method
                            method_index = self.extract_interface_method_information(
                                method_decl,
                                full_interface_name,
                                is_static_interface=False
                            )
                            if method_index:
                                method_list.append(method_index)

                # Check for nested interface declarations
                if hasattr(member, 'interfaceMemberDeclaration') and member.interfaceMemberDeclaration() is not None:
                    if hasattr(member.interfaceMemberDeclaration(),
                               'interfaceDeclaration') and member.interfaceMemberDeclaration().interfaceDeclaration():
                        self.visit(member.interfaceMemberDeclaration().interfaceDeclaration())

                # Check for constant (field) declarations
                elif hasattr(member, 'constantDeclaration') and member.constantDeclaration() is not None:
                    for var in member.constantDeclaration().variableDeclarators().variableDeclarator():
                        if var.variableInitializer() is not None:
                            # Process variable initializers for potential anonymous classes
                            self.visitVariableInitializer(var.variableInitializer())

        self.interfaces[full_interface_name] = {
            "methods": interface_method_names,
            "declaration": _decl
        }

        _temp["Interface Methods"] = interface_method_names
        _temp["Method Declarations"] = method_list
        self._class.append(_temp)
        self.current_class_stack.pop()
        return self.visitChildren(ctx)

    def visitClassBody(self, ctx: JavaParser.ClassBodyContext):
        for decl in ctx.classBodyDeclaration():
            # Check for static initializers which might contain anonymous classes
            if decl.block() is not None and "static" in decl.getText():
                log.info("Processing static initializer block")
                # Process the static block for potential anonymous class creations
                self.visitBlock(decl.block())

            # Handle static inner interfaces
            if hasattr(decl, "memberDeclaration") and decl.memberDeclaration() is not None:
                # Check for static modifier
                is_static = False
                if hasattr(decl, "modifier"):
                    for modifier in decl.modifier():
                        if hasattr(modifier, "getText") and modifier.getText() == "static":
                            is_static = True
                            break

                if not is_static and "static" in decl.getText():
                    is_static = True

                if is_static and hasattr(decl.memberDeclaration(),
                                         "interfaceDeclaration") and decl.memberDeclaration().interfaceDeclaration() is not None:
                    log.info("Found static inner interface")
                    self.visitStaticInnerInterface(decl.memberDeclaration().interfaceDeclaration())

                elif hasattr(decl.memberDeclaration(), "classOrInterfaceModifier"):
                    for modifier in decl.memberDeclaration().classOrInterfaceModifier():
                        if "static" in modifier.getText():
                            is_static = True
                            break

                    if is_static and "interface" in decl.memberDeclaration().getText():
                        for child in decl.memberDeclaration().getChildren():
                            if hasattr(child, "getText") and "interface" in child.getText():
                                log.info("Found alternative format static inner interface")
                                self.visitStaticInnerInterface(child)

        return self.visitChildren(ctx)

    def visitFieldDeclaration(self, ctx: JavaParser.FieldDeclarationContext):
        if hasattr(ctx, "variableDeclarators") and ctx.variableDeclarators() is not None:
            for var in ctx.variableDeclarators().variableDeclarator():
                if var.variableInitializer() is not None:
                    self.visitVariableInitializer(var.variableInitializer())
        return self.visitChildren(ctx)

    def visitVariableInitializer(self, ctx):
        if hasattr(ctx, "expression") and ctx.expression() is not None:
            expr = ctx.expression()
            self.processExpressionForAnonymousClass(expr)
        return self.visitChildren(ctx)

    def processExpressionForAnonymousClass(self, expr):
        if hasattr(expr, "creator") and expr.creator() is not None:
            if hasattr(expr.creator(), "classCreatorRest") and expr.creator().classCreatorRest() is not None:
                if hasattr(expr.creator().classCreatorRest(),
                           "classBody") and expr.creator().classCreatorRest().classBody() is not None:
                    creator_type = expr.creator().createdName().getText() if hasattr(expr.creator(),
                                                                                     "createdName") else None
                    self.processAnonymousClass(expr.creator().classCreatorRest().classBody(), creator_type)

        if hasattr(expr, "primary") and expr.primary() is not None:
            primary = expr.primary()
            if hasattr(primary, "expression") and primary.expression() is not None:
                self.processExpressionForAnonymousClass(primary.expression())

        if hasattr(expr, "methodCall") and expr.methodCall() is not None:
            if hasattr(expr.methodCall(), "expressionList") and expr.methodCall().expressionList() is not None:
                for arg_expr in expr.methodCall().expressionList().expression():
                    self.processExpressionForAnonymousClass(arg_expr)

        # Process operands in binary expressions
        if hasattr(expr, "bop") and hasattr(expr, "expression"):
            expressions = expr.expression()
            if isinstance(expressions, list):
                for sub_expr in expressions:
                    self.processExpressionForAnonymousClass(sub_expr)

        if hasattr(expr, "objectCreationExpression") and expr.objectCreationExpression() is not None:
            self.visitObjectCreationExpression(expr.objectCreationExpression())

    def visitObjectCreationExpression(self, ctx: JavaParser.ObjectCreationExpressionContext):
        log.info("Processing object creation expression for potential anonymous inner class.")
        class_body = None
        creator_type = None

        if hasattr(ctx, "classBody") and ctx.classBody() is not None:
            class_body = ctx.classBody()
            if hasattr(ctx, "createdName") and ctx.createdName() is not None:
                creator_type = ctx.createdName().getText()
        elif hasattr(ctx, "classCreatorRest") and ctx.classCreatorRest() is not None:
            if hasattr(ctx.classCreatorRest(), "classBody") and ctx.classCreatorRest().classBody() is not None:
                class_body = ctx.classCreatorRest().classBody()
                if hasattr(ctx, "creator") and ctx.creator() is not None:
                    if hasattr(ctx.creator(), "createdName") and ctx.creator().createdName() is not None:
                        creator_type = ctx.creator().createdName().getText()

        # If we still don't have the creator type, try to infer it from context or idkkkkk, send me examples
        if not creator_type and ctx.parentCtx:
            parent = ctx.parentCtx
            while parent and not creator_type:
                if hasattr(parent, "variableDeclaratorId") and parent.variableDeclaratorId() is not None:
                    # Found a variable declaration
                    var_name = parent.variableDeclaratorId().getText()
                    log.debug(f"Found anonymous class assigned to variable: {var_name}")

                    # Try to find the type from the variable declaration
                    declaration_ctx = parent.parentCtx
                    while declaration_ctx:
                        if hasattr(declaration_ctx, "typeType") and declaration_ctx.typeType() is not None:
                            creator_type = declaration_ctx.typeType().getText()
                            break
                        declaration_ctx = declaration_ctx.parentCtx

                # Look for field declarations
                if hasattr(parent, "variableDeclarator") and parent.parentCtx and hasattr(parent.parentCtx,
                                                                                          "fieldDeclaration"):
                    field_ctx = parent.parentCtx.parentCtx
                    if hasattr(field_ctx, "typeType") and field_ctx.typeType() is not None:
                        creator_type = field_ctx.typeType().getText()

                parent = parent.parentCtx

            if not creator_type:
                tokens = ctx.parser.getTokenStream()
                start_idx = max(0, ctx.start.tokenIndex - 10)
                for token_index in range(start_idx, ctx.start.tokenIndex):
                    text = tokens.get(token_index).text
                    if text == "new" and token_index + 1 < ctx.start.tokenIndex:
                        creator_type = tokens.get(token_index + 1).text
                        break

        if class_body is not None:
            self.processAnonymousClass(class_body, creator_type)

        return self.visitChildren(ctx)

    def processAnonymousClass(self, class_body, creator_type):
        # Create a unique identifier for this anonymous class
        class_identifier = (class_body.start.start, class_body.stop.stop)

        # Skip if we've already processed this anonymous class
        if class_identifier in self.processed_anonymous_classes:
            log.debug("Skipping already processed anonymous class at position %s", class_identifier)
            return

        # Mark this anonymous class as processed
        self.processed_anonymous_classes.add(class_identifier)

        log.info("Anonymous inner class detected with creator type: %s", creator_type)
        self.anon_counter += 1
        if self.current_class_stack:
            enclosing = self.current_class_stack[-1]
        else:
            enclosing = "AnonymousEnclosure"
        type_suffix = f"_{creator_type.replace('.', '_')}" if creator_type else ""
        synthetic_name = f"{enclosing}$Anonymous{self.anon_counter}{type_suffix}"
        log.info("Generated synthetic name for anonymous inner class: %s", synthetic_name)
        self.current_class_stack.append(synthetic_name)

        _temp = {}
        _temp["Class Name"] = f"{self.current_package}.{synthetic_name}"
        _temp["Anonymous"] = True
        _temp["Implements/Extends"] = creator_type
        tokens = class_body.parser.getTokenStream()
        _decl = [tokens.get(token_index).text for token_index in
                 range(class_body.start.tokenIndex, class_body.stop.tokenIndex + 1)]
        _temp["Class Declaration"] = _decl

        method_list = []
        for member in class_body.classBodyDeclaration():
            if member.memberDeclaration():
                # Handle generic methods in anonymous classes as well.
                if (member.memberDeclaration().genericMethodDeclaration() is not None) or (
                        member.memberDeclaration().methodDeclaration() is not None):
                    method_decl = None
                    if member.memberDeclaration().genericMethodDeclaration() is not None:
                        method_decl = member.memberDeclaration().genericMethodDeclaration().methodDeclaration()
                    elif member.memberDeclaration().methodDeclaration() is not None:
                        method_decl = member.memberDeclaration().methodDeclaration()
                    if method_decl:
                        interface_name = None
                        if creator_type in self.interfaces:
                            method_name = method_decl.identifier().getText()
                            if method_name in self.interfaces[creator_type].get("methods", []):
                                interface_name = creator_type
                        method_index = self.extract_method_information(
                            method_decl,
                            synthetic_name,
                            is_anonymous=True,
                            interface_name=interface_name or creator_type
                        )
                        if method_index:
                            log.info("Extracted method '%s' from anonymous inner class '%s'", method_index.funcname,
                                     synthetic_name)
                            method_list.append(method_index)
                elif member.memberDeclaration().classDeclaration() is not None:
                    log.debug("Found nested class declaration in anonymous inner class: %s", synthetic_name)
                    self.visit(member.memberDeclaration().classDeclaration())
                elif member.memberDeclaration().fieldDeclaration() is not None:
                    # Process field declarations in anonymous class
                    self.visit(member.memberDeclaration().fieldDeclaration())
        _temp["Method Declarations"] = method_list
        self._class.append(_temp)
        self.current_class_stack.pop()

    def visitBlock(self, ctx: JavaParser.BlockContext):
        if hasattr(ctx, "blockStatement"):
            for stmt in ctx.blockStatement():
                if hasattr(stmt, "statement") and stmt.statement() is not None:
                    if hasattr(stmt.statement(), "expression") and stmt.statement().expression() is not None:
                        self.processExpressionForAnonymousClass(stmt.statement().expression())
        return self.visitChildren(ctx)

    def visitInterfaceMethodDeclaration(self, ctx: JavaParser.InterfaceMethodDeclarationContext):
        if self.current_class_stack:
            interface_name = self.current_class_stack[-1]
            method_name = ctx.identifier().getText() if hasattr(ctx, "identifier") else "unknown"
            log.debug(f"Processing interface method declaration: {interface_name}.{method_name}")

            # Add to tracked interfaces
            if interface_name not in self.interfaces:
                self.interfaces[interface_name] = {"methods": []}
            if "methods" not in self.interfaces[interface_name]:
                self.interfaces[interface_name]["methods"] = []
            self.interfaces[interface_name]["methods"].append(method_name)

        return self.visitChildren(ctx)


def extract_method_data(file: Path, target_container_path: Path, focus_dir_relative_path: Optional[str] = None) -> \
        List[Dict[str, List[FunctionIndex]]]:
    input_file = InputStream(safe_decode_string(file.read_bytes()))
    lexer = JavaLexer(input_file)
    # Remove default listeners and add our custom error listener
    lexer.removeErrorListeners()
    lexer.addErrorListener(ErrorListener())
    stream = CommonTokenStream(lexer)
    parser = JavaParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(ErrorListener())
    tree = parser.compilationUnit()
    visitor = Parser(
        target_container_path=target_container_path,
        focus_dir_relative_path=focus_dir_relative_path
    )
    visitor.visit(tree)
    data = visitor._class
    return data


@tracer.start_as_current_span("antlr4_indexer.process_file")
def process_file(file_path: Path, project: OSSFuzzProject) -> List[FunctionIndex]:
    span = get_current_span()
    span.set_attribute("crs.action.code.file", str(file_path))
    if file_path.suffix not in VALID_SOURCE_FILE_SUFFIXES_JVM:
        return []

    try:
        result = adjust_path_info(file_path, project)
        if result is None:
            log.info("Skipping file %s because it is in an ignored directory", file_path)
            return []
        target_container_path, focus_dir_relative_path = result
    except Exception as e:
        log.error("Error computing relative paths for file %s: %s", file_path, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise
        return []

    try:
        info = extract_method_data(file_path, target_container_path, focus_dir_relative_path)
        results = [
            method
            for method_list in info
            for method in method_list.get("Method Declarations", [])
        ]
    except Exception as e:
        log.error("Error processing file %s: %s", file_path, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise
        return []
    return results


def _get_changed_files(commit: git.Commit) -> List[str]:
    changed_files = []
    commit_diff = (
        commit.diff(commit.parents[0], create_patch=True)
        if commit.parents
        else commit.diff(git.NULL_TREE)
    )
    for diff in commit_diff:
        # Handle added, modified, and renamed files
        path = diff.a_path
        if path and any(s in path for s in VALID_SOURCE_FILE_SUFFIXES_JVM):
            changed_files.append(path)
    return changed_files


def _get_commit_ids(repo: git.Repo) -> List[str]:
    log.info("Starting to get commit IDs")
    commit_ids = [commit.hexsha for commit in tqdm(repo.iter_commits(), desc="Processing commits")]
    log.info(f"Finished getting commit IDs: {len(commit_ids)} commits found")
    commit_ids.reverse()
    return commit_ids


def find_git_repos(base_path: Path) -> List[Path]:
    git_repos = []
    for root, dirs, _ in os.walk(base_path):
        if ".git" in dirs:
            git_repos.append(Path(root))
            # Optional: skip subdirectories of the current git repo
            dirs[:] = [d for d in dirs if d != ".git"]
    return git_repos


@tracer.start_as_current_span("antlr4_indexer.process_commit")
def process_commit(commit_id: str, index: int, repo: git.Repo, src_dir: Path, target_root: Path, main_folder: Path):
    span = get_current_span()
    span.set_attribute("antlr4_indexer.commit_id", commit_id)
    span.set_attribute("antlr4_indexer.index", index)
    try:
        repo.git.checkout(commit_id, quiet=True)
        changed_files = _get_changed_files(repo.commit(commit_id))
        changed_files = [src_dir / f for f in changed_files]

        commit_id_dir = f"{index}_{commit_id}"
        class_folder = main_folder / commit_id_dir / "CLASS"
        method_folder = main_folder / commit_id_dir / "METHODS"
        macro_folder = main_folder / commit_id_dir / "MACRO"
        function_folder = main_folder / commit_id_dir / "FUNCTION"

        if index > 0:
            class_folder.mkdir(exist_ok=True, parents=True)
            method_folder.mkdir(exist_ok=True, parents=True)
            macro_folder.mkdir(exist_ok=True, parents=True)
            function_folder.mkdir(exist_ok=True, parents=True)
        log.info("Found #%s Java files to process on commit %s.", len(changed_files), commit_id)
        unchanged_functions = set()
        for file_results in tqdm([process_file(cf, src_dir) for cf in changed_files], total=len(changed_files)):
            for method in file_results:
                if method.hash in unchanged_functions:
                    continue
                unchanged_functions.add(method.hash)
                if index == 0:
                    continue
                func_name = method.funcname.replace("/", "-")
                filename = method.filename.replace("/", "-")
                (method_folder / f"{func_name}_{filename}_{method.hash}.json").write_text(method.model_dump_json())
    except Exception as e:
        log.error("Error processing commit %s: %s", commit_id, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise


def clone_repo_to_temp(repo_path: Path) -> Tuple[Repo, Path]:
    # Create a temporary directory to clone the repo into
    temp_root_dir = Path(tempfile.mkdtemp())
    try:
        log.info("Cloning from %s to %s", repo_path, temp_root_dir)
        repo = Repo.clone_from(repo_path, temp_root_dir, no_checkout=True)
        return repo, temp_root_dir
    except Exception as e:
        log.error("Error cloning repository %s to %s: %s", repo_path, temp_root_dir, e, exc_info=True)
        shutil.rmtree(temp_root_dir)
        raise e


def process_commit_in_temp_repo(commit_id: str, index: int, target_root: Path, main_folder: Path):
    repo, temp_repo_dir = clone_repo_to_temp(target_root)
    try:
        process_commit(commit_id, index, repo, temp_repo_dir, target_root, main_folder)
    finally:
        shutil.rmtree(temp_repo_dir)
    return commit_id


@tracer.start_as_current_span("antlr4_indexer.process_commit")
def process_commit(commit_id: str, index: int, repo: git.Repo, src_dir: Path, target_root: Path, main_folder: Path):
    span = get_current_span()
    span.set_attribute("antlr4_indexer.commit_id", commit_id)
    span.set_attribute("antlr4_indexer.index", index)
    try:
        repo.git.checkout(commit_id, quiet=True)
        changed_files = _get_changed_files(repo.commit(commit_id))
        changed_files = [src_dir / f for f in changed_files]

        commit_id_dir = f"{index}_{commit_id}"
        class_folder = main_folder / commit_id_dir / "CLASS"
        method_folder = main_folder / commit_id_dir / "METHODS"
        macro_folder = main_folder / commit_id_dir / "MACRO"
        function_folder = main_folder / commit_id_dir / "FUNCTION"

        if index > 0:
            class_folder.mkdir(exist_ok=True, parents=True)
            method_folder.mkdir(exist_ok=True, parents=True)
            macro_folder.mkdir(exist_ok=True, parents=True)
            function_folder.mkdir(exist_ok=True, parents=True)
        log.info("Found #%s Java files to process on commit %s.", len(changed_files), commit_id)
        unchanged_functions = set()
        # TODO: different ossfuzz projects for commit mode instead of src_dirs
        for file_results in tqdm([process_file(cf, ossfuzzproject) for cf in changed_files],
                                 total=len(changed_files)):
            for method in file_results:
                if method.hash in unchanged_functions:
                    continue
                unchanged_functions.add(method.hash)
                if index == 0:
                    continue
                func_name = method.funcname.replace("/", "-")
                filename = method.filename.replace("/", "-")
                (method_folder / f"{func_name}_{filename}_{method.hash}.json").write_text(method.model_dump_json())
    except Exception as e:
        log.error("Error processing commit %s: %s", commit_id, e, exc_info=True)
        if artiphishell_should_fail_on_error():
            raise


def process_all(target_project: OSSFuzzProject, output_dir: Path):
    src_dir = target_project.artifacts_dir
    files = [f for suffix in VALID_SOURCE_FILE_SUFFIXES_JVM for f in src_dir.rglob(f"**/*{suffix}")]
    output_dir.mkdir(exist_ok=True, parents=True)
    class_folder = output_dir / "CLASS"
    method_folder = output_dir / "METHOD"
    macro_folder = output_dir / "MACRO"
    function_folder = output_dir / "FUNCTION"
    class_folder.mkdir(exist_ok=True)
    method_folder.mkdir(exist_ok=True)
    macro_folder.mkdir(exist_ok=True)
    function_folder.mkdir(exist_ok=True)
    log.info("Found %s Java files to process.", len(files))
    # Pass the project root (project_path) and the project instance to process_file.
    new_process = functools.partial(process_file, project=target_project)
    for file_results in tqdm(map(new_process, files), total=len(files)):
        for method in file_results:
            try:
                (method_folder / (method.hash + ".json")).write_text(method.model_dump_json(indent=4))
                log.info("File Write Completed: %s", method.signature)
            except Exception as e:
                log.error("Error writing method %s to file: %s", method.signature, e, exc_info=True)
                raise e


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", type=str, choices=["commit", "full"], required=True, help="running mode")
    parser.add_argument("--canonical-build-artifact", type=Path, required=True, help="source code of the target")
    parser.add_argument("--project-source", type=Path, required=True, help="project source")
    parser.add_argument("--output-dir", type=Path, required=True, help="parsed output")
    args = parser.parse_args()
    # Create the project object using the provided artifact path.
    ossfuzzproject = OSSFuzzProject(oss_fuzz_project_path=args.canonical_build_artifact,
                                    project_source=args.project_source)

    with tracer.start_as_current_span("antlr4_indexer") as span:
        span.set_attribute("antlr4_indexer.mode", args.mode)

        if args.mode == "commit":
            # Commit mode not enabled in this version.
            ###########################################
            #            NO COMMIT MODE               #
            ###########################################
            pass
        elif args.mode == "full":
            process_all(ossfuzzproject, args.output_dir)
        span.set_status(status_ok())
