
import copy as _copy
import glob as _glob
import itertools as _itertools
import os as _os
import subprocess as _subprocess

import pyjdb.core.exceptions as _exceptions
import pyjdb.core.jdb_process as _jdb_process


def get_program_variables_trace(class_name, path=None, class_path=None, args=None, unique=False, stdin_text=None):

    with JdbProcessContextManager(
        class_name=class_name,
        path=path,
        class_path=class_path,
        args=args,
    ) as p:

        p.trace_max = 5

        variables = {}
        exception = False

        if stdin_text is not None and stdin_text != "":
            p.target_send_line(stdin_text)

        while True:

            # Try to make an additional step and retrieve local variables
            result = None
            try:
                p.step()
                result = p.locals()

            except _exceptions.JdbHostErrorException:
                exception = True
                break

            except _exceptions.JdbHostExitedException:
                break

            if result is None:
                continue

            # Store the values of each variable
            (args, local_vars) = result

            for (var, val) in _itertools.chain(args.items(), local_vars.items()):
                # Add the current value a variable is taking to a possibly empty history
                # of values
                variables[var] = variables.get(var, list())

                if len(variables[var]) == 0:
                    variables[var].append(val)
                else:
                    if val != variables[var][-1]:
                        variables[var].append(val)

        if unique:
            variables_unique_values = {
                var: list(set(vals)) for (var, vals) in variables.items()
            }
            return exception, variables_unique_values

        return exception, variables


def get_program_trace(class_name, path=None, class_path=None, args=None, stdin_text=None):

    with JdbProcessContextManager(
        class_name=class_name,
        path=path,
        class_path=class_path,
        args=args,
    ) as p:

        # Remove cap on trace history
        p.trace_max = None

        exception = False

        if stdin_text is not None and stdin_text != "":
            p.target_send_line(stdin_text)

        while True:

            # Try to make an additional step
            try:
                p.step(include_locals=True)

            except _exceptions.JdbHostErrorException:
                exception = True
                break

            except _exceptions.JdbHostExitedException:
                break

        trace_history = _copy.deepcopy(p.trace)

        return exception, trace_history


class JdbProcessContextManager(object):

    def __init__(self, class_name, path=None, class_path=None, args=None):
        self.path = path
        self.class_name = class_name
        self.class_path = class_path if class_path is not None else ["."]
        self.args = args

        self.jdb_process = None
        self.original_path = None

        # Fix class path
        if "." not in self.class_path:
            self.class_path.append(".")

    def compile(self):
        compiled_all = True
        compiled_class = True

        try:
            ps1 = _subprocess.run([
                "javac",
                "-classpath",
                ":".join(self.class_path),
                "-g"
            ] + _glob.glob("*.java"))

        except:
            compiled_all = False

        if not compiled_all:

            try:
                ps2 = _subprocess.run([
                    "javac",
                    "-classpath",
                    ":".join(self.class_path),
                    "-g",
                    "{}.java".format(self.class_name)])
            except:
                compiled_class = False

        can_continue = compiled_all or compiled_class

        return can_continue

    def __enter__(self):
        # Switch to target folder (otherwise staying in current directory)
        if self.path is not None:
            self.original_path = _os.getcwd()
            _os.chdir(self.path)

        # Compile files
        self.compile()

        # Spawn the JDB process (and make sure to capture stdin/stdout)
        self.jdb_process = _jdb_process.JDBProcess(
            self.class_name,
            class_path=self.class_path,
        )
        self.jdb_process.spawn(self.args, capture_target=True)

        return self.jdb_process

    def __exit__(self, *args):
        # Terminate the process
        if self.jdb_process is not None and self.jdb_process.active:
            self.jdb_process.close()

        # Restore original path (if we moved)
        if self.original_path is not None:
            _os.chdir(self.original_path)
            self.original_path = None