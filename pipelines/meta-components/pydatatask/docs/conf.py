# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "pydatatask"
author = "Audrey Dutcher"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.todo",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

language = "en"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_static_path = ["_static"]

# -- Options for todo extension ----------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/todo.html#configuration

todo_include_todos = True

# CUSTOM

import os
import sys

sys.path.insert(0, os.path.abspath(".."))
html_theme = "furo"
default_role = "any"
extensions.append("sphinx.ext.intersphinx")
intersphinx_mapping = {
    "asyncssh": ("https://asyncssh.readthedocs.io/en/latest/", None),
    "python": ("https://docs.python.org/3", None),
    "motor": ("https://motor.readthedocs.io/en/stable/", None),
    "networkx": ("https://networkx.org/documentation/stable/", None),
}
autodoc_default_options = {
    "member-order": "bysource",
}
autoclass_content = "both"
autodoc_inherit_docstrings = False

import datetime

import pydatatask

version = pydatatask.__version__
release = pydatatask.released_version
copyright = f"{datetime.datetime.now().year}, Audrey Dutcher"

import subprocess

subprocess.run(
    "sphinx-apidoc --force --module-first --no-toc -o . --separate ../pydatatask '../pydatatask/query/parse*'",
    shell=True,
    check=True,
)
